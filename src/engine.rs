//! Engine egress NL: satu ring drain, satu keputusan per frame.
//!
//! Model: kernel rule (dst-MAC VPN gateway) memblok frame dari stack yang
//! menuju VPN dan tetap menaruh frame itu di ring TX; engine memilih frame:
//!   - owner app masuk whitelist -> rewrite dst-MAC ke gateway LAN + inject
//!     (jalur inject kernel melewati FilterSend, jadi tidak terblok ulang);
//!   - non-app -> inject apa adanya (frame kembali ke VPN, passthrough asli).
//! Tanpa whitelist (apps kosong) semua frame dijalankan ulang apa adanya.
use crate::proclookup;
use crate::nlclient::{NlDevice, NlMode, NlPolicy, NlPolicyRule, MATCH_DSTMAC, NL_RING_TX, MODE_RX, MODE_TX};
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Statistik live yang dibaca UI kapan saja.
#[derive(Default)]
pub struct Stats {
    pub total: AtomicU64,
    pub redirected: AtomicU64,
    pub pass_through: AtomicU64,
}

/// State bersama antara UI dan thread engine.
pub struct Shared {
    /// Basename exe yang sedang di-bypass, huruf kecil, contoh "zen.exe".
    pub apps: Mutex<HashSet<String>>,
    pub stats: Stats,
    pub running: AtomicBool,
}

impl Shared {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            apps: Mutex::new(HashSet::new()),
            stats: Stats::default(),
            running: AtomicBool::new(false),
        })
    }

    pub fn set_app(&self, exe: &str, on: bool) {
        let mut set = self.apps.lock().unwrap();
        if on {
            set.insert(exe.to_lowercase());
        } else {
            set.remove(&exe.to_lowercase());
        }
    }
}

pub struct Cfg {
    /// MAC gateway LAN (arah bypass).
    pub to_gw_mac: [u8; 6],
    /// MAC gateway VPN (arah asli) — jadi rule blok kernel.
    pub from_gw_mac: [u8; 6],
    pub cancel: Arc<AtomicBool>,
    pub shared: Arc<Shared>,
}

/// IP src lokal (host-order LE) untuk skip frame ARP/IPv4? cukup ethertype.
fn eth_ipv4(d: &[u8]) -> bool {
    d.len() >= 34 && d[12] == 0x08 && d[13] == 0x00
}

/// Port src TCP/UDP (LE kontrak) untuk pemetaan PID port.
fn src_port(d: &[u8]) -> Option<(u8, u16)> {
    if !eth_ipv4(d) {
        return None;
    }
    let ihl = ((d[14] & 0x0F) * 4) as usize;
    if d.len() < 14 + ihl + 4 {
        return None;
    }
    let proto = d[23];
    let port = match proto {
        6 | 17 => u16::from_be_bytes([d[14 + ihl], d[14 + ihl + 1]]),
        _ => return None,
    };
    Some((proto, port))
}

/// Owner basename (huruf kecil) bila lokup sudah jua.
fn owner_basename(map: &proclookup::LookupMap, proto: u8, port: u16) -> Option<String> {
    let exe = map.get(&(port, proto == 6))?;
    Some(exe.rsplit('\\').next().unwrap_or(exe).to_lowercase())
}

/// Jalankan engine di thread pemanggil, blocking sampai cancel.
pub fn run(cfg: Cfg) {
    match NlDevice::open() {
        Ok(dev) => run_locked(dev, cfg),
        Err(e) => log_stderr(format!("driver: {e}")),
    }
}

fn log_stderr(s: String) {
    eprintln!("engine: {s}");
}

fn run_locked(dev: NlDevice, cfg: Cfg) {
    // mode TX+RX pada semua adapter agar ring lengkap
    if let Ok(ads) = dev.adapters() {
        for a in ads.iter() {
            let _ = dev.set_mode(NlMode { adapter_index: a.index, flags: MODE_RX | MODE_TX });
        }
    }
    // rule kernel: blok TX = dst-MAC VPN gateway
    let mut p = NlPolicy::default();
    p.count = 1;
    p.enabled = 1;
    p.rules[0] = NlPolicyRule {
        match_bits: MATCH_DSTMAC,
        dst_mac: cfg.from_gw_mac,
        ..NlPolicyRule::default()
    };
    if let Err(e) = dev.set_policy(&p) {
        log_stderr(format!("set_policy gagal: {e}"));
        return;
    }
    cfg.shared.running.store(true, Ordering::Relaxed);

    let mut lookup = proclookup::build();
    let mut seen: u64 = 0;
    let mut tick = Instant::now();

    while !cfg.cancel.load(Ordering::Relaxed) {
        if let Ok(items) = dev.read_ring(None, 256) {
            for e in &items {
                if e.len < 34 || (e.flags & NL_RING_TX) == 0 || e.len as usize > 1514 {
                    continue;
                }
                let data = &e.data[..e.len as usize];
                seen += 1;
                cfg.shared.stats.total.fetch_add(1, Ordering::Relaxed);

                if seen % 50 == 0 {
                    lookup = proclookup::build();
                }
                let mut redirected = false;
                if eth_ipv4(data) {
                    if let Some((proto, port)) = src_port(data) {
                        if let Some(owner) = owner_basename(&lookup, proto, port) {
                            let apps = cfg.shared.apps.lock().unwrap();
                            if apps.contains(&owner) {
                                redirected = true;
                            }
                        }
                    }
                }
                let frame: Vec<u8> = if redirected {
                    let mut f = data.to_vec();
                    f[0..6].copy_from_slice(&cfg.to_gw_mac);
                    f
                } else {
                    data.to_vec()
                };
                if dev.inject(&frame).is_ok() {
                    if redirected {
                        cfg.shared.stats.redirected.fetch_add(1, Ordering::Relaxed);
                    } else {
                        cfg.shared.stats.pass_through.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
        }
        if tick.elapsed() >= Duration::from_secs(1) {
            tick = Instant::now();
        }
    }

    let _ = dev.set_policy(&NlPolicy::default());
    if let Ok(ads) = dev.adapters() {
        for a in ads.iter() {
            let _ = dev.set_mode(NlMode { adapter_index: a.index, flags: 0 });
        }
    }
    cfg.shared.running.store(false, Ordering::Relaxed);
}
