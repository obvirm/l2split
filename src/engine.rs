//! Engine l2split: satu reader per adapter, satu keputusan per frame.
//!
//! Model: filter kernel (STATIC_FILTER dst-MAC gateway VPN, action REDIRECT)
//! menahan frame TX yang menuju VPN dan mengumpankannya ke user-mode.
//! Engine memilih frame:
//!   - owner app masuk whitelist -> rewrite dst-MAC ke gateway LAN + inject ke
//!     adapter LAN (send_packets_to_adapter di jalur driver, bukan jalur stack);
//!   - non-app -> inject apa adanya ke adapter asal (passthrough).
//! Frame non-IPv4 (ARP dll) di-ppassthrough apa adanya.
use crate::helpers::{make_event, reset_event, wait_event};
use crate::ndclient::{NdisDevice, SniAdapter, BATCH};
use crate::proclookup;
use ndisapi::IntermediateBuffer;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
    /// MAC gateway VPN (arah asli) — jadi filter capture kernel.
    pub from_gw_mac: [u8; 6],
    /// HANDLE adapter LAN untuk inject arah bypass.
    pub target_handle: crate::ndclient::AdapterHandle,
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
    match NdisDevice::open() {
        Ok(dev) => run_locked(std::sync::Arc::new(dev), cfg),
        Err(e) => log_stderr(format!("driver: {e}")),
    }
}

fn log_stderr(s: String) {
    eprintln!("engine: {s}");
}

fn run_locked(dev: std::sync::Arc<NdisDevice>, cfg: Cfg) {
    let ads = match dev.adapters() {
        Ok(v) => v,
        Err(e) => {
            log_stderr(format!("enumerate: {e}"));
            return;
        }
    };
    if ads.is_empty() {
        log_stderr("tidak ada adapter TCP/IP-bound".into());
        return;
    }
    if let Err(e) = dev.capture_tx(cfg.from_gw_mac) {
        log_stderr(e);
        return;
    }

    cfg.shared.running.store(true, Ordering::Relaxed);
    let mut joins = Vec::new();
    for a in ads {
        let dev = dev.clone();
        let cancel = cfg.cancel.clone();
        let shared = cfg.shared.clone();
        let to_gw_mac = cfg.to_gw_mac;
        let target_handle = cfg.target_handle;
        joins.push(std::thread::spawn(move || {
            reader_loop(&dev, a, cancel, shared, to_gw_mac, target_handle);
        }));
    }
    for j in joins {
        let _ = j.join();
    }
    cfg.shared.running.store(false, Ordering::Relaxed);
    dev.clear();
}

fn reader_loop(
    dev: &NdisDevice,
    a: SniAdapter,
    cancel: Arc<AtomicBool>,
    shared: Arc<Shared>,
    to_gw_mac: [u8; 6],
    target_handle: crate::ndclient::AdapterHandle,
) {
    let ev = make_event();
    if dev.set_event(a.handle, ev).is_err() {
        return;
    }
    let _ = dev.tunnel_tx(a.handle);
    let mut bufs: Vec<IntermediateBuffer> = vec![IntermediateBuffer::default(); BATCH];
    let mut lookup = proclookup::build();
    let mut last_probe = std::time::Instant::now();
    let mut last_rate_check = std::time::Instant::now();
    let mut frames_since_check: u64 = 0;

    while !cancel.load(Ordering::Relaxed) {
        wait_event(ev, 200);
        loop {
            let n = dev.read_batch(a.handle, &mut bufs);
            if n == 0 {
                break;
            }
            shared.stats.total.fetch_add(n as u64, Ordering::Relaxed);
            frames_since_check += n as u64;
            let mut redirect: Vec<bool> = vec![false; n];
            for i in 0..n {
                let d = bufs[i].get_data();
                if let Some((proto, port)) = src_port(d) {
                    let mut owner = owner_basename(&lookup, proto, port);
                    if owner.is_none() && last_probe.elapsed() > std::time::Duration::from_millis(110) {
                        lookup = proclookup::build();
                        last_probe = std::time::Instant::now();
                        owner = owner_basename(&lookup, proto, port);
                    }
                    if let Some(owner) = owner {
                        let apps = shared.apps.lock().unwrap();
                        if apps.contains(&owner) {
                            redirect[i] = true;
                        }
                    }
                }
                if redirect[i] {
                    let f = bufs[i].get_data_mut();
                    f[0..6].copy_from_slice(&to_gw_mac);
                }
            }
            let mut to_lan =
                ndisapi::EthMRequest::<'_, BATCH>::new(target_handle.0);
            let mut to_src = ndisapi::EthMRequest::<'_, BATCH>::new(a.handle);
            let mut n_lan = 0usize;
            let mut n_src = 0usize;
            for i in 0..n {
                if redirect[i] {
                    if to_lan.push(&bufs[i]).is_ok() {
                        n_lan += 1;
                    }
                } else if to_src.push(&bufs[i]).is_ok() {
                    n_src += 1;
                }
            }
            if n_lan > 0 {
                let _ = dev.send_batch(&to_lan);
            }
            if n_src > 0 {
                let _ = dev.send_batch(&to_src);
            }
            for i in 0..n {
                if redirect[i] {
                    shared.stats.redirected.fetch_add(1, Ordering::Relaxed);
                } else {
                    shared.stats.pass_through.fetch_add(1, Ordering::Relaxed);
                }
            }
            if n < BATCH {
                break;
            }
        }
        if last_rate_check.elapsed() >= std::time::Duration::from_secs(1) {
            if frames_since_check > 4000 {
                log_stderr(format!(
                    "guard rate: {} frame/dtk > 4000, hentikan engine",
                    frames_since_check
                ));
                cancel.store(true, Ordering::Relaxed);
                reset_event(ev);
                break;
            }
            frames_since_check = 0;
            last_rate_check = std::time::Instant::now();
        }
        reset_event(ev);
    }
    dev.restore_mode(a.handle);
    let _ = &mut bufs;
}
