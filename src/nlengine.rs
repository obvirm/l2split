//! Engine egress atas driver NDISLWF: baca ring, terapkan kebijakan bypass,
//! inject ulang frame yang diblokir kernel (re-route), kumpulkan statistik.
//!
//! Pola re-route: rule kernel memblok frame dari stack yang match target
//! (frame itu tetap tercapture di ring TX dulu), engine memilih frame target
//! dan mengirim ulang lewat INJECT — jalur inject kernel memanggil
//! NdisFSendNetBufferLists langsung, sehingga tidak kena rule blok dan tidak
//! tercatat ulang di ring.
use crate::helpers::CmdArgs;
use crate::nlclient::{
    NlDevice, NlMode, NlPolicy, NlPolicyRule, NlRingEntry,
    MATCH_DST, NL_FRAME_MAX, NL_RING_RX, NL_RING_TX,
};
use std::time::{Duration, Instant};

const NL_MODE_RX: u32 = 0x1;
const NL_MODE_TX: u32 = 0x2;

/// Target bypass (host-order kecil-endian sesuai kontrak rule kernel).
pub struct Egress {
    pub dst_ip_le: u32,
    pub mask_le: u32,
}

/// Mask little-endian dari prefix (0 = /0).
pub fn prefix_mask_le(p: u32) -> u32 {
    if p == 0 { 0 } else { (!0u32) << (32 - p) }
}

/// TRUE bila frame TX adalah IPv4 menuju subnet target.
pub fn frame_is_target(e: &NlRingEntry, eg: &Egress) -> bool {
    if e.len < 42 || (e.flags & NL_RING_TX) == 0 || e.len as usize > NL_FRAME_MAX {
        return false;
    }
    let d = &e.data;
    if d[12] != 0x08 || d[13] != 0x00 {
        return false; // bukan IPv4
    }
    let dip = u32::from_le_bytes([d[30], d[31], d[32], d[33]]);
    (dip & eg.mask_le) == (eg.dst_ip_le & eg.mask_le)
}

/// TRUE bila frame RX adalah balasan dari target (src IP = target).
pub fn frame_from_target(e: &NlRingEntry, eg: &Egress) -> bool {
    if e.len < 42 || (e.flags & NL_RING_RX) == 0 {
        return false;
    }
    let d = &e.data;
    if d[12] != 0x08 || d[13] != 0x00 {
        return false;
    }
    let sip = u32::from_le_bytes([d[26], d[27], d[28], d[29]]);
    (sip & eg.mask_le) == (eg.dst_ip_le & eg.mask_le)
}

/// Jalankan siklus run: set rule blok kernel, drain ring TX, re-inject
/// frame target, laporkan tick per detik, lalu bersih-bersih.
///   --idx N      adapter (default 0)
///   --dst IP     subnet target yang di-bypass (default 8.8.8.8)
///   --dstlen N   panjang prefix (default 32)
///   --secs N     durasi detik (default 15)
pub fn cmd_run(args: &CmdArgs) {
    match NlDevice::open() {
        Ok(dev) => {
            let idx = args.num("--idx", 0) as u32;
            let dst = args.get("--dst").unwrap_or_else(|| "8.8.8.8".into());
            let dstlen = args.num("--dstlen", 32) as u32;
            let secs = args.num("--secs", 15) as u64;

            let oct: Vec<u8> = dst.split('.').map(|s| s.parse::<u8>().unwrap_or(0)).collect();
            if oct.len() != 4 {
                println!("--dst tidak valid: {dst}");
                return;
            }
            let dst_ip = u32::from_le_bytes([oct[0], oct[1], oct[2], oct[3]]);
            let mask = prefix_mask_le(dstlen);
            if dstlen > 32 {
                println!("--dstlen tidak valid: {dstlen}");
                return;
            }

            // 1) mode TX+RX pada adapter idx (RX dipakai untuk bukti reply)
            if let Err(e) = dev.set_mode(NlMode { adapter_index: idx, flags: NL_MODE_RX | NL_MODE_TX }) {
                println!("set_mode gagal: {e}");
                return;
            }
            // 2) rule kernel: blok TX ke subnet target (frame dari stack)
            let mut p = NlPolicy::default();
            p.count = 1;
            p.enabled = 1;
            let r = NlPolicyRule { match_bits: MATCH_DST, ip: dst_ip, mask, ..NlPolicyRule::default() };
            p.rules[0] = r;
            if let Err(e) = dev.set_policy(&p) {
                println!("set_policy gagal: {e}");
                return;
            }

            let _ = dev.clear();
            println!("run AKTIF: idx={idx} dst={dst}/{dstlen} durasi={secs}s");

            let eg = Egress { dst_ip_le: dst_ip, mask_le: mask };
            let mut seen = 0u64;
            let mut reinj = 0u64;
            let mut rx_hit = 0u64;
            let mut tx_nontarget = 0u64;
            let t0 = Instant::now();
            let mut tick = Instant::now();

            while t0.elapsed() < Duration::from_secs(secs) {
                if let Ok(items) = dev.read_ring(None, 256) {
                    for e in &items {
                        seen += 1;
                        if frame_is_target(e, &eg) {
                            if dev.inject(&e.data[..e.len as usize]).is_ok() {
                                reinj += 1;
                            }
                        } else if frame_from_target(e, &eg) {
                            rx_hit += 1;
                        } else if (e.flags & NL_RING_TX) != 0 {
                            tx_nontarget += 1;
                        }
                    }
                }
                if tick.elapsed() >= Duration::from_secs(1) {
                    tick = Instant::now();
                    if let Ok(st) = dev.stats(None) {
                        println!("tick: ring={} reinject={} rx-hit={} kernel-injected={} dropped={}",
                                 seen, reinj, rx_hit, st.injected, st.dropped);
                    }
                }
            }

            // bersih-bersih: policy off, mode off
            let _ = dev.set_policy(&NlPolicy::default());
            let _ = dev.set_mode(NlMode { adapter_index: idx, flags: 0 });
            println!("run SELESAI: ring={} reinject={} rx-hit={} tx-nontarget={}",
                     seen, reinj, rx_hit, tx_nontarget);
            if let Ok(st) = dev.stats(None) {
                println!("cap: tx={} rx={} | kernel: injected={} dropped={}",
                         st.tx_captured, st.rx_captured, st.injected, st.dropped);
            }
        }
        Err(e) => println!("driver: TIDAK ADA ({e})"),
    }
}
