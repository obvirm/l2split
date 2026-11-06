//! nlclient - klien user-mode untuk device kontrol ndislwf (NDISLWF.sys).
//!
//! Kontrak ABI = src/nlbridge/nlbridge.h v1 (magic 'NLP1').
//! Rumus CTL_CODE sama persis dengan makro NL_IOCTL di header C supaya
//! konstanta streams identik antara kernel (WDK) dan sini (Rust).

use crate::helpers::CmdArgs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, CreateFileW,
};
use windows::Win32::System::IO::{DeviceIoControl};
use windows::core::PCWSTR;

// --- konstanta ABI (sumber: nlbridge.h) -------------------------------------
const NL_WDM_TYPE: u32 = 0x8900;

#[inline]
const fn nl_ioctl(fn_code: u32, method: u32, access: u32) -> u32 {
    (NL_WDM_TYPE << 16) | ((access & 3) << 14) | ((fn_code & 0xFFF) << 2) | (method & 3)
}

pub const NL_METHOD_BUFFERED: u32 = 0;
pub const NL_METHOD_IN_DIRECT: u32 = 1;
pub const NL_METHOD_OUT_DIRECT: u32 = 2;

pub const IOC_VERSION: u32 = nl_ioctl(0x800, NL_METHOD_BUFFERED, 0);
pub const IOC_ENUM_ADPT: u32 = nl_ioctl(0x801, NL_METHOD_BUFFERED, 0);
pub const IOC_SET_MODE: u32 = nl_ioctl(0x802, NL_METHOD_BUFFERED, 0);
pub const IOC_STATS: u32 = nl_ioctl(0x803, NL_METHOD_BUFFERED, 0);
pub const IOC_READ_RING: u32 = nl_ioctl(0x804, NL_METHOD_BUFFERED, 0);
pub const IOC_INJECT: u32 = nl_ioctl(0x805, NL_METHOD_BUFFERED, 0);
pub const IOC_CLEAR: u32 = nl_ioctl(0x806, NL_METHOD_BUFFERED, 0);
pub const IOC_POLICY: u32 = nl_ioctl(0x807, NL_METHOD_BUFFERED, 0);

pub const NL_ABI_MAGIC: u32 = 0x3150_4C4E; // 'NLP1'
pub const NL_ABI_VER: u32 = (1 << 16) | 0; // major 1, minor 0

pub const NL_FRAME_MAX: usize = 1514;
pub const NL_RING_TX: u32 = 0x1;
pub const NL_RING_RX: u32 = 0x2;

// --- repr(C) contract --------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct NlVersion {
    pub magic: u32,
    pub ver: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlAdapter {
    pub index: u32,
    pub medium: u32,
    pub flags: u32,
    pub reserved: u32,
    pub mac: [u8; 6],
    pub pad2: [u8; 2],
    pub ifname: [u16; 260],
}
impl Default for NlAdapter {
    fn default() -> Self {
        Self { index: 0, medium: 0, flags: 0, reserved: 0, mac: [0; 6], pad2: [0; 2], ifname: [0; 260] }
    }
}
unsafe impl Send for NlAdapter {}
unsafe impl Sync for NlAdapter {}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct NlMode {
    pub adapter_index: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct NlStats {
    pub rx_total: u64,
    pub tx_total: u64,
    pub rx_captured: u64,
    pub tx_captured: u64,
    pub injected: u64,
    pub dropped: u64,
    pub active_units: u32,
    pub abi_ver: u32,
}

/// Empty ring entry: mirrors NL_RING_ENTRY (sizeof = 1524 dgn 4-byte pad).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlRingEntry {
    pub len: u32,
    pub flags: u32,
    pub data: [u8; NL_FRAME_MAX],
}
unsafe impl Send for NlRingEntry {}
unsafe impl Sync for NlRingEntry {}

/// Input inject: mirrors NL_INJECT (sizeof = 1524).
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlInject {
    pub len: u32,
    pub reserved: u32,
    pub data: [u8; NL_FRAME_MAX],
}

/// Satu aturan blok TX (NL_POLICY_RULE). sizeof = 28 B.
#[repr(C)]
#[derive(Clone, Copy, Default, Debug)]
pub struct NlPolicyRule {
    pub proto: u32,       /* 0=any, 6=tcp, 17=udp */
    pub match_bits: u32,  /* 1=src, 2=dst, 4=dstmac */
    pub ip: u32,          /* little-endian urutan oktet wire balik kernel */
    pub mask: u32,
    pub port_min: u16,
    pub port_max: u16,
    pub dst_mac: [u8; 6],
}

/// Set aturan global (NL_POLICY). sizeof = 8 + 16*28 = 456.
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct NlPolicy {
    pub count: u32,
    pub enabled: u32,
    pub rules: [NlPolicyRule; 16],
}
impl Default for NlPolicy {
    fn default() -> Self {
        Self { count: 0, enabled: 0, rules: [NlPolicyRule::default(); 16] }
    }
}

pub const MATCH_SRC: u32 = 0x1;
pub const MATCH_DST: u32 = 0x2;
pub const MATCH_DSTMAC: u32 = 0x4;

pub const FLAG_RUNNING: u32 = 1;
pub const MODE_RX: u32 = 1;
pub const MODE_TX: u32 = 2;

// --- device wrapper -----------------------------------------------------------
pub struct NlDevice {
    h: HANDLE,
}

impl NlDevice {
    /// Buka \\.\ndislwf; kalau driver belum terpasang → Err deskriptif.
    pub fn open() -> Result<Self, String> {
        let name: Vec<u16> = "\\\\.\\NDISLWF\0".encode_utf16().collect();
        unsafe {
            let h = CreateFileW(
                PCWSTR(name.as_ptr()),
                (GENERIC_READ | GENERIC_WRITE).0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
            .map_err(|e| format!("driver belum terpasang / akses ditolak: {e}"))?;
            Ok(Self { h })
        }
    }

    fn ioctl(&self, code: u32, in_buf: Option<(*const u8, u32)>, out: Option<(*mut u8, u32)>) -> Result<u32, String> {
        let mut ret = 0u32;
        let (iptr, isz) = in_buf.unwrap_or((std::ptr::null(), 0));
        let (optr, osz) = out.unwrap_or((std::ptr::null_mut(), 0));
        let ok = unsafe {
            DeviceIoControl(
                self.h,
                code,
                Some(iptr.cast()),
                isz,
                Some(optr.cast()),
                osz,
                Some(&mut ret),
                None,
            )
        };
        match ok {
            Ok(()) if ret <= osz => Ok(ret),
            Ok(()) => Err("output buffer kecil".into()),
            Err(e) if e.code().0 == 997 => {
                // ERROR_IO_INCOMPLETE: expected pada ioctl gagal async? tak di jalur ini
                Err(format!("IO_INCOMPLETE {e}"))
            }
            Err(e) => {
                let le = unsafe { GetLastError().0 };
                Err(format!("ioctl {code:#x} gagal: {e} (last={le})"))
            }
        }
    }

    pub fn version(&self) -> Result<NlVersion, String> {
        let mut v = NlVersion::default();
        let n = self.ioctl(IOC_VERSION, None, Some((&mut v as *mut _ as *mut u8, std::mem::size_of::<NlVersion>() as u32)))?;
        if n != 8 {
            return Err("payload version salah ukuran".into());
        }
        Ok(v)
    }

    pub fn adapters(&self) -> Result<Vec<NlAdapter>, String> {
        let mut buf = vec![NlAdapter::default(); 64];
        let sz = std::mem::size_of::<NlAdapter>() as u32;
        let osz = sz * 64;
        let n = self.ioctl(
            IOC_ENUM_ADPT,
            None,
            Some((buf.as_mut_ptr() as *mut u8, osz)),
        )?;
        let k = (n / sz) as usize;
        buf.truncate(k);
        Ok(buf)
    }

    pub fn set_mode(&self, m: NlMode) -> Result<(), String> {
        self.ioctl(IOC_SET_MODE, Some((&m as *const _ as *const u8, std::mem::size_of::<NlMode>() as u32)), None)?;
        Ok(())
    }

    pub fn stats(&self, adapter: Option<u32>) -> Result<NlStats, String> {
        let mut s = NlStats::default();
        let mut inb = [0u8; 4];
        let inb2: Option<(*const u8, u32)> = match adapter {
            Some(i) => {
                inb.copy_from_slice(&i.to_le_bytes());
                Some((inb.as_ptr(), 4))
            }
            None => None,
        };
        self.ioctl(IOC_STATS, inb2, Some((&mut s as *mut _ as *mut u8, std::mem::size_of::<NlStats>() as u32)))?;
        Ok(s)
    }

    pub fn clear(&self) -> Result<(), String> {
        self.ioctl(IOC_CLEAR, None, None)?;
        Ok(())
    }

    /// Set policy blok TX global (NL_POLICY).
    pub fn set_policy(&self, p: &NlPolicy) -> Result<(), String> {
        self.ioctl(
            IOC_POLICY,
            Some((p as *const NlPolicy as *const u8, std::mem::size_of::<NlPolicy>() as u32)),
            None,
        )?;
        Ok(())
    }

    /// Baca maksimal `max` entri dari ring kernel per-adapter (READ_RING).
    /// Kontrak: IN opsional [u32 adapter]; OUT = [u32 count][entry...].
    /// adapter None = instance pertama.
    pub fn read_ring(&self, adapter: Option<u32>, max: usize) -> Result<Vec<NlRingEntry>, String> {
        let esz = std::mem::size_of::<NlRingEntry>();
        if max == 0 {
            return Ok(Vec::new());
        }
        let mut buf = vec![0u8; 4 + max * esz];
        let mut inb = [0u8; 4];
        let inb2: Option<(*const u8, u32)> = match adapter {
            Some(i) => {
                inb.copy_from_slice(&i.to_le_bytes());
                Some((inb.as_ptr(), 4))
            }
            None => None,
        };
        self.ioctl(IOC_READ_RING, inb2, Some((buf.as_mut_ptr() as *mut u8, buf.len() as u32)))?;
        let count = u32::from_le_bytes(buf[0..4].try_into().unwrap()) as usize;
        if count > max {
            return Err(format!("count ring tidak wajar: {count} > {max}"));
        }
        let mut out = Vec::with_capacity(count);
        for i in 0..count {
            let base = 4 + i * esz;
            // entry ditulis berurutan dgn layout repr(C); baca unaligned-aman.
            let len = u32::from_le_bytes(buf[base..base + 4].try_into().unwrap());
            let flags = u32::from_le_bytes(buf[base + 4..base + 8].try_into().unwrap());
            let mut data = [0u8; NL_FRAME_MAX];
            data.copy_from_slice(&buf[base + 8..base + 8 + NL_FRAME_MAX]);
            out.push(NlRingEntry { len, flags, data });
        }
        Ok(out)
    }

    /// Kosongkan ring: loop READ_RING sampai count=0. Kembalikan total frame.
    pub fn drain_ring(&self) -> Result<(usize, usize, u64), String> {
        let mut n_tx = 0usize;
        let mut n_rx = 0usize;
        let mut bytes = 0u64;
        let mut rounds = 0usize;
        loop {
            let items = self.read_ring(None, 256)?;
            if items.is_empty() {
                break;
            }
            for e in items.iter() {
                if (e.flags & NL_RING_TX) != 0 {
                    n_tx += 1;
                } else {
                    n_rx += 1;
                }
                bytes += e.len as u64;
            }
            rounds += 1;
            if rounds > 4096 {
                break; // guard
            }
        }
        Ok((n_tx, n_rx, bytes))
    }

    /// Kirim satu frame mentah ke adapter (INJECT).
    pub fn inject(&self, frame: &[u8]) -> Result<(), String> {
        if frame.is_empty() || frame.len() > NL_FRAME_MAX {
            return Err(format!("ukuran frame tidak valid: {} (1..={NL_FRAME_MAX})", frame.len()));
        }
        let mut inp = NlInject { len: frame.len() as u32, reserved: 0, data: [0u8; NL_FRAME_MAX] };
        inp.data[..frame.len()].copy_from_slice(frame);
        self.ioctl(
            IOC_INJECT,
            Some((&inp as *const NlInject as *const u8, std::mem::size_of::<NlInject>() as u32)),
            None,
        )?;
        Ok(())
    }
}

impl Drop for NlDevice {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.h);
        }
    }
}

unsafe impl Send for NlDevice {}
unsafe impl Sync for NlDevice {}

// --- CLI diagnostic ------------------------------------------------------------
pub fn cmd_driver_check() {
    match NlDevice::open() {
        Ok(dev) => {
            println!("driver: TERBUKA");
            match dev.version() {
                Ok(v) if v.magic == NL_ABI_MAGIC =>
                    println!("  ABI v{}.{} (magic ok)", v.ver >> 16, v.ver & 0xFFFF),
                Ok(v) => println!("  ABI GAK COCOK: magic={:#x}", v.magic),
                Err(e) => println!("  version ioctl gagal: {e}"),
            }
            match dev.adapters() {
                Ok(a) => {
                    println!("  adapter: {}", a.len());
                    for x in a.iter().take(12) {
                        let nm: String = x.ifname.iter().take_while(|&&c| c != 0).map(|c| char::from_u32(*c as u32).unwrap_or('?')).collect();
                        println!("   [{}] mac={} flags={:#x} {}", x.index, crate::helpers::fmt_mac(&x.mac), x.flags, nm);
                    }
                }
                Err(e) => println!("  enum gagal: {e}"),
            }
        }
        Err(e) => {
            println!("driver: TIDAK ADA ({e})");
            println!("  → folder driver: driver.cmd → 3 (testsigning ON) → reboot → 1 (install)");
        }
    }
    let _ = Arc::new(AtomicBool::new(false)).load(Ordering::Relaxed);
}

/// ring: drain isi ring kernel; print ringkas; --mode N untuk set mode dulu.
pub fn cmd_ring(args: &CmdArgs) {
    let dev = match NlDevice::open() {
        Ok(d) => d,
        Err(e) => { println!("driver: TIDAK ADA ({e})"); return; }
    };

    if let Some(m) = args.get("--mode") {
        let flags = parse_mode(&m);
        let dm = NlMode { adapter_index: args.num("--idx", 0) as u32, flags };
        if let Err(e) = dev.set_mode(dm) { println!("SET_MODE gagal: {e}"); return; }
        println!("mode adapter #{} = {:#x}", dm.adapter_index, flags);
    }

    let start = std::time::Instant::now();
    let mut shown = 0usize;
    let max_show = args.num("--n", 12) as usize;
    let mut total = 0usize;
    let mut txb = 0usize;
    let mut rxb = 0usize;
    let _ = start;
    let mut no = 0usize;
    loop {
        let items = match dev.read_ring(None, 256) { Ok(v) => v, Err(e) => { println!("READ_RING gagal: {e}"); return; } };
        if items.is_empty() { break; }
        for e in items.iter() {
            no += 1;
            if (e.flags & NL_RING_TX) != 0 { txb += 1 } else { rxb += 1 }
            if shown < max_show {
                println!("  [{}] {}", no, ring_line(e));
                if args.flag("--hex") { println!("       {}", hex_dump(&e.data[..(e.len as usize).min(NL_FRAME_MAX)])); }
                shown += 1;
            }
        }
        total += items.len();
        if total > 65536 { println!("  (guard: terlalu banyak entri, berhenti)"); break; }
    }
    println!("ring: total={} tx={} rx={}", total, txb, rxb);
}

/// ring --daemon N: drain ring tiap 500 ms selama N detik; laporan per siklus.
pub fn cmd_ring_daemon(args: &CmdArgs) {
    let secs = args.num("--secs", 6) as u64;
    let dev = match NlDevice::open() {
        Ok(d) => d,
        Err(e) => { println!("driver: TIDAK ADA ({e})"); return; }
    };
    if let Some(m) = args.get("--mode") {
        let dm = NlMode { adapter_index: args.num("--idx", 0) as u32, flags: parse_mode(&m) };
        if let Err(e) = dev.set_mode(dm) { println!("SET_MODE gagal: {e}"); return; }
    }
    let start = std::time::Instant::now();
    let mut cycles = 0u32;
    let mut t_all = 0usize;
    let mut r_all = 0usize;
    while start.elapsed().as_secs() < secs {
        let (n_tx, n_rx, _b) = match dev.drain_ring() {
            Ok(v) => v,
            Err(e) => { println!("drain gagal: {e}"); return; }
        };
        t_all += n_tx;
        r_all += n_rx;
        cycles += 1;
        let st = dev.stats(None).map(|s| (s.dropped, s.rx_captured, s.tx_captured)).unwrap_or((0, 0, 0));
        println!("siklus{cycles} tx={n_tx} rx={n_rx} (total tx={t_all} rx={r_all}) dropped={} cap(rx={},tx={})", st.0, st.1, st.2);
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// mode: set mode capture (--rx/--tx/--off, --idx).
pub fn cmd_mode(args: &CmdArgs) {
    match NlDevice::open() {
        Ok(dev) => {
            let flags = if args.flag("--off") {
                0
            } else {
                let mut f = 0;
                if args.flag("--rx") { f |= MODE_RX }
                if args.flag("--tx") { f |= MODE_TX }
                if f == 0 { 0 } else { f }
            };
            let m = NlMode { adapter_index: args.num("--idx", 0) as u32, flags };
            match dev.set_mode(m) {
                Ok(()) => println!("mode adapter #{} = {:#x}", m.adapter_index, m.flags),
                Err(e) => println!("SET_MODE gagal: {e}"),
            }
        }
        Err(e) => println!("driver: TIDAK ADA ({e})"),
    }
}

/// stats: cetak statistik penuh.
pub fn cmd_stats() {
    match NlDevice::open() {
        Ok(dev) => match dev.stats(None) {
            Ok(s) => {
                println!("passthrough: rx={} tx={}", s.rx_total, s.tx_total);
                println!("capture    : rx={} tx={}", s.rx_captured, s.tx_captured);
                println!("injected   : {}, dropped   : {}", s.injected, s.dropped);
                println!("units      : {}, abi       : v{}.{}", s.active_units, s.abi_ver >> 16, s.abi_ver & 0xFFFF);
            }
            Err(e) => println!("STATS gagal: {e}"),
        },
        Err(e) => println!("driver: TIDAK ADA ({e})"),
    }
}

/// inject: kirim frame dari file (byte mentah).
pub fn cmd_inject(args: &CmdArgs) {
    let pos = args.positional();
    if pos.is_empty() {
        println!("inject: butuh path file frame (.bin)");
        return;
    }
    let data = match std::fs::read(&pos[0]) {
        Ok(d) => d,
        Err(e) => { println!("baca file gagal: {e}"); return; }
    };
    match NlDevice::open() {
        Ok(dev) => {
            let s0 = dev.stats(None).map(|s| s.injected).unwrap_or(0);
            match dev.inject(&data) {
                Ok(()) => {
                    let s1 = dev.stats(None).map(|s| s.injected).unwrap_or(0);
                    println!("inject OK: {} byte (kernel injected {} -> {})", data.len(), s0, s1);
                }
                Err(e) => println!("INJECT gagal: {e}"),
            }
        }
        Err(e) => println!("driver: TIDAK ADA ({e})"),
    }
}

fn parse_mode(text: &str) -> u32 {
    let mut f = 0u32;
    for t in text.split(',') {
        match t.trim().to_ascii_lowercase().as_str() {
            "rx" => f |= MODE_RX,
            "tx" => f |= MODE_TX,
            _ => {}
        }
    }
    if f == 0 {
        // angka desimal/heks mentah
        u32::from_str_radix(text.trim().trim_start_matches("0x"), 16).unwrap_or(0)
    } else {
        f
    }
}

fn ring_line(e: &NlRingEntry) -> String {
    if (e.len as usize) < 14 {
        return format!("len={} (terpangkas)", e.len);
    }
    let dir = if (e.flags & NL_RING_TX) != 0 { "TX" } else { "RX" };
    let et = u16::from_be_bytes([e.data[12], e.data[13]]);
    let mut dst6 = [0u8; 6];
    dst6.copy_from_slice(&e.data[0..6]);
    let mut src6 = [0u8; 6];
    src6.copy_from_slice(&e.data[6..12]);
    format!(
        "{} len={:4} {} -> {} et=0x{:04X}",
        dir,
        e.len,
        crate::helpers::fmt_mac(&src6),
        crate::helpers::fmt_mac(&dst6),
        et
    )
}

fn hex_dump(d: &[u8]) -> String {
    d.iter().take(20).map(|b| format!("{b:02X}")).collect::<Vec<_>>().join(" ")
}
/// policy: set aturan blok TX.
/// --on --dst IP --mask MASK --port PORT --tcp / --udp / --any / --src
/// --off : hanya matikan Enabled, aturan tetap.
pub fn cmd_policy(args: &CmdArgs) {
    match NlDevice::open() {
        Ok(dev) => {
            let mut p = NlPolicy::default();
            let mut r = NlPolicyRule::default();
            let mut ip_str = String::new();

            if !args.flag("--on") && !args.flag("--off") {
                println!("policy pakai --on atau --off");
                return;
            }

            if args.flag("--on") {
                let dst = args.get("--dst");
                let src = args.get("--src");
                let dstmac = args.get("--dstmac");
                if dst.is_none() && src.is_none() && dstmac.is_none() {
                    println!("policy --on butuh --dst <ip>, --src <ip>, atau --dstmac AA:BB:CC:DD:EE:FF");
                    return;
                }
                ip_str = dstmac.clone().unwrap_or_else(|| dst.clone().unwrap_or_else(|| src.clone().unwrap()));
                let mut oct = [0u8; 4];
                let mut macf = false;
                if let Some(m) = dstmac {
                    let parts: Vec<&str> = m.split(':').collect();
                    if parts.len() != 6 {
                        println!("MAC tidak valid: {m}");
                        return;
                    }
                    for i in 0..6 {
                        r.dst_mac[i] = u8::from_str_radix(parts[i], 16).unwrap_or(0);
                    }
                    r.match_bits |= MATCH_DSTMAC;
                    macf = true;
                }
                if !macf {
                    if dst.is_none() && src.is_none() {
                        println!("policy --on butuh --dst <ip> atau --src <ip>");
                        return;
                    }
                    let bs: Vec<&str> = ip_str.split('.').collect();
                    if bs.len() != 4 {
                        println!("IP tidak valid: {ip_str}");
                        return;
                    }
                    for i in 0..4 {
                        oct[i] = bs[i].parse::<u8>().unwrap_or(0);
                    }
                }
                let ip = u32::from_le_bytes(oct);
                let mask = match args.get("--mask") {
                    Some(m) => {
                        let cm: Vec<&str> = m.split('.').collect();
                        let mut mo = [0u8; 4];
                        for i in 0..4 { mo[i] = cm.get(i).and_then(|s| s.parse::<u8>().ok()).unwrap_or(0); }
                        u32::from_le_bytes(mo)
                    }
                    None => u32::from_le_bytes([255, 255, 255, 255]),
                };
                r.ip = ip;
                r.mask = mask;
                if dst.is_some() { r.match_bits |= MATCH_DST; }
                if src.is_some() { r.match_bits |= MATCH_SRC; }
                r.proto = if args.flag("--tcp") { 6 } else if args.flag("--udp") { 17 } else if args.flag("--proto") { args.num("--proto", 0) as u32 } else { 0 };
                let port = args.num("--port", 0) as u16;
                r.port_min = port;
                r.port_max = port;
                if port == 0 { /* any port: 1..65535 */ }
                p.count = 1;
                p.rules[0] = r;
                p.enabled = 1;
            } else {
                p.enabled = 0;
            }

            match dev.set_policy(&p) {
                Ok(()) => {
                    let proto_s = if r.proto == 6 { "tcp" } else if r.proto == 17 { "udp" } else { "any" };
                    let match_s = if (r.match_bits & MATCH_DSTMAC) != 0 {
                        format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                r.dst_mac[0], r.dst_mac[1], r.dst_mac[2],
                                r.dst_mac[3], r.dst_mac[4], r.dst_mac[5])
                    } else if (r.match_bits & MATCH_DST) != 0 { "dst".to_string() } else { "src".to_string() };
                    let port_s = if r.port_min == 0 { "any".to_string() } else { format!("{}", r.port_min) };
                    if p.enabled == 1 {
                        println!("policy AKTIF: proto={} match={} url={} mask={:#x} port={}", proto_s, match_s, ip_str, r.mask, port_s);
                    } else {
                        println!("policy MATI (aturan direset).");
                    }
                }
                Err(e) => println!("SET_POLICY gagal: {e}"),
            }
        }
        Err(e) => println!("driver: TIDAK ADA ({e})"),
    }
}
