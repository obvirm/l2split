//! Mode CLI l2split — bisa dipanggil dari binary mana pun (single-exe).
//!
//! Subcommands:
//!   list                      enumerate adapter
//!   lookup                    dump port -> exe map (debug)
//!   observe <adapter> [secs]  tangkap + cetak traffic tanpa rewrite
//!   run [options]             rebind traffic dari adapter FROM ke adapter TO
use crate::helpers::{adapter_ip, adapter_mac, friendly, resolve, CmdArgs};
use crate::nlclient::{NlDevice, NlMode, MODE_RX, MODE_TX, NL_RING_TX};
use crate::proclookup;

pub fn run_cli() {
    let args = CmdArgs::new();
    let cmd = args.cmd();

    match cmd.as_str() {
        "list" => cmd_list(),
        "nd" => cmd_nd(),
        "ndclear" => cmd_ndclear(),
        "ndcap" => cmd_ndcap(&args),
        "ndrun" => cmd_ndrun(&args),
        "apps" => cmd_apps(),
        "driver" => crate::nlclient::cmd_driver_check(),
        "ring" => crate::nlclient::cmd_ring(&args),
        "ringd" => crate::nlclient::cmd_ring_daemon(&args),
        "mode" => crate::nlclient::cmd_mode(&args),
        "stats" => crate::nlclient::cmd_stats(),
        "inject" => crate::nlclient::cmd_inject(&args),
        "policy" => crate::nlclient::cmd_policy(&args),
        "lookup" => cmd_lookup(),
        "observe" => cmd_observe(&args),
        "run" => crate::nlengine::cmd_run(&args),
        _ => {
            eprintln!("usage: l2split <apps|list|lookup|observe|run|driver|stats|mode|ring|inject> [options]");
            eprintln!("  apps                          daftar aplikasi terdeteksi (running + terinstal)");
        eprintln!("  driver                        cek control device driver (diagnostik)");
            eprintln!("  stats                         statistik ring/sink statistik kernel (v1)");
            eprintln!("  mode [--rx] [--tx] [--off] [--idx N]  set mode capture");
            eprintln!("  ring [--mode 3] [--n N] [--hex]       drain ring capture");
            eprintln!("  inject <file.bin>                     kirim frame mentah ke adapter");
            eprintln!("  list");
            eprintln!("  observe <adapter-needle> [secs]");
            eprintln!("  run --from <ad> --to <ad> --app <exe>[,<exe>] [--secs N]");
            eprintln!("  nd     driver paket + daftar adapter");
            eprintln!("  ndclear                        pemulihan: kosongkan filter + mode NORMAL");
            eprintln!("  ndcap <adapter-needle> --mac X [--secs N --tunnel --raw --alltx --verbose]");
            eprintln!("  ndrun --from <ad> --to <ad> --app <exe>[,<exe>] [--secs N]");
            std::process::exit(2);
        }
    }
}

/// apps: daftar aplikasi terdeteksi (proses berjalan + registry terinstal).
fn cmd_apps() {
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, path) in proclookup::process_exes() {
        map.entry(name).or_insert(path);
    }
    for (name, path) in proclookup::installed_exes() {
        map.entry(name).or_insert(path);
    }
    map.retain(|_, p| !p.eq_ignore_ascii_case(&self_exe));
    let running: std::collections::HashSet<String> = proclookup::process_exes()
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    println!("apps terdeteksi: {}\n", map.len());
    for (name, path) in map {
        let tag = if running.contains(&name) { "[R]" } else { "[ ]" };
        println!("  {tag} {name:<28} {path}");
    }
}

fn cmd_list() {
    let d = NlDevice::open().expect("driver ndislwf tidak terinstall");
    let adapters = d.adapters().expect("gagal enumerate adapter");
    println!("=== Adapter tersedia ===\n");
    for (i, a) in adapters.iter().enumerate() {
        let f = friendly(&adapters, i);
        let ip = adapter_ip(&f).unwrap_or_else(|| "-".into());
        println!("  [{i:>2}] {f:<34} ip={ip:<16} mac={} idx={} (pada ring idx ~ filter instance)",
                 adapter_mac(a), a.index);
    }
}

/// observe: intercept adapter, hitung arah + app pemilik, re-inject tanpa diubah.
fn cmd_observe(args: &CmdArgs) {
    let pos = args.positional();
    let needle = pos.first().cloned().unwrap_or_else(|| "Ethernet".into());
    let secs = pos.get(1).and_then(|s| s.parse::<u64>().ok()).unwrap_or(10);

    let d = NlDevice::open().expect("driver ndislwf tidak terinstall");
    let adapters = d.adapters().expect("gagal enumerate adapter");
    let i = match resolve(&adapters, &needle) {
        Some(i) => i,
        None => {
            eprintln!("adapter '{needle}' tidak ditemukan. Jalankan `l2split list`.");
            std::process::exit(1);
        }
    };
    let idx = adapters[i].index;

    println!("Target : {}", friendly(&adapters, i));
    println!("Window : {secs}s");
    println!("--- generate traffic sekarang ---");

    // mode capture TX+RX; passthrough tetap berjalan, observe hanya membaca ring
    let _ = d.set_mode(NlMode { adapter_index: idx, flags: MODE_RX | MODE_TX });
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let (mut sent, mut recv) = (0u64, 0u64);
    let mut lookup = proclookup::build();
    let mut seen: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut ctr = 0u64;

    while std::time::Instant::now() < deadline {
        if let Ok(items) = d.read_ring(None, 256) {
            for e in &items {
                if (e.flags & NL_RING_TX) != 0 {
                    sent += 1;
                    ctr += 1;
                    if ctr % 50 == 0 {
                        lookup = proclookup::build();
                    }
                    if let Some(exe) = packet_owner(&e.data[..e.len as usize], &lookup) {
                        *seen.entry(exe).or_insert(0) += 1;
                    }
                } else {
                    recv += 1;
                }
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(120));
    }

    let _ = d.set_mode(NlMode { adapter_index: idx, flags: 0 });
    report(sent, recv, &seen);
}

/// Parse eth/ip/tcp|udp -> exe pemilik berdasarkan source port.
fn packet_owner(d: &[u8], map: &proclookup::LookupMap) -> Option<String> {
    if d.len() < 34 || u16::from_be_bytes([d[12], d[13]]) != 0x0800 {
        return None;
    }
    let ip = &d[14..];
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ihl < 20 || ip.len() < ihl + 4 {
        return None;
    }
    let proto = ip[9];
    if proto != 6 && proto != 17 {
        return None;
    }
    let sport = u16::from_be_bytes([ip[ihl], ip[ihl + 1]]);
    map.get(&(sport, proto == 6)).cloned()
}

/// Cetak ringkasan hasil.
fn report(sent: u64, recv: u64, seen: &std::collections::HashMap<String, u64>) {
    println!("\n=== HASIL ===");
    println!("outbound (app -> net) : {sent}");
    println!("inbound  (net -> app) : {recv}");
    let mut v: Vec<_> = seen.iter().collect();
    v.sort_by(|a, b| b.1.cmp(a.1));
    if !v.is_empty() {
        println!("\n=== APP terdeteksi ===");
        for (exe, n) in v.iter().take(15) {
            let short = exe.rsplit('\\').next().unwrap_or(exe);
            println!("  {n:>7}  {short}");
        }
    }
    if sent + recv == 0 {
        println!("VERDICT: tidak ada traffic di adapter ini");
    } else {
        println!("VERDICT: adapter terlihat oleh ndislwf");
    }
}
/// lookup: dump port->exe map buat debug.
fn cmd_lookup() {
    let m = proclookup::build();
    println!("lookup entries: {}", m.len());
    let mut v: Vec<_> = m.iter().collect();
    v.sort_by(|a, b| a.0 .0.cmp(&b.0 .0));
    for ((port, is_tcp), exe) in v.iter().take(40) {
        let short = exe.rsplit('\\').next().unwrap_or(exe);
        let proto = if *is_tcp { "tcp" } else { "udp" };
        println!("  {port:>5}/{proto}  {short}");
    }
}

/// nd: cek driver + daftar adapter ter-attach (klien NL langsung, \\.\NDISLWF).
fn cmd_nd() {
    let dev = match NlDevice::open() {
        Ok(d) => d,
        Err(e) => {
            println!("DRIVER: GAGAL — {e}");
            std::process::exit(1);
        }
    };
    println!("DRIVER: OK");
    match dev.version() {
        Ok(v) if v.magic == crate::nlclient::NL_ABI_MAGIC =>
            println!("  ABI v{}.{} (magic ok)", v.ver >> 16, v.ver & 0xFFFF),
        Ok(v) => println!("  ABI GAK COCOK: magic={:#x}", v.magic),
        Err(e) => println!("  version ioctl gagal: {e}"),
    }
    match dev.adapters() {
        Ok(ads) => {
            println!("adapters TCP/IP-bound: {}", ads.len());
            for a in &ads {
                let nm: String = a.ifname.iter().take_while(|&&c| c != 0)
                    .map(|c| char::from_u32(*c as u32).unwrap_or('?')).collect();
                println!(
                    "  name={:<30} mac={} flags={:#x} idx={}",
                    nm,
                    crate::helpers::fmt_mac(&a.mac),
                    a.flags,
                    a.index
                );
            }
        }
        Err(e) => println!("enum gagal: {e}"),
    }
}

/// ndclear: pemulihan paksa — mode semua adapter passthrough + ring/filter kernel dikosongkan.
/// Dipakai uninstaller + manusia saat butuh pulih.
fn cmd_ndclear() {
    let dev = match NlDevice::open() {
        Ok(d) => d,
        Err(e) => {
            println!("ndclear: driver tidak bisa dibuka — {e}");
            std::process::exit(1);
        }
    };
    let mut n = 0usize;
    if let Ok(ads) = dev.adapters() {
        for i in 0..ads.len() {
            if dev.set_mode(NlMode { adapter_index: i as u32, flags: 0 }).is_ok() {
                n += 1;
            }
        }
    }
    match dev.clear() {
        Ok(()) => println!("ndclear: filter dikosongkan + mode passthrough di {} adapter", n),
        Err(e) => println!("ndclear: CLEAR gagal — {e}"),
    }
}

/// ndcap: pasang static filter dst-MAC (TX), drain ke read, hitung total.
fn cmd_ndcap(args: &CmdArgs) {
    use crate::ndclient::{NdisDevice, BATCH};
    use std::time::{Duration, Instant};

    let needle = args.positional().first().cloned().unwrap_or_default();
    let secs = args.num("--secs", 3) as u64;
    let raw = args.flag("--raw");
    let alltx = args.flag("--alltx");
    let verbose = args.flag("--verbose");
    let mac = args.get("--mac").and_then(|s| crate::helpers::parse_mac(&s));
    if mac.is_none() && !raw && !alltx {
        eprintln!("--mac wajib untuk mode filter dst-MAC (abaikan dengan --raw atau --alltx)");
        std::process::exit(2);
    }
    let mac = mac.unwrap_or([0u8; 6]);
    let d = NdisDevice::open().expect("driver");
    let ads = d.adapters().expect("enumerate");
    let ti = crate::helpers::resolve(&ads, &needle).expect("adapter tidak ketemu");
    let h = ads[ti].handle;
    let tunnel = args.flag("--tunnel");
    if !raw {
        if alltx {
            d.capture_tx_all().expect("filter ALL-TX");
        } else {
            d.capture_tx(mac).expect("pasang filter");
        }
    }
    let mut bufs: Vec<ndisapi::IntermediateBuffer> = vec![ndisapi::IntermediateBuffer::default(); BATCH];
    let ev = crate::helpers::make_event();
    let _ = d.set_event(h, ev);
    if tunnel {
        d.tunnel_tx(h).expect("set mode TUNNEL");
    }
    println!(
        "capture TX dst-MAC={} pada '{}' (tunnel={} raw={} alltx={})",
        crate::helpers::fmt_mac(&mac),
        ads[ti].name,
        tunnel,
        raw,
        alltx
    );
    let started = Instant::now();
    let mut total = 0usize;
    let mut hexed = false;
    let mut last_err = String::new();
    while started.elapsed() < Duration::from_secs(secs) {
        crate::helpers::wait_event(ev, 200);
        loop {
            let n = match d.read_batch_err(h, &mut bufs) {
                Ok(n) => n,
                Err(e) => {
                    if last_err != e {
                        println!("  read err: {e}");
                        last_err = e;
                    }
                    0
                }
            };
            if n == 0 {
                break;
            }
            total += n;
            for i in 0..n {
                let b = bufs[i].get_data();
                let dir = if bufs[i].get_device_flags()
                    == ndisapi::DirectionFlags::PACKET_FLAG_ON_SEND
                {
                    "TX"
                } else {
                    "RX"
                };
                if verbose {
                    println!(
                        "  dir={dir} len={} mac={:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X} {}",
                        bufs[i].get_length(),
                        b[0],
                        b[1],
                        b[2],
                        b[3],
                        b[4],
                        b[5],
                        frame_info(b).unwrap_or_default()
                    );
                }
            }
            if !hexed {
                let d32 = &bufs[0].get_data()[..bufs[0].get_data().len().min(32)];
                println!("  contoh frame head: {d32:02X?}");
                hexed = true;
            }
        }
        crate::helpers::reset_event(ev);
        let ks = started.elapsed().as_secs();
        if ks % 2 == 0 || !hexed {
            println!("  t={ks}s queue={}", d.queue_size(h).unwrap_or(0));
        }
    }
    d.clear();
    if tunnel {
        d.restore_mode(h);
    }
    println!(
        "VERDICT: {total} frame masuk user-mode dalam {secs} detik (queue akhir={})",
        d.queue_size(h).unwrap_or(0)
    );
}

/// Info ringkas ethernet frame (mac asal + ip/proto/port) untuk verbose.
fn frame_info(b: &[u8]) -> Option<String> {
    if b.len() < 14 {
        return None;
    }
    let src = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", b[6], b[7], b[8], b[9], b[10], b[11]);
    let ets = u16::from_be_bytes([b[12], b[13]]);
    if ets != 0x0800 {
        return Some(format!("src={src} evt={ets:04X}"));
    }
    let ip = b.get(14..)?;
    if ip.len() < 20 {
        return None;
    }
    let ihl = ((ip[0] & 0x0F) as usize) * 4;
    if ip.len() < ihl + 8 {
        return None;
    }
    let proto = ip[9];
    let dst_ip = format!("{}.{}.{}.{}", ip[16], ip[17], ip[18], ip[19]);
    if proto == 6 || proto == 17 {
        let p = &ip[ihl..];
        Some(format!(
            "src={src} ip={dst_ip} proto={proto} :{}->{}",
            u16::from_be_bytes([p[0], p[1]]),
            u16::from_be_bytes([p[2], p[3]])
        ))
    } else {
        Some(format!("src={src} ip={dst_ip} proto={proto}"))
    }
}

/// ndrun: jalankan engine (driver paket) via CLI — uji/otomasi tanpa GUI.
fn cmd_ndrun(args: &CmdArgs) {
    use crate::engine::{self, Shared};
    use crate::ndclient::{AdapterHandle, NdisDevice};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let to_n = args.get("--to").unwrap_or_default();
    let app = args.get("--app").unwrap_or_default();
    let secs = args.num("--secs", 15) as u64;
    let from_arg = args.get("--from").unwrap_or_default();

    if to_n.is_empty() {
        eprintln!("--to <adapter-needle> wajib (adapter LAN)");
        std::process::exit(2);
    }
    let d = NdisDevice::open().expect("driver");
    let ads = d.adapters().expect("enumerate");
    let from_n = if from_arg.is_empty() {
        crate::helpers::detect_vpn(&ads, &crate::helpers::net_overview())
            .unwrap_or_else(|| to_n.clone())
    } else {
        from_arg
    };
    let ti = crate::helpers::resolve(&ads, &to_n).expect("adapter TO tidak ketemu");
    let target_handle = ads[ti].handle;
    let gw = crate::helpers::gateway_of(&to_n).expect("TO tidak punya gateway");
    let to_gw_mac = crate::helpers::mac_of_ip(&gw)
        .and_then(|m| crate::helpers::parse_mac(&m))
        .expect("MAC gateway TO tidak diketahui");
    let from_gw_mac = crate::helpers::gateway_of(&from_n)
        .and_then(|g| crate::helpers::mac_of_ip(&g))
        .and_then(|m| crate::helpers::parse_mac(&m))
        .expect("MAC gateway FROM tidak diketahui");

    let shared = Shared::new();
    for name in app.split(',') {
        if !name.trim().is_empty() {
            shared.set_app(name.trim(), true);
        }
    }
    let drop_pass = args.flag("--drop-pass");
    let only_first = args.flag("--only-first");
    let only_from = args.flag("--only-from");
    let drop_all = args.flag("--drop-all");
    let listen = args.flag("--listen");
    let tunnel3 = args.flag("--tunnel3");
    let tunnel1 = args.flag("--tunnel1");
    let passno = args.flag("--passno");
    let redirect = args.flag("--redirect");
    let cancel = Arc::new(AtomicBool::new(false));
    println!("engine: from={from_n} to={to_n} apps={app} window={secs}s");
    let shared2 = shared.clone();
    let c2 = cancel.clone();
    let th = AdapterHandle(target_handle);
    let jh = std::thread::spawn(move || {
        engine::run(engine::Cfg {
            from_gw_mac,
            to_gw_mac,
            target_handle: th,
            from_name: from_n.clone(),
            cancel: c2,
            shared,
            drop_pass,
            only_first,
            only_from,
            drop_all,
            listen,
            tunnel3,
            tunnel1,
            passno,
            redirect,
        })
    });
    std::thread::sleep(Duration::from_secs(secs));
    cancel.store(true, Ordering::Relaxed);
    let _ = jh.join();
    println!(
        "VERDICT: total={} bypassed={} pass_through={}",
        shared2.stats.total.load(Ordering::Relaxed),
        shared2.stats.redirected.load(Ordering::Relaxed),
        shared2.stats.pass_through.load(Ordering::Relaxed)
    );
}
