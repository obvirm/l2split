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
