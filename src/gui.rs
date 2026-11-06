//! GUI Tauri — WebView2, frontend = ui/index.html.
//! Logika bridge tetap memakai crate engine/helpers yang sama.
use crate::engine::{self, Shared};
use crate::helpers::{

    detect_vpn, friendly, gateway_of, mac_of_ip, net_detail, net_overview,
    parse_mac, resolve,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use crate::nlclient::NlDevice;

use serde::Serialize;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Emitter, Manager};

#[tauri::command(async)]
fn apply_ip_config(
    app: AppHandle,
    adapter: String,
    mode: String,
    ip: String,
    gw: String,
    mask: String,
    dns1: String,
    dns2: String,
) -> Result<String, String> {
    let _ = app;
    let a = adapter.replace('"', "");
    let mut batch = String::new();
    if mode == "Static" {
        if ip.is_empty() {
            return Err("IP address kosong".into());
        }
        if mask.is_empty() {
            return Err("Subnet mask kosong".into());
        }
        let g = if gw.is_empty() { String::new() } else { format!(" {gw}") };
        batch.push_str(&format!(
            "netsh interface ip set address name=\"{a}\" static {ip} {mask}{g}\r\n"
        ));
        if dns1.is_empty() {
            batch.push_str(&format!(
                "netsh interface ip set dns name=\"{a}\" source=dhcp\r\n"
            ));
        } else {
            batch.push_str(&format!(
                "netsh interface ip set dns name=\"{a}\" static {dns1}\r\n"
            ));
        }
        if !dns2.is_empty() {
            batch.push_str(&format!(
                "netsh interface ip add dns name=\"{a}\" static {dns2} index=2\r\n"
            ));
        }
    } else {
        batch.push_str(&format!(
            "netsh interface ip set address name=\"{a}\" source=dhcp\r\n"
        ));
        batch.push_str(&format!(
            "netsh interface ip set dns name=\"{a}\" source=dhcp\r\n"
        ));
    }
    // netsh butuh admin: satu prompt UAC untuk semua perintah
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let esc = batch.replace('\"', "\\\"");
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command",
            &format!("Start-Process powershell -Verb RunAs -Wait -ArgumentList '-NoProfile -Command \"{}\"'", esc)])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .map_err(|e| format!("gagal spawn UAC: {e}"))?;
    if !out.status.success() || String::from_utf8_lossy(&out.stderr).to_lowercase().contains("canceled") {
        return Err("UAC dibatalkan / gagal".into());
    }
    Ok("Konfigurasi IP diterapkan".into())
}

#[tauri::command(async)]
fn get_autostart(_app: AppHandle) -> bool {
    use winreg::enums::*;
    let hkcu = winreg::RegKey::predef(HKEY_CURRENT_USER);
    let run = hkcu.open_subkey(r"Software\Microsoft\Windows\CurrentVersion\Run");
    match run {
        Ok(k) => k.get_value::<String, _>("l2split").is_ok(),
        Err(_) => false,
    }
}

#[tauri::command(async)]
fn set_autostart(_app: AppHandle, enabled: bool) -> Result<String, String> {
    let hkcu = winreg::RegKey::predef(winreg::enums::HKEY_CURRENT_USER);
    let run = hkcu
        .open_subkey_with_flags(
            r"Software\Microsoft\Windows\CurrentVersion\Run",
            winreg::enums::KEY_SET_VALUE | winreg::enums::KEY_QUERY_VALUE,
        )
        .map_err(|e| format!("registry: {e}"))?;
    const NAME: &str = "l2split";
    if enabled {
        let exe = std::env::current_exe()
            .map(|p| p.to_string_lossy().to_string())
            .map_err(|e| format!("path: {e}"))?;
        run.set_value(NAME, &format!("\"{exe}\""))
            .map_err(|e| format!("set: {e}"))?;
        Ok("Autostart diaktifkan".into())
    } else {
        let _ = run.delete_value(NAME);
        Ok("Autostart dinonaktifkan".into())
    }
}

// ================= driver setup wizard =================

fn driver_scripts_dir() -> Result<std::path::PathBuf, String> {
    let exe = std::env::current_exe().map_err(|e| format!("path: {e}"))?;
    let dir = exe.parent().ok_or("path parent gagal")?;
    let cands = [
        dir.join("driver"),
        dir.join("..").join("driver"),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("driver"),
    ];
    for c in cands {
        if c.join("prepare.ps1").exists() {
            return Ok(c);
        }
    }
    Err("folder driver (prepare.ps1) tidak ditemukan di samping aplikasi".into())
}

#[tauri::command(async)]
fn driver_check() -> bool {
    NlDevice::open().is_ok()
}

#[tauri::command(async)]
fn driver_setup(reboot: bool) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let dir = driver_scripts_dir()?;
    let arg = dir.join("prepare.ps1").to_string_lossy().into_owned();
    let list = if reboot {
        format!("@('-NoProfile','-ExecutionPolicy','Bypass','-File','{}','-Reboot')", arg.replace("'", "''"))
    } else {
        format!("@('-NoProfile','-ExecutionPolicy','Bypass','-File','{}')", arg.replace("'", "''"))
    };
    let cmd = format!("Start-Process powershell.exe -Verb RunAs -ArgumentList {}", list);
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("elevate: {e}"))?;
    Ok(if reboot {
        "UAC diminta — tekan Yes. Setelah testsigning terpasang, komputer akan reboot dan driver dipasang otomatis."
    } else {
        "UAC diminta — tekan Yes. Setelah itu lakukan reboot sekali untuk berlaku."
    }.into())
}

#[tauri::command(async)]
fn driver_teardown(reboot: bool) -> Result<String, String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let dir = driver_scripts_dir()?;
    let arg = dir.join("teardown.ps1").to_string_lossy().into_owned();
    let list = if reboot {
        format!("@('-NoProfile','-ExecutionPolicy','Bypass','-File','{}','-Reboot')", arg.replace("'", "''"))
    } else {
        format!("@('-NoProfile','-ExecutionPolicy','Bypass','-File','{}')", arg.replace("'", "''"))
    };
    let cmd = format!("Start-Process powershell.exe -Verb RunAs -ArgumentList {}", list);
    std::process::Command::new("powershell.exe")
        .args(["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", &cmd])
        .creation_flags(CREATE_NO_WINDOW)
        .spawn()
        .map_err(|e| format!("elevate: {e}"))?;
    Ok(if reboot {
        "UAC diminta — tekan Yes. Driver dilepas, testsigning OFF, lalu reboot."
    } else {
        "UAC diminta — tekan Yes. Setelah itu lakukan reboot sekali untuk berlaku."
    }.into())
}

#[derive(Serialize, Clone)]
pub struct AppEntry {
    pub name: String,
    pub path: String,
    pub icon: String, // data:image/png;base64... ("" jika gagal)
    pub bypass: bool,
    pub running: bool,
}

#[derive(Serialize, Clone)]
pub struct AdapterEntry {
    pub name: String,
    pub label: String, // "Nama — IP"
}

#[derive(Serialize, Clone)]
pub struct NetInfo {
    pub vpn: String,
    pub lan: String,
    pub adapters: Vec<AdapterEntry>,
    pub dhcp: bool,
    pub ip: String,
    pub gw: String,
    pub mask: String,
    pub dns: Vec<String>,
    pub latency: String,
}

#[derive(Serialize, Clone)]
pub struct Stats {
    pub running: bool,
    pub total: u64,
    pub bypassed: u64,
    pub vpn: u64,
}

pub struct AppState {
    shared: Mutex<Option<Arc<Shared>>>,
    cancel: Mutex<Option<Arc<AtomicBool>>>,
    toggled: Mutex<HashSet<String>>,
    to_adapter: Mutex<String>,
    custom: Mutex<Vec<String>>, // path .exe manual dari UI
    icons: Mutex<std::collections::HashMap<String, String>>, // cache ikon per path
}

// ================= commands =================

#[tauri::command(async)]
fn list_apps(app: AppHandle) -> Vec<AppEntry> {
    let st = app.state::<AppState>();
    // gabung: proses berjalan + aplikasi terinstal (registry) + path custom;
    // jangan tampilkan exe l2split sendiri.
    let self_exe = std::env::current_exe()
        .map(|p| p.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let mut map: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, path) in crate::proclookup::process_exes() {
        map.entry(name).or_insert(path);
    }
    for (name, path) in crate::proclookup::installed_exes() {
        map.entry(name).or_insert(path);
    }
    // prioritas: custom path menang sebagai lokasi referensi
    for path in st.custom.lock().unwrap().clone() {
        let name = std::path::Path::new(&path)
            .file_name()
            .map(|f| f.to_string_lossy().to_lowercase())
            .unwrap_or_else(|| path.clone());
        map.insert(name, path.clone());
    }

    map.retain(|_, path| !path.eq_ignore_ascii_case(&self_exe));
    st.toggled.lock().unwrap().retain(|k| map.contains_key(k));

    let running: HashSet<String> = crate::proclookup::process_exes()
        .into_iter()
        .map(|(n, _)| n)
        .collect();
    out_vec(st, map, running)
}

fn out_vec(
    st: tauri::State<AppState>,
    map: std::collections::BTreeMap<String, String>,
    running: HashSet<String>,
) -> Vec<AppEntry> {
    let mut icons = st.icons.lock().unwrap();
    map.into_iter()
        .map(|(name, path)| {
            let icon = icons
                .entry(path.clone())
                .or_insert_with(|| icon_data_url(&path))
                .clone();
            AppEntry {
                running: running.contains(&name),
                bypass: st.toggled.lock().unwrap().contains(&name),
                icon,
                name,
                path,
            }
        })
        .collect()
}

#[tauri::command(async)]
fn add_app_path(app: AppHandle, path: String) -> Result<(), String> {
    let st = app.state::<AppState>();
    let p = path.trim().to_string();
    if p.is_empty() {
        return Err("path kosong".into());
    }
    let p = if p.to_lowercase().ends_with(".exe") {
        p
    } else {
        format!("{p}.exe")
    };
    if !std::path::Path::new(&p).is_file() {
        return Err(format!("file tidak ditemukan: {p}"));
    }
    let mut c = st.custom.lock().unwrap();
    if !c.iter().any(|x| x.eq_ignore_ascii_case(&p)) {
        c.push(p);
    }
    Ok(())
}

#[tauri::command(async)]
fn get_net(app: AppHandle) -> Result<NetInfo, String> {
    let st = app.state::<AppState>();
    let d = NlDevice::open().map_err(|e| format!("driver ndislwf: {e} — jalankan driver\\driver.cmd (pilih 3 → reboot → 1)"))?;
    let adapters = d.adapters().map_err(|e| format!("enumerate: {e}"))?;
    let overview = net_overview();
    let vpn = detect_vpn(&adapters, &overview).unwrap_or_else(|| "None".into());

    let list: Vec<AdapterEntry> = (0..adapters.len())
        .map(|i| {
            let name = friendly(&adapters, i);
            let ip = overview.get(&name).cloned().unwrap_or_default();
            AdapterEntry {
                label: format!("{name} — {ip}"),
                name,
            }
        })
        .collect();

    // TO default: adapter real — non-APIPA, bukan VPN/virtual, ada IP
    let mut to = st.to_adapter.lock().unwrap().clone();
    if to.is_empty() {
        let virt = |n: &str| {
            let l = n.to_lowercase();
            ["virtual", "vethernet", "loopback", "wan network"]
                .iter()
                .any(|k| l.contains(k))
        };
        to = list
            .iter()
            .find(|a| {
                !a.name.contains("169.254.")
                    && !a.name.to_lowercase().contains("vpn")
                    && !virt(&a.name)
            })
            .map(|a| a.name.clone())
            .or_else(|| list.first().map(|a| a.name.clone()))
            .unwrap_or_default();
        *st.to_adapter.lock().unwrap() = to.clone();
    }

    let (mut dhcp, mut ip, mut gw, mut mask, mut dns) = (true, String::new(), String::new(), String::new(), Vec::new());
    if let Some(det) = net_detail(&to) {
        dhcp = det.dhcp;
        ip = det.ip;
        gw = det.gw;
        mask = det.mask;
        dns = det.dns;
    }
    let latency = ping_ms(&gateway_of(&to).unwrap_or_else(|| "1.1.1.1".into()))
        .unwrap_or_else(|| "—".into());

    Ok(NetInfo {
        lan: to,
        adapters: list,
        ip,
        gw,
        mask,
        dns,
        dhcp,
        latency,
        vpn,
    })
}

#[tauri::command(async)]
fn get_latency(app: AppHandle) -> String {
    let st = app.state::<AppState>();
    let to = st.to_adapter.lock().unwrap().clone();
    ping_ms(&gateway_of(&to).unwrap_or_else(|| "1.1.1.1".into())).unwrap_or_else(|| "—".into())
}

#[tauri::command(async)]
fn set_bypass(app: AppHandle, name: String, on: bool) {
    let st = app.state::<AppState>();
    {
        let mut set = st.toggled.lock().unwrap();
        if on {
            set.insert(name.clone());
        } else {
            set.remove(&name);
        }
    }
    let guard = st.shared.lock().unwrap();
    if let Some(s) = guard.as_ref() {
        s.set_app(&name, on);
    }
}

#[tauri::command(async)]
fn set_to_adapter(app: AppHandle, name: String) {
    let st = app.state::<AppState>();
    *st.to_adapter.lock().unwrap() = name;
}

#[tauri::command(async)]
fn start(app: AppHandle) {
    app.emit("busy", true).ok();
    std::thread::spawn(move || {
        if let Err(e) = engine_bridge(&app) {
            let _ = app.emit("failed", &e);
        }
        let _ = app.emit("busy", false);
    });
}

#[tauri::command(async)]
fn stop(app: AppHandle) {
    let st = app.state::<AppState>();
    let mut guard = st.cancel.lock().unwrap();
    if let Some(c) = guard.take() {
        c.store(true, Ordering::Relaxed);
    }
}

// ================= engine =================

fn engine_bridge(app: &AppHandle) -> Result<(), String> {
    let st = app.state::<AppState>();
    let to_n = st.to_adapter.lock().unwrap().clone();
    if to_n.is_empty() {
        return Err("LAN adapter belum dipilih (Settings)".into());
    }
    let d = NlDevice::open().map_err(|e| format!("driver: {e} — pasang lewat folder driver\\: driver.cmd → 3 (testsigning ON) → reboot → 1 (install)"))?;
    let ads = d.adapters().map_err(|e| format!("enumerate: {e}"))?;

    // FROM auto: VPN connected; fallback = TO (no-op)
    let overview = net_overview();
    let from_n = detect_vpn(&ads, &overview).unwrap_or_else(|| to_n.clone());

    let ti = resolve(&ads, &to_n).ok_or("adapter TO tidak ditemukan")?;
    let _ = ti;

    let gw = gateway_of(&to_n).ok_or("TO tidak punya gateway")?;
    let to_gw_mac = mac_of_ip(&gw)
        .and_then(|m| parse_mac(&m))
        .ok_or("gateway MAC tidak diketahui")?;

    let shared = Shared::new();
    for name in st.toggled.lock().unwrap().iter() {
        shared.set_app(name, true);
    }
    let cancel = Arc::new(AtomicBool::new(false));
    *st.shared.lock().unwrap() = Some(shared.clone());
    *st.cancel.lock().unwrap() = Some(cancel.clone());

    // thread emit stats (250ms) — berhenti saat cancel
    {
        let ah = app.clone();
        let c2 = cancel.clone();
        let s2 = shared.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(200));
            while !c2.load(Ordering::Relaxed) {
                let _ = ah.emit(
                    "stats",
                    Stats {
                        running: true,
                        total: s2.stats.total.load(Ordering::Relaxed),
                        bypassed: s2.stats.redirected.load(Ordering::Relaxed),
                        vpn: s2.stats.pass_through.load(Ordering::Relaxed),
                    },
                );
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            let _ = ah.emit(
                "stats",
                Stats {
                    running: false,
                    total: 0,
                    bypassed: 0,
                    vpn: 0,
                },
            );
        });
    }

    let from_gw_mac = gateway_of(&from_n)
        .and_then(|g| mac_of_ip(&g))
        .and_then(|m| parse_mac(&m))
        .ok_or("gateway MAC VPN tidak diketahui")?;

    engine::run(engine::Cfg {
        from_gw_mac,
        to_gw_mac,
        cancel,
        shared,
    });
    Ok(())
}

// ================= helpers =================

/// Extract ikon exe -> data URL PNG ("" jika gagal).
fn icon_data_url(path: &str) -> String {
    let Some((w, h, px)) = icon_rgba(path) else {
        return String::new();
    };
    let mut buf = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut buf, w, h);
        enc.set_color(png::ColorType::Rgba);
        enc.set_depth(png::BitDepth::Eight);
        if let Ok(mut lw) = enc.write_header() {
            if lw.write_image_data(&px).is_err() {
                return String::new();
            }
        }
    }
    if buf.is_empty() {
        return String::new();
    }
    format!("data:image/png;base64,{}", B64.encode(buf))
}

/// Ping 1x — "14 ms" untuk kartu Latency.
fn ping_ms(target: &str) -> Option<String> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let out = std::process::Command::new("ping")
        .arg("-n").arg("1").arg("-w").arg("2000").arg(target)
        .creation_flags(CREATE_NO_WINDOW)
        .output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let b = text.as_bytes();
    for i in 0..b.len().saturating_sub(1) {
        if b[i] == b'm' && b[i + 1] == b's' {
            let mut j = i;
            while j > 0 && b[j - 1].is_ascii_digit() {
                j -= 1;
            }
            if j < i {
                if let Ok(ms) = text[j..i].parse::<u32>() {
                    return Some(format!("{ms} ms"));
                }
            }
        }
    }
    None
}

/// ExtractAssociatedIconW + GetDIBits -> (w,h,rgba).
fn icon_rgba(path: &str) -> Option<(u32, u32, Vec<u8>)> {
    use std::ffi::c_void;
    use windows::Win32::Foundation::HINSTANCE;
    use windows::Win32::Graphics::Gdi::{
        CreateCompatibleDC, DeleteDC, DeleteObject, GetDIBits, BITMAPINFO, BITMAPINFOHEADER,
        DIB_RGB_COLORS, HBITMAP, HGDIOBJ, HDC,
    };
    use windows::Win32::UI::Shell::ExtractAssociatedIconW;
    use windows::Win32::UI::WindowsAndMessaging::{DestroyIcon, GetIconInfo, ICONINFO};

    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    unsafe {
        let mut buf = [0u16; 128];
        let n = wide.len().min(buf.len() - 1);
        buf[..n].copy_from_slice(&wide[..n]);
        let mut id = 0u16;
        let hicon = ExtractAssociatedIconW(Some(HINSTANCE::default()), &mut buf, &mut id);
        if hicon.is_invalid() {
            return None;
        }
        let mut ii = ICONINFO::default();
        if GetIconInfo(hicon, &mut ii).is_err() {
            let _ = DestroyIcon(hicon);
            return None;
        }
        let _ = DestroyIcon(hicon);

        let hbm_color: HBITMAP = ii.hbmColor;
        if hbm_color.is_invalid() {
            let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
            return None;
        }

        // DC dulu — GetDIBits dengan DC null bikin ikon hilang
        let hdc = CreateCompatibleDC(None);
        if hdc.is_invalid() {
                let _ = DeleteObject(HGDIOBJ(hbm_color.0));
            let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
            return None;
        }
        let hdc: HDC = hdc;

        let mut bi = BITMAPINFO::default();
        bi.bmiHeader.biSize = std::mem::size_of::<BITMAPINFOHEADER>() as u32;
        if GetDIBits(hdc, hbm_color, 0, 0, None, &mut bi, DIB_RGB_COLORS) == 0 {
                let _ = DeleteObject(HGDIOBJ(hbm_color.0));
            let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
            let _ = DeleteDC(hdc);
            return None;
        }
        let w = bi.bmiHeader.biWidth;
        let h = bi.bmiHeader.biHeight;
        bi.bmiHeader.biBitCount = 32;
        bi.bmiHeader.biCompression = 0; // BI_RGB

        let buf_len = (w.abs() as usize) * (h.abs() as usize) * 4;
        let mut bgra = vec![0u8; buf_len];

        let r = GetDIBits(
            hdc,
            hbm_color,
            0,
            h.abs() as u32,
            Some(bgra.as_mut_ptr() as *mut c_void),
            &mut bi,
            DIB_RGB_COLORS,
        );
            let _ = DeleteObject(HGDIOBJ(hbm_color.0));
        let _ = DeleteObject(HGDIOBJ(ii.hbmMask.0));
        let _ = DeleteDC(hdc);
        if r == 0 {
            return None;
        }

        // BGRA -> RGBA
        let mut has_alpha = false;
        for px in bgra.chunks_exact_mut(4) {
            px.swap(0, 2);
            if px[3] != 0 {
                has_alpha = true;
            }
        }
        // ikon lama tanpa alpha -> solid
        if !has_alpha {
            for px in bgra.chunks_exact_mut(4) {
                px[3] = 255;
            }
        }
        if w == 0 || h == 0 || w > 256 || h > 256 {
            return None;
        }
        Some((w.unsigned_abs(), h.unsigned_abs(), bgra))
    }
}

// ================= entry GUI =================

pub fn run() -> Result<(), tauri::Error> {
    tauri::Builder::default()
        .setup(|app| {
            // paksa frameless (pengaman jika config tidak masuk)
            if let Some(w) = app.get_webview_window("main") {
                let _ = w.set_decorations(false);
            }
            Ok(())
        })
        .manage(AppState {
            shared: Mutex::new(None),
            cancel: Mutex::new(None),
            toggled: Mutex::new(HashSet::new()),
            to_adapter: Mutex::new(String::new()),
            custom: Mutex::new(Vec::new()),
            icons: Mutex::new(std::collections::HashMap::new()),
        })
        .invoke_handler(tauri::generate_handler![
            list_apps,
            add_app_path,
            get_net,
            get_latency,
            set_bypass,
            set_to_adapter,
            apply_ip_config,
            set_autostart,
            get_autostart,
            start,
            stop,
            driver_check,
            driver_setup,
            driver_teardown
        ])
        .run(tauri::generate_context!())
}
