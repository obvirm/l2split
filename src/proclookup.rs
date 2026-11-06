// port/proto -> PID -> exe path (IPv4)
use std::collections::HashMap;
use windows::Win32::Foundation::NO_ERROR;
use windows::Win32::NetworkManagement::IpHelper::{
    GetExtendedTcpTable, GetExtendedUdpTable, TCP_TABLE_OWNER_PID_ALL, UDP_TABLE_OWNER_PID,
};

/// key: (host_order_port, is_tcp) -> exe path lowercase
pub type LookupMap = HashMap<(u16, bool), String>;

pub fn pid_to_exe(pid: u32) -> Option<String> {
    use windows::Win32::Foundation::CloseHandle;
    use windows::core::PWSTR;
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_NAME_FORMAT,
        PROCESS_QUERY_LIMITED_INFORMATION,
    };
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 512];
        let mut size = buf.len() as u32;
        let r = QueryFullProcessImageNameW(
            h,
            PROCESS_NAME_FORMAT(0),
            PWSTR(buf.as_mut_ptr()),
            &mut size,
        );
        let _ = CloseHandle(h);
        if r.is_err() {
            return None;
        }
        Some(
            String::from_utf16_lossy(&buf[..size as usize]).to_lowercase(),
        )
    }
}

fn scan(buf: &[u8], is_tcp: bool) -> Vec<(u16, u32)> {
    let mut out = Vec::new();
    if buf.len() < 4 {
        return out;
    }
    let n = u32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    let (row, po, qo) = if is_tcp { (24usize, 8usize, 20usize) } else { (12, 4, 8) };
    for i in 0..n {
        let off = 4 + i * row;
        if off + row > buf.len() {
            break;
        }
        let rp = u32::from_ne_bytes([
            buf[off + po],
            buf[off + po + 1],
            buf[off + po + 2],
            buf[off + po + 3],
        ]);
        let pid = u32::from_ne_bytes([
            buf[off + qo],
            buf[off + qo + 1],
            buf[off + qo + 2],
            buf[off + qo + 3],
        ]);
        if pid == 0 {
            continue;
        }
        out.push((((rp & 0xFFFF) as u16).swap_bytes(), pid));
    }
    out
}

fn fetch(is_tcp: bool) -> Vec<u8> {
    let mut size: u32 = 0;
    let mut buf = vec![0u8; 65536];

    // Panggil pertama untuk minta ukuran yang dibutuhkan.
    let _ = unsafe {
        if is_tcp {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        } else {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }
    };

    if size as usize > buf.len() {
        buf.resize(size as usize + 4096, 0);
    }

    let ok = unsafe {
        if is_tcp {
            GetExtendedTcpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                TCP_TABLE_OWNER_PID_ALL,
                0,
            )
        } else {
            GetExtendedUdpTable(
                Some(buf.as_mut_ptr() as *mut _),
                &mut size,
                false,
                2,
                UDP_TABLE_OWNER_PID,
                0,
            )
        }
    };

    if ok != NO_ERROR.0 {
        return Vec::new();
    }
    buf.truncate(size as usize);
    buf
}

/// Daftar basename exe yang sedang punya koneksi jaringan (untuk dropdown GUI).
pub fn running_exes() -> Vec<String> {
    let mut set = std::collections::BTreeSet::new();
    for (name, _) in exe_paths() {
        set.insert(name);
    }
    set.into_iter().collect()
}

/// Peta basename (huruf kecil) -> path lengkap untuk exe dengan koneksi jaringan.
pub fn exe_paths() -> Vec<(String, String)> {
    let mut map = std::collections::BTreeMap::new();
    for is_tcp in [true, false] {
        let buf = fetch(is_tcp);
        for (_, pid) in scan(&buf, is_tcp) {
            if let Some(exe) = pid_to_exe(pid) {
                if let Some(b) = exe.rsplit('\\').next() {
                    map.entry(b.to_lowercase()).or_insert(exe);
                }
            }
        }
    }
    map.into_iter().collect()
}

/// Snapshot: (port, is_tcp) -> exe path lowercase
pub fn build() -> LookupMap {
    let mut map = LookupMap::new();
    for is_tcp in [true, false] {
        let buf = fetch(is_tcp);
        for (port, pid) in scan(&buf, is_tcp) {
            if let Some(exe) = pid_to_exe(pid) {
                map.entry((port, is_tcp)).or_insert(exe);
            }
        }
    }
    map
}

/// Filter sistem: buang exe di folder Windows (svchost, csrss, dll) & cache installer.
fn user_friendly(exe: &str) -> bool {
    !(exe.starts_with("c:\\windows\\")
        || exe.starts_with("\\device\\")
        || exe.contains("\\package cache\\"))
}

/// Semua exe proses yang sedang berjalan (tidak hanya yang punya koneksi).
pub fn process_exes() -> Vec<(String, String)> {
    use windows::Win32::System::ProcessStatus::EnumProcesses;
    unsafe {
        let mut pids = [0u32; 2048];
        let mut cb = 0u32;
        let _ = EnumProcesses(
            pids.as_mut_ptr(),
            (pids.len() * std::mem::size_of::<u32>()) as u32,
            &mut cb,
        );
        let n = (cb as usize / std::mem::size_of::<u32>()).min(pids.len());
        let mut map = std::collections::BTreeMap::new();
        for i in 0..n {
            if pids[i] == 0 {
                continue;
            }
            let Some(exe) = pid_to_exe(pids[i]) else {
                continue;
            };
            if !user_friendly(&exe) {
                continue;
            }
            if let Some(b) = exe.rsplit(['\\', '/']).next() {
                map.entry(b.to_string()).or_insert(exe);
            }
        }
        map.into_iter().collect()
    }
}

/// Exe aplikasi terinstal dari registry Uninstall (DisplayIcon -> path .exe).
pub fn installed_exes() -> Vec<(String, String)> {
    use winreg::enums::{HKEY_CURRENT_USER, HKEY_LOCAL_MACHINE};
    use winreg::RegKey;
    let roots = [HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER];
    let subs = [
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    ];
    let mut map = std::collections::BTreeMap::new();
    for root in roots {
        for sub in subs {
            let Ok(k) = RegKey::predef(root).open_subkey(sub) else {
                continue;
            };
            for sk in k.enum_keys().flatten() {
                let Ok(e) = k.open_subkey(&sk) else { continue };
                // abaikan komponen sistem & update KB (tidak relevan utk bypass)
                let sys = e.get_value::<u32, _>("SystemComponent").unwrap_or(0);
                if sys == 1 {
                    continue;
                }
                let Ok(icon) = e.get_value::<String, _>("DisplayIcon") else {
                    continue;
                };
                let Some(path) = icon_to_exe(&icon) else { continue };
                if !user_friendly(&path) || !std::path::Path::new(&path).is_file() {
                    continue;
                }
                if let Some(b) = path.rsplit(['\\', '/']).next() {
                    map.entry(b.to_string()).or_insert(path);
                }
            }
        }
    }
    map.into_iter().collect()
}

fn icon_to_exe(icon: &str) -> Option<String> {
    let s = icon.split(',').next()?.trim();
    let s = s.trim_matches('"');
    if s.to_lowercase().ends_with(".exe") {
        Some(s.to_lowercase())
    } else {
        None
    }
}
