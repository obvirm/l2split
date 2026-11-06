//! Utilitas bersama: arg parsing + adapter helpers.
use crate::nlclient::NlAdapter;

/// Parser argumen sederhana: `--key value` dan flag `--flag`.
pub struct CmdArgs {
    args: Vec<String>,
}

impl CmdArgs {
    pub fn new() -> Self {
        CmdArgs {
            args: std::env::args().skip(1).collect(),
        }
    }

    /// Subcommand = argumen pertama yang bukan flag.
    pub fn cmd(&self) -> String {
        self.args
            .iter()
            .find(|a| !a.starts_with("--"))
            .cloned()
            .unwrap_or_default()
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.args
            .iter()
            .position(|a| a == key)
            .and_then(|i| self.args.get(i + 1))
            .cloned()
    }

    pub fn flag(&self, key: &str) -> bool {
        self.args.iter().any(|a| a == key)
    }

    pub fn num(&self, key: &str, def: u64) -> u64 {
        self.get(key).and_then(|s| s.parse().ok()).unwrap_or(def)
    }

    /// Argumen positional setelah subcommand (subcommand di-skip).
    pub fn positional(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut i = 0;
        let mut seen_cmd = false;
        while i < self.args.len() {
            let a = &self.args[i];
            if a.starts_with("--") {
                i += 2; // skip flag + value-nya
            } else {
                if seen_cmd {
                    out.push(a.clone());
                } else {
                    seen_cmd = true; // ini subcommand
                }
                i += 1;
            }
        }
        out
    }
}

/// Decode nama adapter (utf16 null-terminated) dari NlAdapter.
pub fn adapter_name(a: &NlAdapter) -> String {
    String::from_utf16_lossy(
        a.ifname.iter().take_while(|c| **c != 0).map(|c| *c).collect::<Vec<_>>().as_slice(),
    )
}

/// Cari index adapter berdasarkan substring nama (case-insensitive).
pub fn resolve(adapters: &[NlAdapter], needle: &str) -> Option<usize> {
    adapters.iter().position(|a| adapter_name(a).to_lowercase().contains(&needle.to_lowercase()))
}

/// Nama adapter pada index tertentu.
pub fn friendly(adapters: &[NlAdapter], i: usize) -> String {
    adapter_name(&adapters[i])
}

/// Ambil IP IPv4 adapter via PowerShell (alias friendly name).
pub fn adapter_ip(alias: &str) -> Option<String> {
    let out = std::process::Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!(
                "(Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '{alias}' -ErrorAction SilentlyContinue | Select-Object -First 1).IPAddress"
            ),
        ])
        .output()
        .ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        None
    } else {
        Some(s)
    }
}

/// MAC address adapter dalam format heks.
pub fn adapter_mac(a: &NlAdapter) -> String {
    fmt_mac(&a.mac)
}

fn ps(cmd: &str) -> String {
    std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", cmd])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

/// Gateway IPv4 pada interface tertentu.
pub fn gateway_of(iface: &str) -> Option<String> {
    let s = ps(&format!(
        "(Get-NetRoute -AddressFamily IPv4 -InterfaceAlias '{iface}' -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue | Select-Object -First 1).NextHop"
    ));
    if s.is_empty() { None } else { Some(s) }
}

/// Satu kali spawn PowerShell: semua adapter -> (alias -> ip).
/// Menggantikan panggilan adapter_ip per-adapter (jauh lebih cepat).
pub fn net_overview() -> std::collections::HashMap<String, String> {
    use std::collections::HashMap;
    let s = ps(
        "Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' } | ForEach-Object { \"$($_.InterfaceAlias)|$($_.IPAddress)\" }",
    );
    let mut m = HashMap::new();
    for line in s.lines() {
        if let Some((alias, ip)) = line.split_once('|') {
            m.insert(alias.trim().to_string(), ip.trim().to_string());
        }
    }
    m
}

/// Detail konfigurasi IP satu adapter (untuk halaman Settings).
pub struct NetDetail {
    pub dhcp: bool,
    pub ip: String,
    pub gw: String,
    pub mask: String,
    pub dns: Vec<String>,
}

pub fn net_detail(alias: &str) -> Option<NetDetail> {
    let a = alias.replace('\'', "''");
    let s = ps(&format!(
        "$ErrorActionPreference='SilentlyContinue'; $ip = Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias '{a}' | Where-Object {{ $_.IPAddress -notlike '169.254.*' }} | Select-Object -First 1; $r = Get-NetRoute -AddressFamily IPv4 -InterfaceAlias '{a}' -DestinationPrefix '0.0.0.0/0' | Select-Object -First 1; $d = Get-DnsClientServerAddress -AddressFamily IPv4 -InterfaceAlias '{a}' | Select-Object -First 1; $i = Get-NetIPInterface -AddressFamily IPv4 -InterfaceAlias '{a}' | Select-Object -First 1; \"DHCP='\" + [string]($i.Dhcp -eq 'Enabled') + \"'IP='\" + [string]($ip.IPAddress) + \"'GW='\" + [string]($r.NextHop) + \"'PFX='\" + [string]($ip.PrefixLength) + \"'DNS='\" + [string]($d.ServerAddresses -join ',')"
    ));
    // format stabil: DHCP=..IP=..GW=..PFX=..DNS=..  (key= dihapus saat parse)
    let grab = |key: &str| -> String {
        let start = match s.find(key) {
            Some(i) => i + key.len(),
            None => return String::new(),
        };
        let rest = &s[start..];
        match rest.find('\'') {
            Some(e) => rest[..e].trim().to_string(),
            None => rest.trim().to_string(),
        }
    };
    if s.contains("IP=''") {
        return None;
    }
    Some(NetDetail {
        dhcp: grab("DHCP='") == "True",
        ip: grab("IP='"),
        gw: grab("GW='"),
        mask: prefix_to_mask(grab("PFX='").parse().unwrap_or(24)),
        dns: grab("DNS='")
            .split(',')
            .filter(|x| !x.is_empty())
            .map(String::from)
            .collect(),
    })
}

/// Prefix length -> dotted subnet mask.
pub fn prefix_to_mask(prefix: u32) -> String {
    let m = if prefix == 0 { 0u32 } else { u32::MAX << (32 - prefix.min(32)) };
    let b = m.to_be_bytes();
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

const VPN_HINTS: &[&str] = &[
    "vpn", "tun", "tailscale", "warp", "wireguard", "openvpn", "privado", "urban",
];

/// Auto-detect adapter VPN: nama cocok pola VPN + punya IP connected (bukan APIPA).
pub fn detect_vpn(
    adapters: &[NlAdapter],
    overview: &std::collections::HashMap<String, String>,
) -> Option<String> {
    for i in 0..adapters.len() {
        let name = friendly(adapters, i);
        let low = name.to_lowercase();
        if VPN_HINTS.iter().any(|h| low.contains(h)) {
            if let Some(ip) = overview.get(&name) {
                if !ip.is_empty() && !ip.starts_with("169.254.") {
                    return Some(name);
                }
            }
        }
    }
    None
}

/// MAC milik IP tertentu, dari tabel neighbor (ARP).
pub fn mac_of_ip(ip: &str) -> Option<String> {
    let s = ps(&format!(
        "((Get-NetNeighbor -AddressFamily IPv4 -IPAddress '{ip}' -ErrorAction SilentlyContinue | Select-Object -First 1).LinkLayerAddress)"
    ));
    let s = s.replace('-', ":");
    if s.is_empty() || s == "00:00:00:00:00:00" {
        None
    } else {
        Some(s)
    }
}

/// Format [u8;6] jadi "AA:BB:CC:DD:EE:FF".
pub fn fmt_mac(m: &[u8; 6]) -> String {
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

/// "AA:BB:CC:DD:EE:FF" -> [u8;6]
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let v: Vec<u8> = s
        .split(|c| c == ':' || c == '-')
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    if v.len() == 6 {
        let mut a = [0u8; 6];
        a.copy_from_slice(&v);
        Some(a)
    } else {
        None
    }
}

/// "a.b.c.d" -> u32 (network order)
pub fn parse_ip(s: &str) -> Option<u32> {
    let v: Vec<u8> = s.split('.').filter_map(|p| p.parse().ok()).collect();
    if v.len() == 4 {
        Some(u32::from_be_bytes([v[0], v[1], v[2], v[3]]))
    } else {
        None
    }
}

/// Buat Win32 event untuk notifikasi paket dari driver.
pub fn make_event() -> windows::Win32::Foundation::HANDLE {
    use windows::Win32::System::Threading::CreateEventW;
    unsafe { CreateEventW(None, true, false, None) }.expect("CreateEventW")
}

/// Tunggu event sampai timeout (ms).
pub fn wait_event(
    e: windows::Win32::Foundation::HANDLE,
    ms: u32,
) {
    use windows::Win32::System::Threading::WaitForSingleObject;
    unsafe { WaitForSingleObject(e, ms) };
}
