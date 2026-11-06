//! Kalkulasi checksum IP / TCP / UDP (RFC 1071).

/// Internet checksum generik.
pub fn inet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    fold(sum)
}

/// Lipat carry sampai tersisa 16 bit, lalu komplementer.
fn fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Sum 4 byte IP sebagai dua word 16-bit.
fn ip_words(ip: &[u8]) -> u32 {
    u16::from_be_bytes([ip[0], ip[1]]) as u32 + u16::from_be_bytes([ip[2], ip[3]]) as u32
}

/// Checksum TCP/UDP dengan pseudo-header IPv4.
pub fn transport_checksum(src: &[u8], dst: &[u8], proto: u8, seg: &[u8]) -> u16 {
    let mut sum = ip_words(src) + ip_words(dst) + proto as u32 + seg.len() as u32;
    let mut i = 0;
    while i + 1 < seg.len() {
        sum += u16::from_be_bytes([seg[i], seg[i + 1]]) as u32;
        i += 2;
    }
    if i < seg.len() {
        sum += (seg[i] as u32) << 8;
    }
    fold(sum)
}

/// Perbaiki checksum IP header + TCP/UDP pada frame Ethernet mentah.
/// `d` = eth(14) + ip + payload. Offset IP = 14.
pub fn fix_frame(d: &mut [u8]) {
    // Cukup IPv4
    if d.len() < 34 || u16::from_be_bytes([d[12], d[13]]) != 0x0800 {
        return;
    }
    let ihl = ((d[23] & 0x0F) as usize) * 4;
    if ihl < 20 || 14 + ihl > d.len() {
        return;
    }

    // IP header checksum
    d[24] = 0;
    d[25] = 0;
    let s = inet_checksum(&d[14..14 + ihl]);
    d[24] = (s >> 8) as u8;
    d[25] = (s & 0xFF) as u8;

    let proto = d[23];
    let seg_start = 14 + ihl;
    let total = u16::from_be_bytes([d[16], d[17]]) as usize;
    let seg_end = total.min(d.len());
    if seg_end <= seg_start {
        return;
    }

    if proto == 6 {
        // TCP: checksum di offset 16 dari segmen
        if seg_end - seg_start < 18 {
            return;
        }
        d[seg_start + 16] = 0;
        d[seg_start + 17] = 0;
        let c = transport_checksum(&d[14..18], &d[18..22], 6, &d[seg_start..seg_end]);
        d[seg_start + 16] = (c >> 8) as u8;
        d[seg_start + 17] = (c & 0xFF) as u8;
    } else if proto == 17 {
        // UDP: checksum di offset 6 dari segmen
        if seg_end - seg_start < 8 {
            return;
        }
        d[seg_start + 6] = 0;
        d[seg_start + 7] = 0;
        let c = transport_checksum(&d[14..18], &d[18..22], 17, &d[seg_start..seg_end]);
        d[seg_start + 6] = (c >> 8) as u8;
        d[seg_start + 7] = (c & 0xFF) as u8;
    }
}
