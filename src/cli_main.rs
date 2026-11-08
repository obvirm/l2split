//! l2split CLI — subsystem console. Khusus otomasi + konsol pengguna:
//! log CLI pasti terbaca oleh redirect file, tanpa menyentuh GUI exe.

fn main() {
    l2split::cli::run_cli();
}
