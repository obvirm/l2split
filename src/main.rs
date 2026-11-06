//! l2split — satu exe untuk CLI dan GUI.
//!
//! - Tanpa argumen -> buka GUI (Slint).
//! - Dengan argumen (`list`, `run --app ...`, dll) -> mode CLI di konsol.
// (windows_subsystem dinonaktifkan: CLI harus bisa keluar stdout saat dibangun release)

fn main() {
    if std::env::args_os().len() > 1 {
        // Mode CLI: attach ke konsol induk (release build = windowed subsystem).
        #[cfg(not(debug_assertions))]
        unsafe {
            const ATTACH_PARENT_PROCESS: u32 = 0xFFFFFFFF; // (DWORD)-1
            extern "system" {
                fn AttachConsole(dwprocessid: u32) -> i32;
            }
            let _ = AttachConsole(ATTACH_PARENT_PROCESS);
        }
        l2split::cli::run_cli();
        return;
    }
    if let Err(e) = l2split::gui::run() {
        eprintln!("GUI error: {e}");
    }
}
