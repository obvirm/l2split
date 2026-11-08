//! l2split — satu exe untuk CLI dan GUI.
//!
//! - Tanpa argumen -> buka GUI (Slint).
//! - Dengan argumen (`list`, `run --app ...`, dll) -> mode CLI di konsol.
// (tanpa jendela hitam di release: GUI mode tanpa argumen tidak membuka konsol;
//  mode CLI masih dapat console induk lewat AttachConsole di bawah)
#![cfg_attr(all(windows, not(debug_assertions)), windows_subsystem = "windows")]

fn main() {
    if std::env::args_os().len() > 1 {
        // Mode CLI pada exe GUI (release = windowed): coba attach konsol induk.
        // Otomasi yang butuh output file yang pasti pakai l2split_cli.exe.
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
