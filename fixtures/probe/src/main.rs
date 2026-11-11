//! Usage: `probe <dll> <flagless|app|app_system32>`.
//!
//! Loads `<dll>` by bare name, the way a program loads a sidecar. Windows only.
//!
//! Exits 0 and prints `loaded` if it loaded. Otherwise exits 1 and prints `error <GetLastError()>`.

#[cfg(windows)]
fn main() {
    use windows_sys::Win32::System::LibraryLoader::{
        LoadLibraryExW, LoadLibraryW, LOAD_LIBRARY_SEARCH_APPLICATION_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    let mut args = std::env::args().skip(1);
    let (Some(dll), Some(mode)) = (args.next(), args.next()) else {
        eprintln!("usage: probe <dll> <flagless|app|app_system32>");
        std::process::exit(2);
    };
    let name: Vec<u16> = dll.encode_utf16().chain(Some(0)).collect();
    let module = unsafe {
        match mode.as_str() {
            "flagless" => LoadLibraryW(name.as_ptr()),
            "app" => LoadLibraryExW(name.as_ptr(), std::ptr::null_mut(), LOAD_LIBRARY_SEARCH_APPLICATION_DIR),
            "app_system32" => LoadLibraryExW(
                name.as_ptr(),
                std::ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            ),
            other => {
                eprintln!("unknown mode {other}");
                std::process::exit(2);
            }
        }
    };
    if module.is_null() {
        let error = std::io::Error::last_os_error();
        println!("error {}: {error}", error.raw_os_error().unwrap_or_default());
        std::process::exit(1);
    }
    println!("loaded");
}

#[cfg(not(windows))]
fn main() {}

#[cfg(test)]
mod tests {
    #[test]
    fn the_bin_has_a_test_harness() {}
}
