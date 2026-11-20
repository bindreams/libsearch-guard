//! Prints, in the order they run, every pre-main initializer slot: the C (XI) slots, the C++ (XC) slots and
//! the ones the C++ object adds, each with the result of a flagless LoadLibrary of a DLL planted beside the exe.
use std::ffi::c_void;

extern "system" {
    fn GetStdHandle(std_handle: u32) -> *mut c_void;
    fn WriteFile(file: *mut c_void, buffer: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetLastError() -> u32;
}

fn emit(line: &str) {
    let mut written = 0u32;
    unsafe {
        WriteFile(GetStdHandle(-11i32 as u32), line.as_ptr(), line.len() as u32, &mut written, std::ptr::null_mut());
    }
}

fn load(slot: &str, dll: &str) {
    let name: Vec<u16> = dll.encode_utf16().chain(Some(0)).collect();
    let module = unsafe { LoadLibraryW(name.as_ptr()) };
    let err = if module.is_null() { unsafe { GetLastError() } } else { 0 };
    emit(&format!("{slot} load={} err={err}\n", if module.is_null() { "blocked" } else { "ok" }));
}

macro_rules! c_slot {
    ($section:literal, $name:ident, $dll:literal) => {
        #[used]
        #[link_section = $section]
        static $name: extern "C" fn() -> i32 = {
            extern "C" fn f() -> i32 {
                load($section, $dll);
                0
            }
            f
        };
    };
}
macro_rules! cxx_slot {
    ($section:literal, $name:ident, $dll:literal) => {
        #[used]
        #[link_section = $section]
        static $name: extern "C" fn() = {
            extern "C" fn f() {
                load($section, $dll);
            }
            f
        };
    };
}

// C initializers, in section-name order; the guard sits at XIAB.
c_slot!(".CRT$XIAA", XIAA, "planted-xiaa.dll");
c_slot!(".CRT$XIAC", XIAC, "planted-xiac.dll");
c_slot!(".CRT$XIC", XIC, "planted-xic.dll");
// C++ initializers (what `ctor`-style crates use is XCU).
cxx_slot!(".CRT$XCT", XCT, "planted-xct.dll");
cxx_slot!(".CRT$XCU", XCU, "planted-xcu.dll");

fn main() {
    emit("main\n");
}
