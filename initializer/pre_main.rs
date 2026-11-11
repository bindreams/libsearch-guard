//! libsearch-guard pre-main initializer (spike A).
#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_void;

extern "system" {
    fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
    fn GetLastError() -> u32;
    fn GetStdHandle(std_handle: u32) -> *mut c_void;
    fn WriteFile(file: *mut c_void, buffer: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn GetCurrentProcess() -> *mut c_void;
    fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
}

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const STATUS_FAIL_FAST_EXCEPTION: u32 = 0xC000_0409;

unsafe fn write_stderr(bytes: &[u8]) {
    let mut written = 0u32;
    WriteFile(GetStdHandle(STD_ERROR_HANDLE), bytes.as_ptr(), bytes.len() as u32, &mut written, core::ptr::null_mut());
}

unsafe extern "C" fn initialize() -> i32 {
    if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 {
        return 0;
    }
    let code = GetLastError();
    let mut hex = *b"00000000\r\n";
    let mut i = 0;
    while i < 8 {
        let digit = ((code >> (28 - 4 * i)) & 0xF) as u8;
        hex[i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        i += 1;
    }
    write_stderr(b"libsearch-guard: SetDefaultDllDirectories failed, error 0x");
    write_stderr(&hex);
    TerminateProcess(GetCurrentProcess(), STATUS_FAIL_FAST_EXCEPTION);
    1
}

// `.CRT$XIAB` is a C initializer slot (`int (*)(void)`): the CRT runs the `.CRT$XI*` entries, in section-name
// order, before every `.CRT$XC*` entry, which is where C++ constructors and `ctor`-style crates register.
#[used]
#[link_section = ".CRT$XIAB"]
static INITIALIZER: unsafe extern "C" fn() -> i32 = initialize;
