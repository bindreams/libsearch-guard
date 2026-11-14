//! Pre-`main` initializer: restricts the default DLL search to System32, or terminates the process.
#![no_std]
#![allow(non_snake_case)]

use core::ffi::c_void;

extern "system" {
    fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
    fn GetLastError() -> u32;
    fn GetStdHandle(std_handle: u32) -> *mut c_void;
    fn WriteFile(file: *mut c_void, buffer: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn OutputDebugStringA(message: *const u8);
    fn GetCurrentProcess() -> *mut c_void;
    fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
}

const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;
const INVALID_HANDLE_VALUE: isize = -1;
const STATUS_FAIL_FAST_EXCEPTION: u32 = 0xC000_0409;
const FAST_FAIL_FATAL_APP_EXIT: u32 = 7;

/// Writes the NUL-terminated `message` to stderr, or to the debugger where stderr is unusable (closed,
/// redirected nowhere, or a GUI-subsystem process). Best effort: if both fail the process still terminates,
/// and there is nowhere left to say why.
unsafe fn report(message: &[u8]) {
    let stderr = GetStdHandle(STD_ERROR_HANDLE);
    let mut written = 0u32;
    let wrote = !stderr.is_null()
        && stderr as isize != INVALID_HANDLE_VALUE
        && WriteFile(
            stderr,
            message.as_ptr(),
            (message.len() - 1) as u32,
            &mut written,
            core::ptr::null_mut(),
        ) != 0;
    if !wrote {
        OutputDebugStringA(message.as_ptr());
    }
}

/// Ends the process without returning, whatever `TerminateProcess` did: a fast-fail trap (`__fastfail`), which the
/// OS handles itself and no exception handler can intercept. It is written for x86, x64, ARM64 and ARM64EC; an
/// endless loop stands in on any other architecture.
unsafe fn fail_fast() -> ! {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        core::arch::asm!("int 0x29", in("ecx") FAST_FAIL_FATAL_APP_EXIT, options(noreturn, nostack));
    }
    #[cfg(any(target_arch = "aarch64", target_arch = "arm64ec"))]
    {
        core::arch::asm!("brk #0xF003", in("x0") FAST_FAIL_FATAL_APP_EXIT, options(noreturn, nostack));
    }
    #[cfg(not(any(
        target_arch = "x86",
        target_arch = "x86_64",
        target_arch = "aarch64",
        target_arch = "arm64ec"
    )))]
    {
        let _ = FAST_FAIL_FATAL_APP_EXIT;
        loop {}
    }
}

unsafe extern "C" fn initialize() -> i32 {
    if SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) != 0 {
        return 0;
    }
    let code = GetLastError();
    let mut message = *b"libsearch-guard: SetDefaultDllDirectories failed, error 0x00000000\r\n\0";
    let digits_at = message.len() - 11;
    let mut i = 0;
    while i < 8 {
        let digit = ((code >> (28 - 4 * i)) & 0xF) as u8;
        message[digits_at + i] = if digit < 10 { b'0' + digit } else { b'a' + digit - 10 };
        i += 1;
    }
    report(&message);
    TerminateProcess(GetCurrentProcess(), STATUS_FAIL_FAST_EXCEPTION);
    // `TerminateProcess` does not return on success. If it failed, `main` would run unhardened.
    fail_fast()
}

// `.CRT$XIAB` is a C initializer slot (`int (*)(void)`): the CRT runs the `.CRT$XI*` entries, in section-name
// order, before every `.CRT$XC*` entry, which is where C++ constructors and `ctor`-style crates register.
#[used]
#[link_section = ".CRT$XIAB"]
static INITIALIZER: unsafe extern "C" fn() -> i32 = initialize;

/// The section `verify` looks for in an executable to know that this object was linked: it is defined in the same
/// object as the `.CRT$XIAB` entry, and `#[used]` keeps it through `/OPT:REF` and `/OPT:ICF`, so the image has a
/// section of this name exactly when the initializer was linked. Nothing refers to it. The name is the whole 8-byte
/// field of a PE section header.
///
/// The cost is a section header, one `FileAlignment` block on disk and one page of address space per hardened
/// executable; it buys a check that reads only the section table.
#[used]
#[link_section = ".lsguard"]
static LINKED: [u8; 1] = [1];
