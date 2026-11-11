//! Pre-`main` initializers that load a planted DLL by bare name and record how that went, as C++ static
//! constructors and `ctor`-style crates may. Windows only.

#![cfg(windows)]

use std::sync::atomic::{AtomicU32, Ordering};

use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::System::LibraryLoader::LoadLibraryW;

const NOT_RUN: u32 = u32::MAX;

/// What one initializer's `LoadLibraryW` returned.
pub struct Outcome(AtomicU32);

impl Outcome {
    pub const fn new() -> Self {
        Self(AtomicU32::new(NOT_RUN))
    }

    /// Loads the DLL `name` and records the result.
    pub fn load(&self, name: &str) {
        let name: Vec<u16> = name.encode_utf16().chain(Some(0)).collect();
        let module = unsafe { LoadLibraryW(name.as_ptr()) };
        let outcome = if module.is_null() { unsafe { GetLastError() } } else { 0 };
        self.0.store(outcome, Ordering::SeqCst);
    }

    /// `Some(0)` if the DLL loaded, `Some(error)` if not, `None` if the initializer has not run.
    pub fn get(&self) -> Option<u32> {
        match self.0.load(Ordering::SeqCst) {
            NOT_RUN => None,
            outcome => Some(outcome),
        }
    }
}

impl Default for Outcome {
    fn default() -> Self {
        Self::new()
    }
}

/// Set by an initializer in `.CRT$XCT`, which sorts before `.CRT$XCU`.
pub static XCT: Outcome = Outcome::new();
/// Set by an initializer in `.CRT$XCU`, where `ctor`-style crates and C++ constructors put theirs.
pub static XCU: Outcome = Outcome::new();

unsafe extern "C" fn load_into_xct() {
    XCT.load("planted-dependency-xct.dll");
}

unsafe extern "C" fn load_into_xcu() {
    XCU.load("planted-dependency-xcu.dll");
}

#[used]
#[link_section = ".CRT$XCT"]
static XCT_INITIALIZER: unsafe extern "C" fn() = load_into_xct;

#[used]
#[link_section = ".CRT$XCU"]
static XCU_INITIALIZER: unsafe extern "C" fn() = load_into_xcu;
