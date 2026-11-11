//! Usage: `early_probe <dependency-xct|dependency-xcu|bin-xcu>`.
//!
//! Reports what a pre-`main` initializer got from loading `planted-<that name>.dll` by bare name: one in the
//! `early` dependency's `.CRT$XCT` or `.CRT$XCU` section, or one in this bin's own `.CRT$XCU`. Each loads its
//! own file, so that one's load does not satisfy another's. Windows only.
//!
//! Exits 0 and prints `loaded` if it loaded. Otherwise exits 1 and prints `error <GetLastError()>`; exits 2 if
//! the initializer never ran.

#[cfg(windows)]
static BIN_XCU: early::Outcome = early::Outcome::new();

#[cfg(windows)]
unsafe extern "C" fn load_into_bin_xcu() {
    BIN_XCU.load("planted-bin-xcu.dll");
}

#[cfg(windows)]
#[used]
#[link_section = ".CRT$XCU"]
static BIN_XCU_INITIALIZER: unsafe extern "C" fn() = load_into_bin_xcu;

#[cfg(windows)]
fn main() {
    let outcome = match std::env::args().nth(1).as_deref() {
        Some("dependency-xct") => &early::XCT,
        Some("dependency-xcu") => &early::XCU,
        Some("bin-xcu") => &BIN_XCU,
        other => {
            eprintln!("usage: early_probe <dependency-xct|dependency-xcu|bin-xcu>, not {other:?}");
            std::process::exit(2);
        }
    };
    match outcome.get() {
        Some(0) => println!("loaded"),
        Some(error) => {
            println!("error {error}");
            std::process::exit(1);
        }
        None => {
            println!("the initializer did not run");
            std::process::exit(2);
        }
    }
}

#[cfg(not(windows))]
fn main() {}
