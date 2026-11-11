use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(test)]
#[path = "bins_tests.rs"]
mod tests;

/// Source of the pre-`main` initializer. Compiled by [`bins`] into the consumer's `OUT_DIR`.
const INITIALIZER: &str = include_str!("../initializer/pre_main.rs");

/// The static-vcruntime link arguments, copied from the `static_vcruntime` crate (3.0.0), which can only emit
/// them for every target, not for bins alone. They link the C startup code and the VC runtime statically
/// and keep the Universal CRT dynamic, so the binary imports no `vcruntime140.dll`.
const REPLACED_RUNTIME_LIBS: [&str; 8] = [
    "libvcruntimed.lib",
    "vcruntime.lib",
    "vcruntimed.lib",
    "libcmtd.lib",
    "msvcrt.lib",
    "msvcrtd.lib",
    "libucrt.lib",
    "libucrtd.lib",
];
const WANTED_RUNTIME_LIBS: [&str; 3] = ["libcmt.lib", "libvcruntime.lib", "ucrt.lib"];

/// Hardens the package's `[[bin]]` targets against DLL planting. Call it from `build.rs`:
///
/// ```no_run
/// libsearch_guard::bins();
/// ```
///
/// On `windows` + `msvc` targets this makes every `[[bin]]` of the package:
///
/// - link the C startup code and the VC runtime statically, so it imports no `vcruntime140.dll`. The Universal
///   CRT stays dynamic, unless the build already links the whole CRT statically (`+crt-static`): then these
///   arguments are skipped and it stays static;
/// - set `/DEPENDENTLOADFLAG:0x800`, so its imports are searched in System32 only;
/// - call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` before `main`, from the `.CRT$XIAB` slot,
///   so a `LoadLibrary` call without flags, including one made inside a system DLL, searches System32 only.
///   The CRT runs that slot before every `.CRT$XC*` initializer (C++ constructors, `ctor`-style crates). If the
///   call fails, the process writes the error to stderr (to the debugger where there is no usable stderr) and
///   terminates before `main`; a fast-fail trap follows the termination, so it never reaches `main` unhardened.
///
/// What runs before that call: TLS callbacks (`.CRT$XL*`), the CRT's own start-up code and its `.CRT$XIAA`
/// initializers, and the loader's resolution of the import table, which `/DEPENDENTLOADFLAG` covers.
///
/// "Every `[[bin]]`" includes each bin's own unit-test and bench harness, which is the bin's code. The
/// package's library, integration tests, examples and `cdylib`s are not affected. On a target that is not
/// Windows, this does nothing. On a Windows target that is not MSVC, or on Cygwin, it fails the build (see
/// Panics).
///
/// `+crt-static` is detected through the target features cargo reports to the build script: `RUSTFLAGS` and
/// the target config set them, but `cargo rustc -- -C target-feature=+crt-static` reaches the final crate
/// only and is not seen. The static-CRT arguments are then emitted and make the Universal CRT dynamic.
///
/// Call it only from a package that has a `[[bin]]`: cargo rejects the link arguments otherwise.
///
/// # Panics
///
/// - If it is not called from a build script.
/// - On a Windows target that is not `*-windows-msvc`, or on Cygwin (whose executables are PE files loaded by
///   the Windows loader): GNU ld has no `DEPENDENTLOADFLAG`, so the bins cannot be hardened, and a bin that
///   silently is not would be worse than a failed build.
/// - If compiling the initializer fails (rustc's error is printed above the panic). A target with no prebuilt
///   `core` (tier 3, `-Zbuild-std`) is not supported.
pub fn bins() {
    match hardens(&var("CARGO_CFG_TARGET_OS"), &var("CARGO_CFG_TARGET_ENV")) {
        Ok(true) => {}
        Ok(false) => return,
        Err(message) => panic!("libsearch-guard: {message}"),
    }
    let object = compile_initializer(&var("TARGET"), Path::new(&var("OUT_DIR")), Path::new(&var("RUSTC")));
    println!("cargo:rustc-link-arg-bins={}", object.display());
    // `+crt-static` already links the whole CRT statically, the Universal CRT included. The arguments below
    // would turn that one back into a dynamic import.
    if !crt_static() {
        for lib in REPLACED_RUNTIME_LIBS {
            println!("cargo:rustc-link-arg-bins=/NODEFAULTLIB:{lib}");
        }
        for lib in WANTED_RUNTIME_LIBS {
            println!("cargo:rustc-link-arg-bins=/DEFAULTLIB:{lib}");
        }
    }
    println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
}

/// Whether `bins()` hardens a target with this `CARGO_CFG_TARGET_OS` and `CARGO_CFG_TARGET_ENV`. An error is
/// a Windows target it cannot harden.
fn hardens(os: &str, env: &str) -> Result<bool, String> {
    match (os, env) {
        ("windows", "msvc") => Ok(true),
        ("windows", _) => Err(format!(
            "only windows-msvc is supported on Windows (this target's env is {env:?}): GNU ld has no DEPENDENTLOADFLAG, so its bins cannot be hardened (see the README, Platform notes)"
        )),
        ("cygwin", _) => Err(
            "cygwin is not supported: its executables are PE files loaded by the Windows loader, and GNU ld has no DEPENDENTLOADFLAG, so its bins cannot be hardened (see the README, Platform notes)"
                .into(),
        ),
        _ => Ok(false),
    }
}

/// Compiles the initializer to an object file with the build's own `rustc`.
///
/// The object is handed to the linker directly, so it is linked into whichever binary gets the argument and
/// into nothing else. The consumer's `RUSTFLAGS` are not passed on: the object needs none of them. That was
/// measured with `-C control-flow-guard`, the one flag that could matter, since the CRT calls the initializer
/// through a function pointer: it runs the same with and without the flag, so nothing needs passing on.
fn compile_initializer(target: &str, out_dir: &Path, rustc: &Path) -> PathBuf {
    let source = out_dir.join("libsearch_guard_pre_main.rs");
    let object = out_dir.join("libsearch_guard_pre_main.obj");
    std::fs::write(&source, INITIALIZER)
        .unwrap_or_else(|e| panic!("libsearch-guard: cannot write {}: {e}", source.display()));
    let status = Command::new(rustc)
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--crate-name",
            "libsearch_guard_pre_main",
        ])
        .args(["--emit=obj", "--target", target])
        .args([
            "-C",
            "panic=abort",
            "-C",
            "opt-level=s",
            "-C",
            "codegen-units=1",
            "-C",
            "debuginfo=0",
        ])
        .arg("-o")
        .arg(&object)
        .arg(&source)
        .status()
        .unwrap_or_else(|e| panic!("libsearch-guard: cannot run {}: {e}", rustc.display()));
    assert!(
        status.success(),
        "libsearch-guard: compiling libsearch-guard's initializer for {target} failed (rustc's error is above). A target with no prebuilt `core` (tier 3, -Zbuild-std) is not supported."
    );
    object
}

/// Whether the build links the C runtime statically (`-C target-feature=+crt-static`).
fn crt_static() -> bool {
    env::var("CARGO_CFG_TARGET_FEATURE")
        .unwrap_or_default()
        .split(',')
        .any(|feature| feature == "crt-static")
}

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("libsearch-guard: {name} is not set; call `bins()` from a build script"))
}
