use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

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
/// - link the C startup code and the VC runtime statically, so it imports no `vcruntime140.dll`;
/// - set `/DEPENDENTLOADFLAG:0x800`, so its imports are searched in System32 only;
/// - call `SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32)` before `main`, so a `LoadLibrary` call
///   without flags, including one made inside a system DLL, searches System32 only. If that call fails, the
///   process writes the error to stderr and terminates before `main`.
///
/// Libraries, tests, benches, examples and `cdylib`s of the package are not affected. On every other target
/// this does nothing.
///
/// Call it only from a package that has a `[[bin]]`: cargo rejects the link arguments otherwise.
///
/// # Panics
///
/// If it is not called from a build script, or if compiling the initializer fails.
pub fn bins() {
    if var("CARGO_CFG_TARGET_OS") != "windows" || var("CARGO_CFG_TARGET_ENV") != "msvc" {
        return;
    }
    let object = compile_initializer(&var("TARGET"), Path::new(&var("OUT_DIR")), Path::new(&var("RUSTC")));
    println!("cargo:rustc-link-arg-bins={}", object.display());
    for lib in REPLACED_RUNTIME_LIBS {
        println!("cargo:rustc-link-arg-bins=/NODEFAULTLIB:{lib}");
    }
    for lib in WANTED_RUNTIME_LIBS {
        println!("cargo:rustc-link-arg-bins=/DEFAULTLIB:{lib}");
    }
    println!("cargo:rustc-link-arg-bins=/DEPENDENTLOADFLAG:0x800");
}

/// Compiles the initializer to an object file with the build's own `rustc`.
///
/// The object is handed to the linker directly, so it is linked into whichever binary gets the argument and
/// into nothing else. The consumer's `RUSTFLAGS` are not passed on: the object needs none of them.
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
        "libsearch-guard: compiling the initializer for {target} failed ({status})"
    );
    object
}

fn var(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("libsearch-guard: {name} is not set; call `bins()` from a build script"))
}
