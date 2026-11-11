use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

#[cfg(test)]
#[path = "bins_tests.rs"]
mod tests;

/// Source of the pre-`main` initializer.
const INITIALIZER: &str = include_str!("../initializer/pre_main.rs");

/// The static-vcruntime link arguments: link the C startup code and the VC runtime statically, keep the
/// Universal CRT dynamic, so the binary imports no `vcruntime140.dll`.
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
///   terminates before `main`; a fast-fail trap (x86, x64, ARM64 and ARM64EC; an endless loop on any other
///   architecture) follows the termination, so it never reaches `main` unhardened.
///
/// What runs before that call, so that a `LoadLibrary` call without flags made there is not protected:
///
/// - the executable's TLS callbacks (`.CRT$XL*`), which the loader calls before the CRT starts;
/// - the `DllMain` (`DLL_PROCESS_ATTACH`) and TLS callbacks of every DLL the executable imports. Their own imports
///   follow their own load flags, not the executable's, and their flagless `LoadLibrary` calls are not covered;
/// - the CRT's own start-up code, and every `.CRT$XI*` initializer that sorts at or before `.CRT$XIAB`: the CRT's
///   `.CRT$XIAA` ones, and any object's `XIAA`, `XIA0` and the like;
/// - the loader's resolution of the executable's import table, which `/DEPENDENTLOADFLAG` covers.
///
/// "Every `[[bin]]`" includes each bin's own unit-test and bench harness, which is the bin's code. The
/// package's library, integration tests, examples and `cdylib`s are not affected. On a target that is not
/// Windows, this does nothing. On a Windows target that is not MSVC, or on Cygwin, it fails the build (see
/// Panics).
///
/// `+crt-static` is detected through the target features cargo reports to the build script: `RUSTFLAGS` and
/// the target config set them, but `cargo rustc -- -C target-feature=+crt-static` reaches the final crate
/// only and is not seen.
///
/// Call it only from a package that has a `[[bin]]`: cargo rejects the link arguments otherwise.
///
/// # Panics
///
/// - If it is not called from a build script.
/// - On a Windows target that is not `*-windows-msvc`, or on Cygwin (whose executables are PE files loaded by
///   the Windows loader): GNU ld has no `DEPENDENTLOADFLAG`, so the bins cannot be hardened.
/// - On a target it hardens, if `OUT_DIR` is not valid Unicode: rustc and the linker take only Unicode paths. It
///   is refused before anything is compiled.
/// - If compiling the initializer fails (rustc's error is printed above the panic). A target with no prebuilt
///   `core` (tier 3, `-Zbuild-std`) is not supported.
pub fn bins() {
    let out_dir = var_os("OUT_DIR");
    let initializer = match plan(
        &var("CARGO_CFG_TARGET_OS"),
        &var("CARGO_CFG_TARGET_ENV"),
        Path::new(&out_dir),
    ) {
        Ok(Some(initializer)) => initializer,
        Ok(None) => return,
        Err(message) => panic!("libsearch-guard: {message}"),
    };
    compile_initializer(&var("TARGET"), Path::new(&var_os("RUSTC")), &initializer);
    println!("cargo:rustc-link-arg-bins={}", initializer.object);
    // +crt-static: these arguments would make the Universal CRT dynamic again.
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

/// Where `bins()` compiles the initializer to. Both paths are text: rustc takes only Unicode arguments, and the
/// object is also the text of a `cargo:rustc-link-arg-bins` line.
#[derive(Debug)]
struct Initializer {
    source: String,
    object: String,
}

/// What `bins()` does for a target with this `CARGO_CFG_TARGET_OS` and `CARGO_CFG_TARGET_ENV`, building in
/// `out_dir`: nothing, or compile the initializer. An error is a target it cannot harden, or an `out_dir` that
/// is not Unicode; it is reached before anything is compiled.
fn plan(os: &str, env: &str, out_dir: &Path) -> Result<Option<Initializer>, String> {
    if !hardens(os, env)? {
        return Ok(None);
    }
    let unicode_path = |name: &str| {
        let path = out_dir.join(name);
        path.to_str().map(str::to_owned).ok_or_else(|| {
            format!(
                "{} is not valid Unicode, and the paths handed to rustc and the linker must be; use a target directory with a Unicode path",
                path.display()
            )
        })
    };
    Ok(Some(Initializer {
        source: unicode_path("libsearch_guard_pre_main.rs")?,
        object: unicode_path("libsearch_guard_pre_main.obj")?,
    }))
}

/// Compiles the initializer to an object file with the build's own `rustc`.
///
/// The object is handed to the linker directly, so it is linked into whichever binary gets the argument and
/// into nothing else. The consumer's `RUSTFLAGS` are not passed on; the object needs none of them
/// (`-C control-flow-guard` included).
fn compile_initializer(target: &str, rustc: &Path, initializer: &Initializer) {
    std::fs::write(&initializer.source, INITIALIZER)
        .unwrap_or_else(|e| panic!("libsearch-guard: cannot write {}: {e}", initializer.source));
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
        .arg(&initializer.object)
        .arg(&initializer.source)
        .status()
        .unwrap_or_else(|e| panic!("libsearch-guard: cannot run {}: {e}", rustc.display()));
    assert!(
        status.success(),
        "libsearch-guard: compiling libsearch-guard's initializer for {target} failed (rustc's error is above). A target with no prebuilt `core` (tier 3, -Zbuild-std) is not supported."
    );
}

fn crt_static() -> bool {
    env::var_os("CARGO_CFG_TARGET_FEATURE").is_some_and(|features| {
        features
            .to_string_lossy()
            .split(',')
            .any(|feature| feature == "crt-static")
    })
}

/// A build-script environment variable, which cargo sets whatever its value: a path need not be Unicode.
fn var_os(name: &str) -> OsString {
    env::var_os(name).unwrap_or_else(|| panic!("libsearch-guard: {name} is not set; call `bins()` from a build script"))
}

/// `value`, the value of the variable `name`, as the text that `cargo:` lines and the Windows target names are.
fn unicode(name: &str, value: OsString) -> String {
    value
        .into_string()
        .unwrap_or_else(|value| panic!("libsearch-guard: {name} is not valid Unicode: {value:?}"))
}

fn var(name: &str) -> String {
    unicode(name, var_os(name))
}
