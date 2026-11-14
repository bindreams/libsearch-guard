use std::env;
use std::ffi::OsString;
use std::path::Path;
use std::process::Command;

#[cfg(test)]
#[path = "bins_tests.rs"]
mod tests;

/// The file name of the link argument that fails the link of every `[[bin]]` on a target `bins()` cannot harden.
/// Cargo hides a dependency's `cargo:warning`, so this name is what the reader of a failed build sees. The argument
/// is its absolute path in `OUT_DIR`, so a file of that name in the linker's working directory cannot satisfy it.
const MISSING_INPUT_NAME: &str = "libsearch-guard-cannot-harden-this-target-see-README";

/// Source of the pre-`main` initializer: the code, then the marker `verify` looks for.
const INITIALIZER: &str = concat!(
    include_str!("../initializer/pre_main.rs"),
    include_str!("../initializer/marker.rs")
);

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
/// - the `DllMain` (`DLL_PROCESS_ATTACH`) and TLS callbacks of every DLL the executable imports, which run before the
///   guard, so their flagless `LoadLibrary` calls are not covered by it;
/// - the CRT's own start-up code, and every `.CRT$XI*` initializer that sorts at or before `.CRT$XIAB`: the CRT's
///   `.CRT$XIAA` ones, and any object's `XIAA`, `XIA0` and the like;
/// - the loader's resolution of the executable's import table, which `/DEPENDENTLOADFLAG` covers.
///
/// "Every `[[bin]]`" includes each bin's own unit-test and bench harness, which is the bin's code. The
/// package's library, examples and `cdylib`s are not affected. Integration tests are not hardened on MSVC: the
/// test executable is not a `[[bin]]`.
///
/// On a target that is not Windows, this does nothing. On a Windows target that is not MSVC, or on Cygwin, it
/// hardens nothing and does not panic (see Panics): it prints a `cargo:warning` and fails the link of every
/// `[[bin]]`. The library, and a package that only depends on it, still build; an integration test or `[[bench]]`
/// of a package with a `[[bin]]` fails, since cargo links the bins first.
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
/// - On a Windows or Cygwin target, if `OUT_DIR` is not valid Unicode, or contains a newline: rustc and the
///   linker take only Unicode paths, and a link argument is a `cargo:` line, which a newline would end. It is
///   refused before anything is compiled. This is a limit: use a target directory with a Unicode path and no
///   newline.
/// - If compiling the initializer fails (rustc's error is printed above the panic). A target with no prebuilt
///   `core` (tier 3, `-Zbuild-std`) is not supported.
pub fn bins() {
    let out_dir = var_os("OUT_DIR");
    let initializer = match plan(
        &var("CARGO_CFG_TARGET_OS"),
        &var("CARGO_CFG_TARGET_ENV"),
        Path::new(&out_dir),
    ) {
        Ok(Plan::Harden(initializer)) => initializer,
        Ok(Plan::Skip) => return,
        Ok(Plan::FailBinsLink { warning, missing_input }) => {
            println!("cargo:warning={warning}");
            println!("cargo:rustc-link-arg-bins={missing_input}");
            return;
        }
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

/// Where `bins()` compiles the initializer to. Both paths are text: rustc takes only Unicode arguments, and the
/// object is also the text of a `cargo:rustc-link-arg-bins` line.
#[derive(Debug)]
struct Initializer {
    source: String,
    object: String,
}

/// What `bins()` does for a target.
#[derive(Debug)]
enum Plan {
    /// Compile the initializer and link it, with the other arguments, into every bin.
    Harden(Initializer),
    /// Do nothing.
    Skip,
    /// Print `warning` and fail every bin's link with `missing_input`, a file that never exists: an unhardened bin
    /// that looks hardened is worse than none.
    FailBinsLink { warning: String, missing_input: String },
}

/// What `bins()` does for a target with this `CARGO_CFG_TARGET_OS` and `CARGO_CFG_TARGET_ENV`, building in
/// `out_dir`. An error is an `out_dir` that is not Unicode, or holds a newline, on a Windows or Cygwin target; it
/// is reached before anything is compiled.
fn plan(os: &str, env: &str, out_dir: &Path) -> Result<Plan, String> {
    let out_dir = match os {
        "windows" | "cygwin" => usable_out_dir(out_dir)?,
        // Not Windows: the loader's behaviour is already right, and `verify` checks it.
        _ => return Ok(Plan::Skip),
    };
    Ok(match (os, env) {
        ("windows", "msvc") => Plan::Harden(Initializer {
            source: in_dir(out_dir, "libsearch_guard_pre_main.rs"),
            object: in_dir(out_dir, "libsearch_guard_pre_main.obj"),
        }),
        // Another Windows target, or Cygwin (whose executables are PE files loaded by the Windows loader).
        _ => Plan::FailBinsLink {
            // The cfg values, not a triple: `*-windows-gnullvm` reports `target_env = "gnu"`.
            warning: format!(
                "target_os = {os:?}, target_env = {env:?} cannot be hardened (only windows + msvc is), so the link of every [[bin]] of this package fails rather than building unhardened bins; the library still builds (see the README, Platform notes)"
            ),
            missing_input: in_dir(out_dir, MISSING_INPUT_NAME),
        },
    })
}

/// `out_dir` as text that can go into a `cargo:` line and reach rustc and the linker: valid Unicode, with no
/// newline, which ends a `cargo:` line (cargo splits build-script output on newlines only).
fn usable_out_dir(out_dir: &Path) -> Result<&str, String> {
    match out_dir.to_str() {
        None => Err(format!(
            "{out_dir:?} is not valid Unicode, and the paths handed to rustc and the linker must be; use a target directory with a Unicode path"
        )),
        Some(text) if text.contains('\n') => Err(format!(
            "{out_dir:?} contains a newline, which would end the `cargo:` line that carries it; use a target directory with no newline in its path"
        )),
        Some(text) => Ok(text),
    }
}

/// `name` in the directory `dir`, as text.
fn in_dir(dir: &str, name: &str) -> String {
    Path::new(dir)
        .join(name)
        .to_str()
        .expect("Unicode joined with Unicode")
        .to_owned()
}

/// Compiles the initializer to an object file with the build's own `rustc`.
///
/// The object is handed to the linker directly, so it is linked into whichever binary gets the argument and
/// into nothing else. The consumer's `RUSTFLAGS` are not passed on; the object needs none of them
/// (`-C control-flow-guard` included).
fn compile_initializer(target: &str, rustc: &Path, initializer: &Initializer) {
    std::fs::write(&initializer.source, INITIALIZER)
        .unwrap_or_else(|e| panic!("libsearch-guard: cannot write {}: {e}", initializer.source));
    let status = initializer_command(rustc, target, "obj", &initializer.source, &initializer.object)
        .status()
        .unwrap_or_else(|e| panic!("libsearch-guard: cannot run {}: {e}", rustc.display()));
    assert!(
        status.success(),
        "libsearch-guard: compiling libsearch-guard's initializer for {target} failed (rustc's error is above). A target with no prebuilt `core` (tier 3, -Zbuild-std) is not supported."
    );
}

/// The `rustc` command line that compiles the initializer `source` for `target`, writing `output` in the `emit`
/// form (`obj` for the link; the tests ask for `asm`). Every flag but `--emit` is the same for both.
fn initializer_command(rustc: &Path, target: &str, emit: &str, source: &str, output: &str) -> Command {
    let mut command = Command::new(rustc);
    command
        .args([
            "--edition",
            "2021",
            "--crate-type",
            "lib",
            "--crate-name",
            "libsearch_guard_pre_main",
        ])
        .arg(format!("--emit={emit}"))
        .args(["--target", target])
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
        .args(["-o", output, source]);
    command
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
