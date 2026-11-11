//! Builds the fixture packages with a nested cargo, once per variant for the whole test run.
//!
//! The build caches live under `CARGO_TARGET_TMPDIR`, cargo's own scratch space inside `target/`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use serde_json::Value;

const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
const MANIFEST_DIR: &str = env!("CARGO_MANIFEST_DIR");
const WORKSPACE_MANIFEST: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml");

/// How a probe binary was built.
#[derive(Clone, Copy)]
pub enum Probe {
    /// The consumer calls `libsearch_guard::bins()` from its build script.
    Hardened,
    /// The consumer does not.
    Plain,
    /// Built so that the loader searches the executable's folder, whatever the platform's way of asking is
    /// (an `$ORIGIN` RUNPATH on Linux, an `@executable_path` LC_RPATH on macOS). On Windows that is `Plain`.
    #[cfg_attr(
        windows,
        allow(dead_code, reason = "only the unix tests build it; on Windows it is `Plain`")
    )]
    SearchesItsFolder,
}

/// The C runtime a planted DLL links.
#[cfg(windows)]
#[derive(Clone, Copy)]
pub enum Runtime {
    Dynamic,
    Static,
}

/// One artifact cargo reported for a fixture package.
#[derive(Debug)]
pub struct Artifact {
    /// The cargo target's name.
    pub target: String,
    /// The cargo target's kinds: `bin`, `lib`, `rlib`, `cdylib`, `test`, `example`, ...
    pub kinds: Vec<String>,
    /// Whether this is the target's test harness (`profile.test`).
    pub harness: bool,
    /// The executable, or for a `cdylib` the DLL. `None` for an `rlib`.
    pub path: Option<PathBuf>,
}

/// The file of the one artifact with this target name and kind, harness or not.
pub fn file_of<'a>(artifacts: &'a [Artifact], target: &str, kind: &str, harness: bool) -> &'a Path {
    let mut matching = artifacts
        .iter()
        .filter(|a| a.target == target && a.harness == harness && a.kinds.iter().any(|k| k == kind));
    let found = matching.next().unwrap_or_else(|| {
        panic!("cargo reported no {kind} artifact named {target} (harness: {harness}) in {artifacts:#?}")
    });
    assert!(matching.next().is_none(), "two {kind} artifacts named {target}");
    found
        .path
        .as_deref()
        .unwrap_or_else(|| panic!("{target} ({kind}) has no file to inspect"))
}

pub fn probe(kind: Probe) -> &'static Path {
    static HARDENED: OnceLock<PathBuf> = OnceLock::new();
    static PLAIN: OnceLock<PathBuf> = OnceLock::new();
    static SEARCHES: OnceLock<PathBuf> = OnceLock::new();
    match kind {
        Probe::Hardened => {
            HARDENED.get_or_init(|| probe_bin("probe-hardened", &[("LIBSEARCH_GUARD_HARDEN_PROBE", "1")]))
        }
        Probe::Plain => PLAIN.get_or_init(|| probe_bin("probe-plain", &[])),
        Probe::SearchesItsFolder if cfg!(windows) => probe(Probe::Plain),
        Probe::SearchesItsFolder => SEARCHES.get_or_init(|| {
            let origin = if cfg!(target_os = "macos") {
                "@executable_path/lib"
            } else {
                "$ORIGIN/lib"
            };
            let flags = format!("-C link-arg=-Wl,-rpath,{origin}");
            probe_bin("probe-searches", &[("RUSTFLAGS", &flags)])
        }),
    }
}

fn probe_bin(target_dir_name: &str, envs: &[(&str, &str)]) -> PathBuf {
    let artifacts = cargo(&["build"], "probe", target_dir_name, envs);
    file_of(&artifacts, "probe", "bin", false).to_owned()
}

#[cfg(windows)]
pub fn planted(runtime: Runtime) -> &'static Path {
    static DYNAMIC: OnceLock<PathBuf> = OnceLock::new();
    static STATIC: OnceLock<PathBuf> = OnceLock::new();
    let dll = |target_dir_name, envs: &[(&str, &str)]| {
        let artifacts = cargo(&["build"], "planted", target_dir_name, envs);
        file_of(&artifacts, "planted", "cdylib", false).to_owned()
    };
    match runtime {
        Runtime::Dynamic => DYNAMIC.get_or_init(|| dll("planted-dynamic", &[])),
        Runtime::Static => {
            STATIC.get_or_init(|| dll("planted-static", &[("RUSTFLAGS", "-C target-feature=+crt-static")]))
        }
    }
}

/// Every artifact of the hardened probe package: its bin and the bin's test harness, its library (as an
/// `rlib` and a `cdylib`), its integration test and its example.
#[cfg(windows)]
pub fn hardened_probe_artifacts() -> &'static [Artifact] {
    static ALL: OnceLock<Vec<Artifact>> = OnceLock::new();
    ALL.get_or_init(|| {
        cargo(
            &["build", "--all-targets"],
            "probe",
            "probe-hardened",
            &[("LIBSEARCH_GUARD_HARDEN_PROBE", "1")],
        )
    })
}

/// The harness `cargo bench --bins` builds for the hardened probe's bin.
#[cfg(windows)]
pub fn hardened_probe_bench_harness() -> &'static Path {
    static BENCH: OnceLock<PathBuf> = OnceLock::new();
    BENCH.get_or_init(|| {
        let artifacts = cargo(
            &["bench", "--no-run", "--bins"],
            "probe",
            "probe-hardened",
            &[("LIBSEARCH_GUARD_HARDEN_PROBE", "1")],
        );
        file_of(&artifacts, "probe", "bin", true).to_owned()
    })
}

/// Runs `cargo <subcommand>` on a fixture package in its own target directory and returns the package's
/// artifacts from cargo's JSON messages. Panics, with cargo's stderr, when cargo fails.
fn cargo(subcommand: &[&str], package: &str, target_dir_name: &str, envs: &[(&str, &str)]) -> Vec<Artifact> {
    let target_dir = Path::new(TARGET_TMPDIR).join(target_dir_name);
    let package_manifest = canonical(
        &Path::new(MANIFEST_DIR)
            .join("fixtures")
            .join(package)
            .join("Cargo.toml"),
    );
    let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
        .args(subcommand)
        .args([
            "--locked",
            "--message-format=json",
            "--package",
            package,
            "--manifest-path",
        ])
        .arg(WORKSPACE_MANIFEST)
        .arg("--target-dir")
        .arg(&target_dir)
        .envs(envs.iter().copied())
        .output()
        .expect("cannot run cargo");
    assert!(
        output.status.success(),
        "cargo {subcommand:?} on fixture {package} ({target_dir_name}) failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut artifacts = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        let message: Value = serde_json::from_str(line).unwrap_or_else(|e| panic!("cargo printed {line:?}: {e}"));
        if message["reason"] != "compiler-artifact"
            || canonical(Path::new(message["manifest_path"].as_str().unwrap())) != package_manifest
        {
            continue;
        }
        let files = || {
            message["filenames"]
                .as_array()
                .unwrap()
                .iter()
                .filter_map(Value::as_str)
        };
        artifacts.push(Artifact {
            target: message["target"]["name"].as_str().unwrap().to_owned(),
            kinds: message["target"]["kind"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| k.as_str().unwrap().to_owned())
                .collect(),
            harness: message["profile"]["test"].as_bool().unwrap(),
            path: message["executable"]
                .as_str()
                .or_else(|| files().find(|f| f.ends_with(".dll")))
                .map(PathBuf::from),
        });
    }
    artifacts
}

fn canonical(path: &Path) -> PathBuf {
    std::fs::canonicalize(path).unwrap_or_else(|e| panic!("cannot resolve {}: {e}", path.display()))
}
