//! Builds the fixture packages with a nested `cargo build`, once per variant for the whole test run.
//!
//! The build caches live under `CARGO_TARGET_TMPDIR`, cargo's own scratch space inside `target/`.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

const TARGET_TMPDIR: &str = env!("CARGO_TARGET_TMPDIR");
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

pub fn probe(kind: Probe) -> &'static Path {
    static HARDENED: OnceLock<PathBuf> = OnceLock::new();
    static PLAIN: OnceLock<PathBuf> = OnceLock::new();
    static SEARCHES: OnceLock<PathBuf> = OnceLock::new();
    match kind {
        Probe::Hardened => HARDENED.get_or_init(|| {
            build(
                "probe",
                "probe-hardened",
                &[("LIBSEARCH_GUARD_HARDEN_PROBE", "1")],
                exe("probe"),
            )
        }),
        Probe::Plain => PLAIN.get_or_init(|| build("probe", "probe-plain", &[], exe("probe"))),
        Probe::SearchesItsFolder if cfg!(windows) => probe(Probe::Plain),
        Probe::SearchesItsFolder => SEARCHES.get_or_init(|| {
            let origin = if cfg!(target_os = "macos") {
                "@executable_path/lib"
            } else {
                "$ORIGIN/lib"
            };
            let flags = format!("-C link-arg=-Wl,-rpath,{origin}");
            build("probe", "probe-searches", &[("RUSTFLAGS", &flags)], exe("probe"))
        }),
    }
}

#[cfg(windows)]
pub fn planted(runtime: Runtime) -> &'static Path {
    static DYNAMIC: OnceLock<PathBuf> = OnceLock::new();
    static STATIC: OnceLock<PathBuf> = OnceLock::new();
    match runtime {
        Runtime::Dynamic => DYNAMIC.get_or_init(|| build("planted", "planted-dynamic", &[], "planted.dll".into())),
        Runtime::Static => STATIC.get_or_init(|| {
            build(
                "planted",
                "planted-static",
                &[("RUSTFLAGS", "-C target-feature=+crt-static")],
                "planted.dll".into(),
            )
        }),
    }
}

/// The executable of the hardened probe package's integration test target.
#[cfg(windows)]
pub fn hardened_probe_test_target() -> &'static Path {
    static TEST: OnceLock<PathBuf> = OnceLock::new();
    TEST.get_or_init(|| {
        let target_dir = Path::new(TARGET_TMPDIR).join("probe-hardened");
        let output = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()))
            .args([
                "test",
                "--no-run",
                "--locked",
                "--package",
                "probe",
                "--manifest-path",
                WORKSPACE_MANIFEST,
            ])
            .arg("--target-dir")
            .arg(&target_dir)
            .arg("--message-format=json")
            .env("LIBSEARCH_GUARD_HARDEN_PROBE", "1")
            .output()
            .expect("cannot run cargo");
        assert!(
            output.status.success(),
            "building the probe tests failed:
{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // Cargo's JSON lines carry `"executable":"<escaped path>"`. Take the one for the `scope` test target.
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout
            .lines()
            .find(|line| line.contains("\"name\":\"scope\"") && line.contains("\"executable\":\""))
            .expect("cargo reported no executable for the scope test");
        let start = line.find("\"executable\":\"").unwrap() + "\"executable\":\"".len();
        let end = start + line[start..].find('"').unwrap();
        PathBuf::from(line[start..end].replace("\\\\", "\\"))
    })
}

fn exe(name: &str) -> String {
    format!("{name}{}", std::env::consts::EXE_SUFFIX)
}

fn build(package: &str, target_dir_name: &str, envs: &[(&str, &str)], artifact: String) -> PathBuf {
    let target_dir = Path::new(TARGET_TMPDIR).join(target_dir_name);
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let output = Command::new(cargo)
        .args([
            "build",
            "--locked",
            "--package",
            package,
            "--manifest-path",
            WORKSPACE_MANIFEST,
        ])
        .arg("--target-dir")
        .arg(&target_dir)
        .envs(envs.iter().copied())
        .output()
        .expect("cannot run cargo");
    assert!(
        output.status.success(),
        "building fixture {package} ({target_dir_name}) failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = target_dir.join("debug").join(artifact);
    assert!(path.is_file(), "cargo did not produce {}", path.display());
    path
}
