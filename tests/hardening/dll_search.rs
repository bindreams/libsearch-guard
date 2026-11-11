//! What a probe's DLL loads do when a DLL sits in the probe's own folder. Windows only.

#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use crate::fixtures::{early_probe, planted, probe, Probe, Runtime};

/// `LoadLibrary`'s error for a DLL, or one of its dependencies, that the search did not find.
const ERROR_MOD_NOT_FOUND: u32 = 126;

/// Runs `probe_exe` with `args` from a scratch folder holding a copy of `dll` named `dll_name`, and returns
/// whether the DLL loaded. A load that fails with anything but `ERROR_MOD_NOT_FOUND` is not a refusal and
/// panics. Both folders are removed when this returns, panic or not. The probe's working directory is a
/// different empty folder, so only the executable's folder can explain a load.
fn run(probe_exe: &Path, dll: &Path, dll_name: &str, args: &[&str]) -> bool {
    let app_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();
    let exe = app_dir.path().join("probe.exe");
    std::fs::copy(probe_exe, &exe).unwrap();
    std::fs::copy(dll, app_dir.path().join(dll_name)).unwrap();
    let output = Command::new(&exe)
        .args(args)
        .current_dir(work_dir.path())
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    match output.status.code() {
        Some(0) => true,
        Some(1) => {
            let error = stdout
                .strip_prefix("error ")
                .and_then(|rest| rest.split(|c: char| !c.is_ascii_digit()).next())
                .and_then(|code| code.parse::<u32>().ok());
            assert_eq!(
                error,
                Some(ERROR_MOD_NOT_FOUND),
                "the load failed, but not with ERROR_MOD_NOT_FOUND; probe stdout: {stdout}"
            );
            false
        }
        other => panic!(
            "probe failed unexpectedly ({other:?}): {stdout}{}",
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

/// Runs a probe that loads `planted.dll` as `mode` says.
fn loads(probe_exe: &Path, dll: &Path, mode: &str) -> bool {
    run(probe_exe, dll, "planted.dll", &["planted.dll", mode])
}

/// Runs the early probe's pre-`main` initializer `slot`, which loads `planted-<slot>.dll`. Each initializer has
/// its own file name: a DLL that one of them loaded would satisfy the next one's load by name.
fn early_loads(kind: Probe, slot: &str) -> bool {
    run(
        early_probe(kind),
        planted(Runtime::Static),
        &format!("planted-{slot}.dll"),
        &[slot],
    )
}

#[test]
fn a_plain_probe_loads_a_dll_planted_in_its_folder() {
    assert!(loads(probe(Probe::Plain), planted(Runtime::Static), "flagless"));
}

#[test]
fn a_hardened_probe_refuses_a_dll_planted_in_its_folder() {
    assert!(!loads(probe(Probe::Hardened), planted(Runtime::Static), "flagless"));
}

#[test]
fn a_hardened_probe_with_a_static_crt_refuses_a_dll_planted_in_its_folder() {
    assert!(!loads(
        probe(Probe::HardenedCrtStatic),
        planted(Runtime::Static),
        "flagless"
    ));
}

#[test]
fn a_hardened_probe_still_loads_a_static_runtime_sidecar_from_its_folder_explicitly() {
    assert!(loads(probe(Probe::Hardened), planted(Runtime::Static), "app"));
}

#[test]
fn a_sidecar_that_imports_vcruntime_needs_system32_as_well() {
    let hardened = probe(Probe::Hardened);
    assert!(!loads(hardened, planted(Runtime::Dynamic), "app"));
    assert!(loads(hardened, planted(Runtime::Dynamic), "app_system32"));
}

/// The pre-`main` initializers of the early probe, each of which loads a DLL by bare name: a dependency's, in a
/// section that sorts before `.CRT$XCU`; a dependency's, in the section C++ constructors and `ctor`-style crates
/// use; and the bin's own, whose object file is linked before the guard's.
const EARLY_INITIALIZERS: [&str; 3] = ["dependency-xct", "dependency-xcu", "bin-xcu"];

#[test]
fn a_plain_probe_loads_a_dll_planted_in_its_folder_from_any_pre_main_initializer() {
    for slot in EARLY_INITIALIZERS {
        assert!(early_loads(Probe::Plain, slot), "{slot}");
    }
}

#[test]
fn a_hardened_probe_refuses_a_dll_that_any_pre_main_initializer_loads() {
    for slot in EARLY_INITIALIZERS {
        assert!(!early_loads(Probe::Hardened, slot), "{slot}");
    }
}

#[test]
fn a_hardened_probe_with_a_static_crt_refuses_a_dll_that_any_pre_main_initializer_loads() {
    for slot in EARLY_INITIALIZERS {
        assert!(!early_loads(Probe::HardenedCrtStatic, slot), "{slot}");
    }
}
