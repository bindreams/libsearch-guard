//! What a probe's DLL loads do when a DLL sits in the probe's own folder. Windows only.

#![cfg(windows)]

use std::path::Path;
use std::process::Command;

use crate::fixtures::{planted, probe, Probe, Runtime};

/// Runs `probe_exe` from a scratch folder holding `planted.dll` (a copy of `dll`) and returns whether the DLL
/// loaded. Both folders are removed when this returns, panic or not. The probe's working directory is a
/// different empty folder, so only the executable's folder can explain a load.
fn loads(probe_exe: &Path, dll: &Path, mode: &str) -> bool {
    let app_dir = tempfile::tempdir().unwrap();
    let work_dir = tempfile::tempdir().unwrap();
    let exe = app_dir.path().join("probe.exe");
    std::fs::copy(probe_exe, &exe).unwrap();
    std::fs::copy(dll, app_dir.path().join("planted.dll")).unwrap();
    let output = Command::new(&exe)
        .args(["planted.dll", mode])
        .current_dir(work_dir.path())
        .output()
        .unwrap();
    match output.status.code() {
        Some(0) => true,
        Some(1) => false,
        other => panic!(
            "probe failed unexpectedly ({other:?}): {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    }
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
fn a_hardened_probe_still_loads_a_static_runtime_sidecar_from_its_folder_explicitly() {
    assert!(loads(probe(Probe::Hardened), planted(Runtime::Static), "app"));
}

#[test]
fn a_sidecar_that_imports_vcruntime_needs_system32_as_well() {
    let hardened = probe(Probe::Hardened);
    assert!(!loads(hardened, planted(Runtime::Dynamic), "app"));
    assert!(loads(hardened, planted(Runtime::Dynamic), "app_system32"));
}
