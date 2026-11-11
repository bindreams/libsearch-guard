//! `verify` against real binaries on every OS.

use libsearch_guard::{verify, VerifyError, ViolationKind};

#[cfg(windows)]
use crate::fixtures::{file_of, hardened_probe_artifacts};
use crate::fixtures::{probe, Probe};

fn violation_kinds(error: VerifyError) -> Vec<ViolationKind> {
    match error {
        VerifyError::Violations(violations) => violations.into_iter().map(|v| v.kind).collect(),
        other => panic!("expected violations, got: {other}"),
    }
}

#[test]
fn the_hardened_probe_passes() {
    verify(probe(Probe::Hardened)).unwrap();
}

#[cfg(windows)]
#[test]
fn the_plain_probe_breaks_both_windows_rules() {
    let kinds = violation_kinds(verify(probe(Probe::Plain)).unwrap_err());
    assert_eq!(
        kinds,
        vec![ViolationKind::PeDependentLoadFlags, ViolationKind::PeRuntimeImport]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_probe_with_an_origin_runpath_is_reported() {
    let kinds = violation_kinds(verify(probe(Probe::SearchesItsFolder)).unwrap_err());
    assert_eq!(kinds, vec![ViolationKind::ElfSearchPath]);
}

#[cfg(target_os = "macos")]
#[test]
fn a_probe_with_an_executable_path_rpath_is_reported() {
    let kinds = violation_kinds(verify(probe(Probe::SearchesItsFolder)).unwrap_err());
    assert_eq!(kinds, vec![ViolationKind::MachoRpath]);
}

/// `bins()` hardens the package's bins and nothing else: its test target links without the initializer,
/// the static runtime or the load flag.
#[cfg(windows)]
#[test]
fn a_test_target_of_a_hardened_package_is_not_hardened() {
    let kinds = violation_kinds(verify(file_of(hardened_probe_artifacts(), "scope", "test", true)).unwrap_err());
    assert_eq!(
        kinds,
        vec![ViolationKind::PeDependentLoadFlags, ViolationKind::PeRuntimeImport]
    );
}
