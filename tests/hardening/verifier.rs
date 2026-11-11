//! `verify` against real binaries on every OS.

use libsearch_guard::{verify, VerifyError, ViolationKind};

#[cfg(windows)]
use crate::fixtures::{file_of, hardened_probe_artifacts, hardened_probe_bench_harness};
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

/// `bins()` hardens each `[[bin]]`, its test and bench harnesses included (a bin's tests are the bin's own
/// code), and nothing else: the package's library and `cdylib`, integration tests and examples link without
/// the initializer, the static runtime or the load flag.
#[cfg(windows)]
#[test]
fn only_the_bins_and_their_own_harnesses_are_hardened() {
    let artifacts = hardened_probe_artifacts();
    for (target, kind, harness) in [("probe", "bin", false), ("probe", "bin", true)] {
        verify(file_of(artifacts, target, kind, harness))
            .unwrap_or_else(|e| panic!("{target} ({kind}, harness: {harness}) is not hardened: {e}"));
    }
    verify(hardened_probe_bench_harness()).unwrap_or_else(|e| panic!("the bin's bench harness is not hardened: {e}"));
    for (target, kind, harness) in [
        ("probe_lib", "lib", true),
        ("probe_lib", "cdylib", false),
        ("scope", "test", true),
        ("sidecar", "example", false),
    ] {
        let kinds = violation_kinds(verify(file_of(artifacts, target, kind, harness)).unwrap_err());
        assert_eq!(
            kinds,
            vec![ViolationKind::PeDependentLoadFlags, ViolationKind::PeRuntimeImport],
            "{target} ({kind}, harness: {harness})"
        );
    }
}
