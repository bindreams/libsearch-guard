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

/// What `verify` reports for an executable that has none of the Windows hardening.
#[cfg(windows)]
const UNHARDENED: [ViolationKind; 3] = [
    ViolationKind::PeDependentLoadFlags,
    ViolationKind::PeInitializer,
    ViolationKind::PeRuntimeImport,
];

#[test]
fn the_hardened_probe_passes() {
    verify(probe(Probe::Hardened)).unwrap();
}

#[cfg(windows)]
#[test]
fn the_plain_probe_breaks_every_windows_rule() {
    let kinds = violation_kinds(verify(probe(Probe::Plain)).unwrap_err());
    assert_eq!(kinds, UNHARDENED);
}

/// A binary with the load flags and the static runtime but without the initializer claims hardening it lacks:
/// `verify` reports the missing initializer and nothing else.
#[cfg(windows)]
#[test]
fn a_probe_without_the_initializer_is_reported() {
    let kinds = violation_kinds(verify(probe(Probe::HardenedWithoutInitializer)).unwrap_err());
    assert_eq!(kinds, vec![ViolationKind::PeInitializer]);
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
        // A DLL never carries the initializer, so it is not reported for lacking it.
        let expected: Vec<_> = UNHARDENED
            .into_iter()
            .filter(|kind_| kind != "cdylib" || *kind_ != ViolationKind::PeInitializer)
            .collect();
        assert_eq!(kinds, expected, "{target} ({kind}, harness: {harness})");
    }
}

/// A consumer that links the C runtime statically (`+crt-static`) keeps the Universal CRT static too: the
/// bin imports only the system DLLs it needs, none of the `api-ms-win-crt-*` forwarders.
#[cfg(windows)]
#[test]
fn a_hardened_probe_with_a_static_crt_imports_no_universal_crt_dll() {
    use object::read::File;
    use object::Object;

    let path = probe(Probe::HardenedCrtStatic);
    verify(path).unwrap();
    let bytes = std::fs::read(path).unwrap();
    let file = File::parse(&*bytes).unwrap();
    let imports = file.imports().unwrap();
    let mut libraries: Vec<String> = imports
        .map(|i| String::from_utf8_lossy(i.unwrap().library()).to_ascii_lowercase())
        .collect();
    libraries.sort();
    libraries.dedup();
    let crt: Vec<_> = libraries
        .iter()
        .filter(|l| l.starts_with("api-ms-win-crt-") || l.starts_with("ucrtbase"))
        .collect();
    assert!(
        crt.is_empty(),
        "imports the Universal CRT: {crt:?} (all imports: {libraries:?})"
    );
}
