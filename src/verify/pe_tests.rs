use super::crafted::{pe, Pe};
use super::{verify_bytes, VerifyError, ViolationKind};

fn kinds(image: &[u8]) -> Vec<ViolationKind> {
    match verify_bytes(image) {
        Ok(()) => Vec::new(),
        Err(VerifyError::Violations(v)) => v.into_iter().map(|v| v.kind).collect(),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

const FULL: u32 = size_of::<object::pe::ImageLoadConfigDirectory64>() as u32;

#[test]
fn hardened_pe_passes() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll", "api-ms-win-crt-runtime-l1-1-0.dll"],
        load_config: Some((0x800, FULL)),
    });
    assert_eq!(kinds(&image), vec![]);
}

#[test]
fn flags_that_include_system32_pass() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        load_config: Some((0x800 | 0x200, FULL)),
    });
    assert_eq!(kinds(&image), vec![]);
}

#[test]
fn flags_without_system32_are_reported() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        load_config: Some((0x400, FULL)),
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

#[test]
fn missing_load_config_is_reported() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        load_config: None,
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

#[test]
fn load_config_too_short_to_hold_the_flags_is_reported() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        load_config: Some((0x800, 0x40)),
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

fn runtime_import_kinds(dll: &str) -> Vec<ViolationKind> {
    kinds(&pe(&Pe {
        imports: &["KERNEL32.dll", dll],
        load_config: Some((0x800, FULL)),
    }))
}

#[test]
fn every_redistributable_runtime_is_reported() {
    for dll in [
        "vcruntime140.dll",
        "vcruntime140_1.dll",
        "vcruntime140d.dll",
        "msvcp140.dll",
        "msvcp140_1.dll",
        "msvcp140d.dll",
        "msvcp120.dll",
        "msvcp210.dll",
        "msvcp60.dll",
        "concrt140.dll",
        "vcomp140.dll",
        "vccorlib140.dll",
        "vcamp140.dll",
        "mfc140.dll",
        "mfc140u.dll",
        "mfcm140.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![ViolationKind::PeRuntimeImport], "{dll}");
    }
}

#[test]
fn older_c_runtimes_are_reported() {
    for dll in [
        "msvcr71.dll",
        "msvcr80.dll",
        "msvcr90.dll",
        "msvcr100.dll",
        "msvcr120d.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![ViolationKind::PeRuntimeImport], "{dll}");
    }
}

#[test]
fn atl_runtimes_are_reported() {
    for dll in ["atl71.dll", "atl80.dll", "atl100.dll", "atl110.dll", "atl140.dll"] {
        assert_eq!(runtime_import_kinds(dll), vec![ViolationKind::PeRuntimeImport], "{dll}");
    }
}

#[test]
fn the_debug_universal_crt_is_reported() {
    assert_eq!(
        runtime_import_kinds("ucrtbased.dll"),
        vec![ViolationKind::PeRuntimeImport]
    );
}

#[test]
fn runtime_imports_are_reported_in_any_case() {
    for dll in [
        "VCRUNTIME140.dll",
        "MSVCP140.dll",
        "Concrt140.DLL",
        "MFC140U.dll",
        "MSVCR100.dll",
        "ATL100.dll",
        "UCRTBASED.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![ViolationKind::PeRuntimeImport], "{dll}");
    }
}

/// `msvcp_win.dll`, `msvcrt.dll` (a KnownDLL) and `atl.dll` are part of Windows; the redistributable
/// `msvcp140.dll`, `msvcr100.dll` and `atl100.dll` are not.
#[test]
fn system_dlls_with_a_runtime_like_name_are_not_reported() {
    for dll in [
        "msvcp_win.dll",
        "MSVCP_WIN.dll",
        "msvcrt.dll",
        "MSVCRT.dll",
        "atl.dll",
        "ucrtbase.dll",
        "ucrtbase.dll",
        "api-ms-win-crt-runtime-l1-1-0.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![], "{dll}");
    }
}

#[test]
fn every_violation_is_reported_not_only_the_first() {
    let image = pe(&Pe {
        imports: &["VCRUNTIME140.dll", "MSVCP140.dll"],
        load_config: None,
    });
    assert_eq!(
        kinds(&image),
        vec![
            ViolationKind::PeDependentLoadFlags,
            ViolationKind::PeRuntimeImport,
            ViolationKind::PeRuntimeImport
        ]
    );
}
