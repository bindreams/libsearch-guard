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
        delay_imports: &[],
        load_config: Some((0x800, FULL)),
    });
    assert_eq!(kinds(&image), vec![]);
}

#[test]
fn flags_that_include_system32_pass() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        delay_imports: &[],
        load_config: Some((0x800 | 0x200, FULL)),
    });
    assert_eq!(kinds(&image), vec![]);
}

#[test]
fn flags_without_system32_are_reported() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        delay_imports: &[],
        load_config: Some((0x400, FULL)),
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

#[test]
fn missing_load_config_is_reported() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        delay_imports: &[],
        load_config: None,
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

#[test]
fn load_config_too_short_to_hold_the_flags_is_reported() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
        delay_imports: &[],
        load_config: Some((0x800, 0x40)),
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

fn runtime_import_kinds(dll: &str) -> Vec<ViolationKind> {
    kinds(&pe(&Pe {
        imports: &["KERNEL32.dll", dll],
        delay_imports: &[],
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

fn delay_load_kinds(imports: &[&str], delay_imports: &[&str]) -> Vec<ViolationKind> {
    kinds(&pe(&Pe {
        imports,
        delay_imports,
        load_config: Some((0x800, FULL)),
    }))
}

/// A delay-loaded DLL is loaded by `LoadLibrary` at the first call, searched for like any other.
#[test]
fn a_delay_loaded_redistributable_is_reported() {
    for dll in ["msvcp140.dll", "VCRUNTIME140.dll", "atl100.dll"] {
        assert_eq!(
            delay_load_kinds(&["KERNEL32.dll"], &["KERNEL32.dll", dll]),
            vec![ViolationKind::PeRuntimeImport],
            "{dll}"
        );
    }
}

#[test]
fn delay_loaded_system_dlls_pass() {
    assert_eq!(
        delay_load_kinds(&["KERNEL32.dll"], &["msvcp_win.dll", "ole32.dll"]),
        vec![]
    );
}

#[test]
fn a_redistributable_is_reported_once_per_table_that_imports_it() {
    assert_eq!(
        delay_load_kinds(&["msvcp140.dll"], &["msvcp140.dll"]),
        vec![ViolationKind::PeRuntimeImport; 2]
    );
}

#[test]
fn every_violation_is_reported_not_only_the_first() {
    let image = pe(&Pe {
        imports: &["VCRUNTIME140.dll", "MSVCP140.dll"],
        delay_imports: &[],
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
