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

#[test]
fn runtime_imports_are_reported_in_any_case() {
    for dll in [
        "VCRUNTIME140.dll",
        "vcruntime140_1.dll",
        "MSVCP140.dll",
        "msvcp140d.dll",
    ] {
        let image = pe(&Pe {
            imports: &["KERNEL32.dll", dll],
            load_config: Some((0x800, FULL)),
        });
        assert_eq!(kinds(&image), vec![ViolationKind::PeRuntimeImport], "{dll}");
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
