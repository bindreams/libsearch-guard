use super::crafted::{dylib_command, macho, macho_fat, rpath_command, LC_ID_DYLIB, LC_LOAD_DYLIB};
use super::{verify_bytes, VerifyError, ViolationKind};

fn kinds(image: &[u8]) -> Vec<ViolationKind> {
    match verify_bytes(image) {
        Ok(()) => Vec::new(),
        Err(VerifyError::Violations(v)) => v.into_iter().map(|v| v.kind).collect(),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn absolute_dylibs_and_no_rpath_pass() {
    let image = macho(&[dylib_command(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib")]);
    assert_eq!(kinds(&image), vec![]);
}

#[test]
fn any_rpath_is_reported() {
    for path in ["@executable_path/../lib", "/usr/lib"] {
        assert_eq!(
            kinds(&macho(&[rpath_command(path)])),
            vec![ViolationKind::MachoRpath],
            "{path}"
        );
    }
}

#[test]
fn relative_dylib_references_are_reported() {
    for name in [
        "@executable_path/lib/libx.dylib",
        "@loader_path/libx.dylib",
        "@rpath/libx.dylib",
        "libx.dylib",
    ] {
        let image = macho(&[dylib_command(LC_LOAD_DYLIB, name)]);
        assert_eq!(kinds(&image), vec![ViolationKind::MachoDylib], "{name}");
    }
}

#[test]
fn a_dylibs_own_install_name_is_not_a_search() {
    let image = macho(&[dylib_command(LC_ID_DYLIB, "@rpath/libself.dylib")]);
    assert_eq!(kinds(&image), vec![]);
}

#[test]
fn every_violation_is_reported_not_only_the_first() {
    let image = macho(&[
        rpath_command("/x"),
        dylib_command(LC_LOAD_DYLIB, "@rpath/a.dylib"),
        dylib_command(LC_LOAD_DYLIB, "b.dylib"),
    ]);
    assert_eq!(
        kinds(&image),
        vec![
            ViolationKind::MachoRpath,
            ViolationKind::MachoDylib,
            ViolationKind::MachoDylib
        ]
    );
}

#[test]
fn every_slice_of_a_universal_binary_is_checked() {
    let clean = macho(&[dylib_command(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib")]);
    let bad = macho(&[rpath_command("@loader_path")]);
    assert_eq!(kinds(&macho_fat(&[clean.clone(), clean.clone()])), vec![]);
    assert_eq!(kinds(&macho_fat(&[clean, bad])), vec![ViolationKind::MachoRpath]);
}
