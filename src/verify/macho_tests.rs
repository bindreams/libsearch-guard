use super::crafted::{
    dylib_command, dylinker_command, elf, macho, macho_fat, rpath_command, LC_DYLD_ENVIRONMENT, LC_ID_DYLIB,
    LC_LOAD_DYLIB, LC_LOAD_DYLINKER,
};
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

fn dyld_environment(value: &str) -> Vec<ViolationKind> {
    kinds(&macho(&[dylinker_command(LC_DYLD_ENVIRONMENT, value)]))
}

#[test]
fn a_dyld_search_path_that_is_relative_to_the_binary_is_reported() {
    for value in [
        "DYLD_LIBRARY_PATH=@executable_path/../lib",
        "DYLD_FRAMEWORK_PATH=@loader_path/Frameworks",
        "DYLD_FALLBACK_LIBRARY_PATH=@rpath/lib",
        "DYLD_FALLBACK_FRAMEWORK_PATH=Frameworks",
        "DYLD_VERSIONED_LIBRARY_PATH=lib",
    ] {
        assert_eq!(
            dyld_environment(value),
            vec![ViolationKind::MachoDyldEnvironment],
            "{value}"
        );
    }
}

#[test]
fn every_relative_element_of_a_dyld_search_path_is_reported() {
    assert_eq!(
        dyld_environment("DYLD_LIBRARY_PATH=/usr/lib:lib:@loader_path/x"),
        vec![ViolationKind::MachoDyldEnvironment; 2]
    );
}

#[test]
fn absolute_dyld_search_paths_and_other_dyld_variables_pass() {
    for value in [
        "DYLD_LIBRARY_PATH=/usr/local/lib:/opt/lib",
        "DYLD_IMAGE_SUFFIX=_debug",
        "DYLD_PRINT_LIBRARIES=1",
    ] {
        assert_eq!(dyld_environment(value), vec![], "{value}");
    }
}

/// dyld joins an empty element to the leaf name as `/leaf`, a path in the root directory: neither relative to
/// the binary nor to the working directory.
#[test]
fn an_empty_dyld_search_path_or_element_is_not_reported() {
    for value in [
        "DYLD_LIBRARY_PATH=",
        "DYLD_LIBRARY_PATH=/usr/lib:",
        "DYLD_FALLBACK_LIBRARY_PATH=:/usr/lib",
        "DYLD_FRAMEWORK_PATH=/usr/lib::/opt/lib",
    ] {
        assert_eq!(dyld_environment(value), vec![], "{value}");
    }
}

#[test]
fn the_dynamic_linker_load_command_is_not_an_environment() {
    let image = macho(&[dylinker_command(LC_LOAD_DYLINKER, "/usr/lib/dyld")]);
    assert_eq!(kinds(&image), vec![]);
}

/// Only a Mach-O image is a slice of a universal binary. Anything else, a universal binary included, would
/// otherwise be checked as if dyld could load it, or recurse without a bound.
#[test]
fn a_slice_that_is_not_a_macho_image_is_unreadable() {
    let clean = macho(&[dylib_command(LC_LOAD_DYLIB, "/usr/lib/libSystem.B.dylib")]);
    for (what, slice) in [
        ("a nested universal binary", macho_fat(std::slice::from_ref(&clean))),
        ("an ELF image", elf(&[])),
        ("text", b"not an image".to_vec()),
    ] {
        let result = verify_bytes(&macho_fat(&[clean.clone(), slice]));
        assert!(matches!(result, Err(VerifyError::Unreadable(_))), "{what}: {result:?}");
    }
}

/// A universal header whose one slice is the whole file, itself.
#[test]
fn a_universal_binary_that_contains_itself_is_unreadable() {
    let mut image = Vec::new();
    image.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    image.extend_from_slice(&1u32.to_be_bytes());
    image.extend_from_slice(&0x0100_000cu32.to_be_bytes()); // cputype
    image.extend_from_slice(&0u32.to_be_bytes()); // cpusubtype
    image.extend_from_slice(&0u32.to_be_bytes()); // offset
    image.extend_from_slice(&28u32.to_be_bytes()); // size: the whole file
    image.extend_from_slice(&0u32.to_be_bytes()); // align
    let result = verify_bytes(&image);
    assert!(matches!(result, Err(VerifyError::Unreadable(_))), "{result:?}");
}

/// What an earlier slice broke is not lost when a later slice cannot be read.
#[test]
fn violations_found_before_an_unreadable_slice_are_in_the_error() {
    let bad = macho(&[rpath_command("@executable_path/lib")]);
    let Err(VerifyError::Unreadable(why)) = verify_bytes(&macho_fat(&[bad, b"not an image".to_vec()])) else {
        panic!("expected an unreadable file");
    };
    assert!(
        why.contains("MachoRpath") && why.contains("@executable_path/lib"),
        "{why}"
    );
}
