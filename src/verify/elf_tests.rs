use super::crafted::{elf, elf_with_unmapped_strtab, DT_NEEDED, DT_RPATH, DT_RUNPATH};
use super::{verify_bytes, VerifyError, ViolationKind};

fn kinds(image: &[u8]) -> Vec<ViolationKind> {
    match verify_bytes(image) {
        Ok(()) => Vec::new(),
        Err(VerifyError::Violations(v)) => v.into_iter().map(|v| v.kind).collect(),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

#[test]
fn executable_without_a_dynamic_section_passes() {
    assert_eq!(kinds(&elf(&[])), vec![]);
}

#[test]
fn absolute_search_paths_pass() {
    assert_eq!(kinds(&elf(&[(DT_RUNPATH, "/usr/lib:/opt/app/lib")])), vec![]);
    assert_eq!(kinds(&elf(&[(DT_RPATH, "/usr/lib")])), vec![]);
}

#[test]
fn origin_based_paths_are_reported() {
    for path in ["$ORIGIN", "$ORIGIN/../lib", "${ORIGIN}/lib", "/usr/lib:$ORIGIN/lib"] {
        assert_eq!(
            kinds(&elf(&[(DT_RUNPATH, path)])),
            vec![ViolationKind::ElfSearchPath],
            "{path}"
        );
        assert_eq!(
            kinds(&elf(&[(DT_RPATH, path)])),
            vec![ViolationKind::ElfSearchPath],
            "{path}"
        );
    }
}

#[test]
fn relative_paths_are_reported() {
    for path in ["lib", "../lib", "/usr/lib:lib", ":/usr/lib", "/usr/lib:"] {
        assert_eq!(
            kinds(&elf(&[(DT_RUNPATH, path)])),
            vec![ViolationKind::ElfSearchPath],
            "{path:?}"
        );
    }
}

#[test]
fn every_offending_element_is_reported() {
    let image = elf(&[(DT_RPATH, "$ORIGIN:lib"), (DT_RUNPATH, "$ORIGIN")]);
    assert_eq!(kinds(&image), vec![ViolationKind::ElfSearchPath; 3]);
}

/// The crafted images have no section headers at all, as a stripped binary has: the loader reads
/// `PT_DYNAMIC`, so the verifier must too.
#[test]
fn an_image_without_section_headers_is_checked() {
    assert_eq!(
        kinds(&elf(&[(DT_RUNPATH, "$ORIGIN")])),
        vec![ViolationKind::ElfSearchPath]
    );
}

#[test]
fn needed_libraries_named_by_a_relative_path_are_reported() {
    for name in ["lib/libx.so", "./libx.so", "../libx.so"] {
        assert_eq!(
            kinds(&elf(&[(DT_NEEDED, name)])),
            vec![ViolationKind::ElfNeeded],
            "{name}"
        );
    }
}

#[test]
fn needed_libraries_named_bare_or_by_an_absolute_path_pass() {
    assert_eq!(
        kinds(&elf(&[(DT_NEEDED, "libc.so.6"), (DT_NEEDED, "/usr/lib/libx.so")])),
        vec![]
    );
}

#[test]
fn a_string_table_that_no_segment_maps_is_refused_not_passed() {
    assert!(matches!(
        verify_bytes(&elf_with_unmapped_strtab(&[(DT_RUNPATH, "$ORIGIN")])),
        Err(VerifyError::Unreadable(_))
    ));
}
