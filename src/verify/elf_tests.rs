use super::crafted::{
    elf, elf_image, elf_with_interpreter, elf_with_unmapped_strtab, not_utf8, Elf, StringTable, DT_AUDIT, DT_AUXILIARY,
    DT_DEPAUDIT, DT_FILTER, DT_NEEDED, DT_RPATH, DT_RUNPATH,
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
fn a_relative_interpreter_is_reported() {
    for name in ["ld.so", "lib/ld.so", "./ld.so", "$ORIGIN/ld.so", ""] {
        assert_eq!(
            kinds(&elf_with_interpreter(&[(DT_NEEDED, "libc.so.6")], name)),
            vec![ViolationKind::ElfInterpreter],
            "{name:?}"
        );
    }
}

#[test]
fn a_relative_interpreter_is_reported_without_a_dynamic_section() {
    assert_eq!(
        kinds(&elf_with_interpreter(&[], "lib/ld.so")),
        vec![ViolationKind::ElfInterpreter]
    );
}

#[test]
fn an_absolute_interpreter_passes() {
    assert_eq!(
        kinds(&elf_with_interpreter(
            &[(DT_NEEDED, "libc.so.6")],
            "/lib64/ld-linux-x86-64.so.2"
        )),
        vec![]
    );
}

#[test]
fn a_string_table_that_no_segment_maps_is_refused_not_passed() {
    assert!(matches!(
        verify_bytes(&elf_with_unmapped_strtab(&[(DT_RUNPATH, "$ORIGIN")])),
        Err(VerifyError::Unreadable { .. })
    ));
}

/// The loader maps these libraries too: audit libraries (`DT_AUDIT`, `DT_DEPAUDIT`) and filtees (`DT_FILTER`,
/// `DT_AUXILIARY`). Each holds a `:`-separated list, and an element with a `/` is opened as a path.
const LOADER_TAGS: [(u64, &str); 4] = [
    (DT_AUDIT, "DT_AUDIT"),
    (DT_DEPAUDIT, "DT_DEPAUDIT"),
    (DT_FILTER, "DT_FILTER"),
    (DT_AUXILIARY, "DT_AUXILIARY"),
];

#[test]
fn loader_libraries_named_by_a_relative_or_origin_based_path_are_reported() {
    for (tag, name) in LOADER_TAGS {
        for value in [
            "lib/libx.so",
            "./libx.so",
            "$ORIGIN/libx.so",
            "${ORIGIN}/libx.so",
            "$ORIGIN",
            "/usr/lib/liby.so:lib/libx.so",
        ] {
            assert_eq!(
                kinds(&elf(&[(tag, value)])),
                vec![ViolationKind::ElfLoaderLibrary],
                "{name} {value}"
            );
        }
    }
}

#[test]
fn every_offending_loader_library_element_is_reported() {
    assert_eq!(
        kinds(&elf(&[(DT_AUDIT, "$ORIGIN/a.so:lib/b.so:/usr/lib/c.so")])),
        vec![ViolationKind::ElfLoaderLibrary; 2]
    );
}

#[test]
fn loader_libraries_named_bare_or_by_an_absolute_path_pass() {
    for (tag, name) in LOADER_TAGS {
        assert_eq!(
            kinds(&elf(&[(tag, "libaudit.so:/usr/lib/libx.so"), (tag, "")])),
            vec![],
            "{name}"
        );
    }
}

/// Every combination of word size and byte order the loader reads.
const FORMATS: [(bool, bool); 4] = [(false, false), (true, false), (false, true), (true, true)];

#[test]
fn every_word_size_and_byte_order_is_checked() {
    for (is_32_bit, is_big_endian) in FORMATS {
        let image = |entries| {
            elf_image(&Elf {
                entries,
                interpreter: Some("/lib/ld.so"),
                is_32_bit,
                is_big_endian,
                ..Elf::default()
            })
        };
        let bad = [
            (DT_RUNPATH, "$ORIGIN/lib"),
            (DT_NEEDED, "lib/libx.so"),
            (DT_AUDIT, "lib/a.so"),
        ];
        assert_eq!(
            kinds(&image(&bad)),
            vec![
                ViolationKind::ElfSearchPath,
                ViolationKind::ElfNeeded,
                ViolationKind::ElfLoaderLibrary
            ],
            "32 bit: {is_32_bit}, big endian: {is_big_endian}"
        );
        assert_eq!(
            kinds(&image(&[(DT_RUNPATH, "/usr/lib"), (DT_NEEDED, "libc.so.6")])),
            vec![],
            "32 bit: {is_32_bit}, big endian: {is_big_endian}"
        );
    }
}

#[test]
fn a_relative_interpreter_is_reported_in_every_format() {
    for (is_32_bit, is_big_endian) in FORMATS {
        let image = elf_image(&Elf {
            entries: &[(DT_NEEDED, "libc.so.6")],
            interpreter: Some("ld.so"),
            is_32_bit,
            is_big_endian,
            ..Elf::default()
        });
        assert_eq!(kinds(&image), vec![ViolationKind::ElfInterpreter]);
    }
}

/// The loader stops at `DT_NULL`, so an entry after it is not a search.
#[test]
fn entries_after_the_terminating_null_are_not_read() {
    let image = elf_image(&Elf {
        entries: &[(DT_RUNPATH, "/usr/lib")],
        after_null: &[(DT_RUNPATH, "$ORIGIN"), (DT_NEEDED, "lib/libx.so")],
        ..Elf::default()
    });
    assert_eq!(kinds(&image), vec![]);
}

/// `DT_STRTAB` is an address; the segment that maps it need not be the first.
#[test]
fn a_string_table_in_a_later_load_segment_is_read() {
    let image = elf_image(&Elf {
        entries: &[(DT_RUNPATH, "$ORIGIN")],
        string_table: StringTable::SecondSegment,
        ..Elf::default()
    });
    assert_eq!(kinds(&image), vec![ViolationKind::ElfSearchPath]);
}

/// A name the loader would read as bytes, and this crate cannot read as text, is a file it cannot check: not a pass.
#[test]
fn a_string_that_is_not_utf8_is_unreadable() {
    let tags = [
        (DT_RPATH, "DT_RPATH"),
        (DT_RUNPATH, "DT_RUNPATH"),
        (DT_NEEDED, "DT_NEEDED"),
        (DT_AUDIT, "DT_AUDIT"),
        (DT_DEPAUDIT, "DT_DEPAUDIT"),
        (DT_FILTER, "DT_FILTER"),
        (DT_AUXILIARY, "DT_AUXILIARY"),
    ];
    for (tag, name) in tags {
        let image = not_utf8(elf(&[(tag, "/usr/lib/zzmarker")]), "zzmarker");
        let result = verify_bytes(&image);
        assert!(
            matches!(result, Err(VerifyError::Unreadable { .. })),
            "{name}: {result:?}"
        );
    }
}

#[test]
fn an_interpreter_that_is_not_utf8_is_unreadable() {
    let image = not_utf8(elf_with_interpreter(&[], "/lib/zzmarker"), "zzmarker");
    let result = verify_bytes(&image);
    assert!(matches!(result, Err(VerifyError::Unreadable { .. })), "{result:?}");
}

/// What was found before the string that cannot be read is kept.
#[test]
fn violations_found_before_a_string_that_is_not_utf8_are_kept() {
    let image = not_utf8(
        elf(&[(DT_RUNPATH, "$ORIGIN"), (DT_NEEDED, "/usr/lib/zzmarker")]),
        "zzmarker",
    );
    let Err(VerifyError::Unreadable { found, .. }) = verify_bytes(&image) else {
        panic!("expected an unreadable file");
    };
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, ViolationKind::ElfSearchPath);
}
