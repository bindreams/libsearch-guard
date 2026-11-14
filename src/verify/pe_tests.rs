use super::crafted::{pe, pe32, pe_variant, Bits, BrokenName, Pe, Variant};
use super::{verify_bytes, VerifyError, ViolationKind};

fn kinds(image: &[u8]) -> Vec<ViolationKind> {
    match verify_bytes(image) {
        Ok(()) => Vec::new(),
        Err(VerifyError::Violations(v)) => v.into_iter().map(|v| v.kind).collect(),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

const KERNEL32: &str = "KERNEL32.dll";

const FULL: u32 = size_of::<object::pe::ImageLoadConfigDirectory64>() as u32;

#[test]
fn hardened_pe_passes() {
    let image = pe(&Pe {
        imports: &[KERNEL32, "api-ms-win-crt-runtime-l1-1-0.dll"],
        delay_imports: &[],
        load_config: Some((0x800, FULL)),
    });
    assert_eq!(kinds(&image), vec![]);
}

/// `LOAD_LIBRARY_SEARCH_USER_DIRS` (0x400) adds the directories a process registered with `AddDllDirectory`;
/// at load time there are none, so an import is still searched for in System32 only (measured).
#[test]
fn flags_that_add_the_user_dirs_to_system32_pass() {
    let image = pe(&Pe {
        imports: &[KERNEL32],
        delay_imports: &[],
        load_config: Some((0x800 | 0x400, FULL)),
    });
    assert_eq!(kinds(&image), vec![]);
}

/// 0x100 is `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR`, 0x200 is `LOAD_LIBRARY_SEARCH_APPLICATION_DIR` and 0x1000 is
/// `LOAD_LIBRARY_SEARCH_DEFAULT_DIRS`, which includes the application directory. Each one, next to 0x800, makes
/// the loader search the executable's folder for its imports (measured).
#[test]
fn flags_that_search_the_executables_folder_are_reported_even_with_system32() {
    for flags in [
        0x800 | 0x100,
        0x800 | 0x200,
        0x800 | 0x1000,
        0x800 | 0x100 | 0x200 | 0x1000,
    ] {
        let image = pe(&Pe {
            imports: &[KERNEL32],
            delay_imports: &[],
            load_config: Some((flags, FULL)),
        });
        assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags], "{flags:#x}");
    }
}

/// Only 0x800 and 0x400 are allowed: a bit the loader does not document for `DependentLoadFlags`, or one that
/// changes how the DLL is loaded, is reported with the bit named.
#[test]
fn a_flag_bit_outside_the_allowlist_is_reported_and_named() {
    for (flags, bit) in [
        (0x808u16, "0x8"),
        (0x2800, "0x2000"),
        (0x900, "0x100"),
        (0x801, "0x1"),
        (0x8800, "0x8000"),
    ] {
        let image = pe(&Pe {
            imports: &[KERNEL32],
            delay_imports: &[],
            load_config: Some((flags, FULL)),
        });
        let Err(VerifyError::Violations(violations)) = verify_bytes(&image) else {
            panic!("{flags:#x} passed");
        };
        assert_eq!(violations.len(), 1, "{flags:#x}: {violations:?}");
        assert_eq!(violations[0].kind, ViolationKind::PeDependentLoadFlags);
        assert!(
            violations[0].detail.contains(&format!("bit {bit}")),
            "{flags:#x}: {}",
            violations[0].detail
        );
    }
}

#[test]
fn system32_with_the_user_dirs_is_the_only_extra_that_passes() {
    for flags in [0x800, 0xC00] {
        let image = pe(&Pe {
            imports: &[KERNEL32],
            delay_imports: &[],
            load_config: Some((flags, FULL)),
        });
        assert_eq!(kinds(&image), vec![], "{flags:#x}");
    }
}

#[test]
fn flags_without_system32_are_reported() {
    let image = pe(&Pe {
        imports: &[KERNEL32],
        delay_imports: &[],
        load_config: Some((0x400, FULL)),
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

#[test]
fn missing_load_config_is_reported() {
    let image = pe(&Pe {
        imports: &[KERNEL32],
        delay_imports: &[],
        load_config: None,
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

#[test]
fn load_config_too_short_to_hold_the_flags_is_reported() {
    let image = pe(&Pe {
        imports: &[KERNEL32],
        delay_imports: &[],
        load_config: Some((0x800, 0x40)),
    });
    assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags]);
}

fn runtime_import_kinds(dll: &str) -> Vec<ViolationKind> {
    kinds(&pe(&Pe {
        imports: &[KERNEL32, dll],
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
        "vcruntime140_1d.dll",
        "vcruntime140_threads.dll",
        "vcruntime140_threads_app.dll",
        "msvcp140.dll",
        "msvcp140_1.dll",
        "msvcp140_2d.dll",
        "msvcp140d.dll",
        "msvcp140_atomic_wait.dll",
        "msvcp140d_codecvt_ids.dll",
        "msvcp120.dll",
        "msvcp210.dll",
        "concrt140.dll",
        "vcomp140.dll",
        "vccorlib140.dll",
        "vcamp140.dll",
        "mfc140.dll",
        "mfc140u.dll",
        "mfc140ud.dll",
        "mfc140deu.dll",
        "mfcm140.dll",
        "mfcm140ud.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![ViolationKind::PeRuntimeImport], "{dll}");
    }
}

/// The UWP (VCLibs) copies of the runtimes carry an `_app` suffix.
#[test]
fn the_uwp_runtimes_are_reported() {
    for dll in [
        "vcruntime140_app.dll",
        "vcruntime140_1_app.dll",
        "vcruntime140d_app.dll",
        "msvcp140_app.dll",
        "msvcp140d_app.dll",
        "msvcp140_atomic_wait_app.dll",
        "msvcp140_codecvt_ids_app.dll",
        "msvcp140d_atomic_wait_app.dll",
        "msvcp140d_codecvt_ids_app.dll",
        "vccorlib140_app.dll",
        "vccorlib140d_app.dll",
        "concrt140_app.dll",
        "vcomp140_app.dll",
        "vcamp140_app.dll",
        "VCRUNTIME140_APP.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![ViolationKind::PeRuntimeImport], "{dll}");
    }
}

/// `_app` is a suffix of the families that have a UWP copy, and nothing else.
#[test]
fn an_app_suffix_on_a_windows_dll_or_an_unknown_variant_is_not_reported() {
    for dll in [
        "msvcp_win_app.dll",
        "msvcr100_app.dll",
        "mfc140_app.dll",
        "vcruntime140_apps.dll",
        "vcruntime140__app.dll",
        "vcruntime140_atomic_wait_app.dll",
        "msvcp140_atomic_wait_apps.dll",
        "msvcp140_atomic_wait__app.dll",
    ] {
        assert_eq!(runtime_import_kinds(dll), vec![], "{dll}");
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

/// What ships in Windows, and so is not a redistributable, although its name starts like one. Each name was
/// checked in `System32` or `SysWOW64`.
#[test]
fn windows_dlls_with_a_runtime_like_name_are_not_reported() {
    for dll in [
        "msvcp_win.dll",
        "MSVCP_WIN.dll",
        "msvcp110_win.dll",
        "msvcp60.dll",
        "msvcp140_clr0400.dll",
        "msvcrt.dll",
        "MSVCRT.dll",
        "msvcrt20.dll",
        "msvcr120_clr0400.dll",
        "vcruntime140_clr0400.dll",
        "mfcore.dll",
        "mfcsubs.dll",
        "mfc40.dll",
        "mfc42.dll",
        "mfc42u.dll",
        "atl.dll",
        "atlthunk.dll",
        "ucrtbase.dll",
        "ucrtbase_clr0400.dll",
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
            delay_load_kinds(&[KERNEL32], &[KERNEL32, dll]),
            vec![ViolationKind::PeRuntimeImport],
            "{dll}"
        );
    }
}

#[test]
fn delay_loaded_system_dlls_pass() {
    assert_eq!(delay_load_kinds(&[KERNEL32], &["msvcp_win.dll", "ole32.dll"]), vec![]);
}

#[test]
fn a_redistributable_is_reported_once_per_table_that_imports_it() {
    assert_eq!(
        delay_load_kinds(&[KERNEL32, "msvcp140.dll"], &["msvcp140.dll"]),
        vec![ViolationKind::PeRuntimeImport; 2]
    );
}

#[test]
fn every_violation_is_reported_not_only_the_first() {
    let image = pe_variant(
        &Pe {
            imports: &["VCRUNTIME140.dll", "MSVCP140.dll"],
            delay_imports: &[],
            load_config: None,
        },
        &no_initializer(),
    );
    assert_eq!(
        kinds(&image),
        vec![
            ViolationKind::PeDependentLoadFlags,
            ViolationKind::PeRuntimeImport,
            ViolationKind::PeRuntimeImport,
            ViolationKind::PeInitializer
        ]
    );
}

fn no_initializer() -> Variant {
    Variant {
        no_initializer: true,
        ..Variant::default()
    }
}

fn hardened_spec() -> Pe<'static> {
    Pe {
        imports: &[KERNEL32],
        delay_imports: &[],
        load_config: Some((0x800, FULL)),
    }
}

/// The initializer's object contributes the `.lsguard` section, so an image without it has lost the initializer,
/// whatever its load flags say, and whatever it imports: a dependency that calls `SetDefaultDllDirectories` does
/// not stand in.
#[test]
fn an_image_without_the_initializers_section_is_reported() {
    for imports in [&[KERNEL32][..], &[], &["KERNEL32.dll!SetDefaultDllDirectories"]] {
        let spec = Pe {
            imports,
            ..hardened_spec()
        };
        assert_eq!(
            kinds(&pe_variant(&spec, &no_initializer())),
            vec![ViolationKind::PeInitializer],
            "{imports:?}"
        );
    }
}

/// Whatever else the image imports, the section is what shows the initializer.
#[test]
fn an_image_with_the_initializers_section_passes_whatever_it_imports() {
    let spec = Pe {
        imports: &[
            "USER32.dll",
            "api-ms-win-core-libraryloader-l1-2-0.dll!SetDefaultDllDirectories",
        ],
        ..hardened_spec()
    };
    assert_eq!(kinds(&pe(&spec)), vec![]);
}

/// Only the section's name shows the initializer: the same text in another section's data, as in an executable
/// that embeds a hardened one, and a name that differs in its last byte do not.
#[test]
fn only_a_section_of_exactly_that_name_shows_the_initializer() {
    let rename = |image: &mut Vec<u8>, from: &[u8], to: &[u8]| {
        let at = image.windows(from.len()).position(|window| window == from).unwrap();
        image[at..at + to.len()].copy_from_slice(to);
    };
    let mut lookalike = pe(&hardened_spec());
    rename(&mut lookalike, b".lsguard", b".lsguarX");
    assert_eq!(kinds(&lookalike), vec![ViolationKind::PeInitializer]);

    let embedded = pe_variant(
        &hardened_spec(),
        &Variant {
            unread_data: b".lsguard",
            ..no_initializer()
        },
    );
    assert!(embedded.windows(8).any(|window| window == b".lsguard"));
    assert_eq!(kinds(&embedded), vec![ViolationKind::PeInitializer]);
}

fn broken(name: BrokenName) -> Variant {
    Variant {
        broken_name: Some(name),
        ..Variant::default()
    }
}

const BROKEN_NAMES: [BrokenName; 2] = [BrokenName::Before, BrokenName::After];

/// A section name that cannot be read matters only if it could be the initializer's: with `.lsguard` found
/// anywhere, the initializer is present, whatever the other names say.
#[test]
fn a_section_name_that_cannot_be_read_does_not_hide_the_initializers_section() {
    for name in BROKEN_NAMES {
        assert_eq!(kinds(&pe_variant(&hardened_spec(), &broken(name))), vec![], "{name:?}");
    }
}

/// Without `.lsguard`, a name that cannot be read could have been it: the image is unreadable, not reported for
/// lacking the initializer, and what was found before is kept. The error names the section by its name field,
/// and says why it matters.
#[test]
fn without_the_initializers_section_a_section_name_that_cannot_be_read_is_unreadable() {
    let spec = Pe {
        load_config: None,
        ..hardened_spec()
    };
    for name in BROKEN_NAMES {
        let variant = Variant {
            no_initializer: true,
            ..broken(name)
        };
        let Err(VerifyError::Unreadable { why, found }) = verify_bytes(&pe_variant(&spec, &variant)) else {
            panic!("{name:?}: not unreadable");
        };
        assert_eq!(
            found.iter().map(|v| v.kind).collect::<Vec<_>>(),
            vec![ViolationKind::PeDependentLoadFlags],
            "{name:?}"
        );
        assert!(why.contains("`/99`") && why.contains("initializer"), "{name:?}: {why}");
    }
}

/// The checks are independent, so a section name that cannot be read never hides a runtime import that can be.
#[test]
fn a_section_name_that_cannot_be_read_does_not_hide_a_runtime_import() {
    let spec = Pe {
        imports: &[KERNEL32, "VCRUNTIME140.dll"],
        ..hardened_spec()
    };
    for name in BROKEN_NAMES {
        assert_eq!(
            kinds(&pe_variant(&spec, &broken(name))),
            vec![ViolationKind::PeRuntimeImport],
            "{name:?}"
        );
        let variant = Variant {
            no_initializer: true,
            ..broken(name)
        };
        let Err(VerifyError::Unreadable { found, .. }) = verify_bytes(&pe_variant(&spec, &variant)) else {
            panic!("{name:?}: not unreadable");
        };
        assert_eq!(
            found.iter().map(|v| v.kind).collect::<Vec<_>>(),
            vec![ViolationKind::PeRuntimeImport],
            "{name:?}"
        );
    }
}

/// What was found before a part that cannot be read is kept, as for ELF and Mach-O.
#[test]
fn violations_found_before_an_unreadable_import_table_are_kept() {
    let spec = Pe {
        load_config: None,
        ..hardened_spec()
    };
    let variant = Variant {
        unreadable_import_table: true,
        ..Variant::default()
    };
    let Err(VerifyError::Unreadable { found, .. }) = verify_bytes(&pe_variant(&spec, &variant)) else {
        panic!("expected an unreadable file");
    };
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].kind, ViolationKind::PeDependentLoadFlags);
}

/// The checks are independent: a part that cannot be read does not hide what the other checks find. The first
/// unreadable part is the error, with every violation kept.
fn unreadable_found(spec: &Pe, variant: &Variant) -> (String, Vec<ViolationKind>) {
    match verify_bytes(&pe_variant(spec, variant)) {
        Err(VerifyError::Unreadable { why, found }) => (why, found.into_iter().map(|v| v.kind).collect()),
        other => panic!("not unreadable: {other:?}"),
    }
}

#[test]
fn an_unreadable_load_config_hides_neither_a_runtime_import_nor_the_missing_initializer() {
    let spec = Pe {
        imports: &[KERNEL32, "VCRUNTIME140.dll"],
        ..hardened_spec()
    };
    let variant = Variant {
        unreadable_load_config: true,
        ..no_initializer()
    };
    let (_, found) = unreadable_found(&spec, &variant);
    assert_eq!(
        found,
        vec![ViolationKind::PeRuntimeImport, ViolationKind::PeInitializer]
    );
}

#[test]
fn an_unreadable_import_table_does_not_hide_the_missing_initializer() {
    let variant = Variant {
        unreadable_import_table: true,
        ..no_initializer()
    };
    let (_, found) = unreadable_found(&hardened_spec(), &variant);
    assert_eq!(found, vec![ViolationKind::PeInitializer]);
}

#[test]
fn an_unreadable_delay_load_table_keeps_the_runtime_imports_already_read() {
    let spec = Pe {
        imports: &[KERNEL32, "VCRUNTIME140.dll"],
        ..hardened_spec()
    };
    let variant = Variant {
        unreadable_delay_table: true,
        ..Variant::default()
    };
    let (_, found) = unreadable_found(&spec, &variant);
    assert_eq!(found, vec![ViolationKind::PeRuntimeImport]);
}

/// A DLL never carries the initializer (it must not change the process's search order), so the check does not
/// apply to it; the other rules do.
#[test]
fn a_dll_without_the_initializer_is_not_reported_for_it() {
    let dll = Variant {
        dll: true,
        ..no_initializer()
    };
    assert_eq!(kinds(&pe_variant(&hardened_spec(), &dll)), vec![]);
    let flags_missing = Pe {
        load_config: None,
        ..hardened_spec()
    };
    assert_eq!(
        kinds(&pe_variant(&flags_missing, &dll)),
        vec![ViolationKind::PeDependentLoadFlags]
    );
    let runtime = Pe {
        imports: &[KERNEL32, "VCRUNTIME140.dll"],
        ..hardened_spec()
    };
    assert_eq!(kinds(&pe_variant(&runtime, &dll)), vec![ViolationKind::PeRuntimeImport]);
}

#[test]
fn a_pe32_without_the_initializer_is_reported() {
    let image = pe_variant(
        &Pe {
            imports: &[KERNEL32],
            delay_imports: &[],
            load_config: Some((0x800, FULL32)),
        },
        &Variant {
            bits: Bits::B32,
            ..no_initializer()
        },
    );
    assert_eq!(kinds(&image), vec![ViolationKind::PeInitializer]);
}

/// The 32-bit load config directory is shorter, and its `DependentLoadFlags` sit at a different offset.
const FULL32: u32 = 0x40;

fn pe32_kinds(imports: &[&str], load_config: Option<(u16, u32)>) -> Vec<ViolationKind> {
    kinds(&pe32(&Pe {
        imports,
        delay_imports: &[],
        load_config,
    }))
}

#[test]
fn a_hardened_pe32_passes() {
    assert_eq!(pe32_kinds(&[KERNEL32], Some((0x800, FULL32))), vec![]);
}

#[test]
fn a_pe32_without_system32_in_its_flags_is_reported() {
    assert_eq!(
        pe32_kinds(&[KERNEL32], Some((0x400, FULL32))),
        vec![ViolationKind::PeDependentLoadFlags]
    );
}

#[test]
fn a_pe32_that_searches_the_executables_folder_is_reported() {
    assert_eq!(
        pe32_kinds(&[KERNEL32], Some((0x800 | 0x200, FULL32))),
        vec![ViolationKind::PeDependentLoadFlags]
    );
}

#[test]
fn a_pe32_without_a_load_config_or_with_one_too_short_is_reported() {
    for load_config in [None, Some((0x800, 0x30))] {
        assert_eq!(
            pe32_kinds(&[KERNEL32], load_config),
            vec![ViolationKind::PeDependentLoadFlags],
            "{load_config:?}"
        );
    }
}

#[test]
fn a_pe32_that_imports_a_redistributable_is_reported() {
    assert_eq!(
        pe32_kinds(&[KERNEL32, "VCRUNTIME140.dll"], Some((0x800, FULL32))),
        vec![ViolationKind::PeRuntimeImport]
    );
}
