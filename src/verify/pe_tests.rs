use super::crafted::{pe, pe32, Pe};
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

/// `LOAD_LIBRARY_SEARCH_USER_DIRS` (0x400) adds the directories a process registered with `AddDllDirectory`;
/// at load time there are none, so an import is still searched for in System32 only (measured).
#[test]
fn flags_that_add_the_user_dirs_to_system32_pass() {
    let image = pe(&Pe {
        imports: &["KERNEL32.dll"],
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
            imports: &["KERNEL32.dll"],
            delay_imports: &[],
            load_config: Some((flags, FULL)),
        });
        assert_eq!(kinds(&image), vec![ViolationKind::PeDependentLoadFlags], "{flags:#x}");
    }
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
        "vcruntime140_1d.dll",
        "vcruntime140_threads.dll",
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
    assert_eq!(pe32_kinds(&["KERNEL32.dll"], Some((0x800, FULL32))), vec![]);
}

#[test]
fn a_pe32_without_system32_in_its_flags_is_reported() {
    assert_eq!(
        pe32_kinds(&["KERNEL32.dll"], Some((0x400, FULL32))),
        vec![ViolationKind::PeDependentLoadFlags]
    );
}

#[test]
fn a_pe32_that_searches_the_executables_folder_is_reported() {
    assert_eq!(
        pe32_kinds(&["KERNEL32.dll"], Some((0x800 | 0x200, FULL32))),
        vec![ViolationKind::PeDependentLoadFlags]
    );
}

#[test]
fn a_pe32_without_a_load_config_or_with_one_too_short_is_reported() {
    for load_config in [None, Some((0x800, 0x30))] {
        assert_eq!(
            pe32_kinds(&["KERNEL32.dll"], load_config),
            vec![ViolationKind::PeDependentLoadFlags],
            "{load_config:?}"
        );
    }
}

#[test]
fn a_pe32_that_imports_a_redistributable_is_reported() {
    assert_eq!(
        pe32_kinds(&["KERNEL32.dll", "VCRUNTIME140.dll"], Some((0x800, FULL32))),
        vec![ViolationKind::PeRuntimeImport]
    );
}
