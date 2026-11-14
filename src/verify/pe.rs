//! PE rules: the load config's `DependentLoadFlags` include `LOAD_LIBRARY_SEARCH_SYSTEM32` and no bit outside it
//! and `LOAD_LIBRARY_SEARCH_USER_DIRS`, an executable has the section of the pre-`main` initializer's object (a DLL
//! never does), and no Visual C++ redistributable DLL is imported, in the import table or the delay-load import
//! table.

use object::pe::{
    ImageLoadConfigDirectory32, ImageLoadConfigDirectory64, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG, IMAGE_FILE_DLL,
};
use object::read::pe::{ImageNtHeaders, PeFile};
use object::{LittleEndian as LE, Object, ObjectSection};

use super::{unreadable, Violation, ViolationKind};

/// The section the initializer's object defines (`initializer/pre_main.rs`). The name is the whole 8-byte field.
const INITIALIZER_SECTION: &[u8] = b".lsguard";

const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x0800;
/// `LOAD_LIBRARY_SEARCH_USER_DIRS`: it adds only the directories registered with `AddDllDirectory`, and none is
/// at load time, so it is the one bit besides `LOAD_LIBRARY_SEARCH_SYSTEM32` that is allowed.
const LOAD_LIBRARY_SEARCH_USER_DIRS: u16 = 0x0400;
const ALLOWED_FLAGS: u16 = LOAD_LIBRARY_SEARCH_SYSTEM32 | LOAD_LIBRARY_SEARCH_USER_DIRS;

/// The bits that make the loader search the executable's own folder, named in a violation.
const NAMED_FLAGS: [(u16, &str); 3] = [
    (0x0100, "LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR"),
    (0x0200, "LOAD_LIBRARY_SEARCH_APPLICATION_DIR"),
    (
        0x1000,
        "LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, which includes the application directory",
    ),
];

/// The set bits of `flags`, one per element, each with the name it has where it has one.
fn describe_bits(flags: u16) -> String {
    (0..u16::BITS)
        .map(|shift| 1u16 << shift)
        .filter(|bit| flags & bit != 0)
        .map(|bit| match NAMED_FLAGS.iter().find(|(named, _)| *named == bit) {
            Some((_, name)) => format!("bit {bit:#x} ({name})"),
            None => format!("bit {bit:#x}"),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Whether the DLL `name` (lower case) is a Visual C++ redistributable: not part of Windows, so an import of it
/// is searched for in the executable's folder, and is not found in System32 where the redistributable is not
/// installed. Names are matched exactly, by family, version digits and the suffixes each family has: the
/// Windows DLLs that begin like one (`msvcp_win`, `msvcp110_win`, `msvcp60`, `msvcrt`, `mfcore`, `mfc42`, the
/// `*_clr0400` copies, `atl`) do not match.
fn is_redistributable(name: &str) -> bool {
    let stem = name.strip_suffix(".dll").unwrap_or(name);
    if stem == "ucrtbased" {
        return true;
    }
    REDISTRIBUTABLE_FAMILIES.iter().any(|family| {
        let Some(rest) = stem.strip_prefix(family.prefix) else {
            return false;
        };
        let digits_end = rest.find(|c: char| !c.is_ascii_digit()).unwrap_or(rest.len());
        let (version, suffix) = rest.split_at(digits_end);
        !version.is_empty() && !family.ships_in_windows.contains(&version) && (family.suffix)(suffix)
    })
}

/// A redistributable DLL family: `<prefix><version digits><suffix>`.
struct Family {
    prefix: &'static str,
    /// Versions of this family that are part of Windows.
    ships_in_windows: &'static [&'static str],
    /// Whether the text after the version digits is one the family has.
    suffix: fn(&str) -> bool,
}

const REDISTRIBUTABLE_FAMILIES: [Family; 10] = [
    Family {
        prefix: "vcruntime",
        ships_in_windows: &[],
        suffix: vcruntime_suffix,
    },
    Family {
        prefix: "msvcp",
        ships_in_windows: &["60"],
        suffix: msvcp_suffix,
    },
    Family {
        prefix: "msvcr",
        ships_in_windows: &[],
        suffix: debug_suffix,
    },
    Family {
        prefix: "concrt",
        ships_in_windows: &[],
        suffix: uwp_suffix,
    },
    Family {
        prefix: "vcomp",
        ships_in_windows: &[],
        suffix: uwp_suffix,
    },
    Family {
        prefix: "vccorlib",
        ships_in_windows: &[],
        suffix: uwp_suffix,
    },
    Family {
        prefix: "vcamp",
        ships_in_windows: &[],
        suffix: uwp_suffix,
    },
    Family {
        prefix: "mfc",
        ships_in_windows: &["40", "42"],
        suffix: mfc_suffix,
    },
    Family {
        prefix: "mfcm",
        ships_in_windows: &[],
        suffix: mfcm_suffix,
    },
    Family {
        prefix: "atl",
        ships_in_windows: &[],
        suffix: str::is_empty,
    },
];

fn debug_suffix(suffix: &str) -> bool {
    matches!(suffix, "" | "d")
}

/// `_<digits>` with an optional debug `d`: `msvcp140_1`, `vcruntime140_1d`.
fn numbered_suffix(suffix: &str) -> bool {
    let Some(rest) = suffix.strip_prefix('_') else {
        return false;
    };
    let digits = rest.strip_suffix('d').unwrap_or(rest);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// `base` accepts a runtime's own suffix; this also accepts its UWP (VCLibs) copy, the same name with `_app`
/// after it, as in `vcruntime140_1_app` and `msvcp140d_app`.
fn or_uwp(suffix: &str, base: fn(&str) -> bool) -> bool {
    base(suffix) || suffix.strip_suffix("_app").is_some_and(base)
}

fn uwp_suffix(suffix: &str) -> bool {
    or_uwp(suffix, |base| debug_suffix(base) || numbered_suffix(base))
}

fn vcruntime_suffix(suffix: &str) -> bool {
    or_uwp(suffix, |base| {
        debug_suffix(base) || numbered_suffix(base) || matches!(base, "_threads" | "_threadsd")
    })
}

fn msvcp_suffix(suffix: &str) -> bool {
    or_uwp(suffix, |base| {
        debug_suffix(base)
            || numbered_suffix(base)
            || matches!(
                base,
                "_atomic_wait" | "_codecvt_ids" | "d_atomic_wait" | "d_codecvt_ids"
            )
    })
}

fn mfcm_suffix(suffix: &str) -> bool {
    matches!(suffix, "" | "u" | "d" | "ud")
}

/// The MFC DLLs, and its language packs (`mfc140deu`, three letters).
fn mfc_suffix(suffix: &str) -> bool {
    mfcm_suffix(suffix) || (suffix.len() == 3 && suffix.bytes().all(|b| b.is_ascii_lowercase()))
}

pub(super) fn check<Pe: ImageNtHeaders>(data: &[u8], out: &mut Vec<Violation>) -> Result<(), super::VerifyError> {
    let file = PeFile::<Pe, _>::parse(data).map_err(unreadable)?;

    let flags = dependent_load_flags::<Pe>(&file, data).map_err(unreadable)?;
    if flags & LOAD_LIBRARY_SEARCH_SYSTEM32 == 0 {
        out.push(Violation {
            kind: ViolationKind::PeDependentLoadFlags,
            detail: format!("DependentLoadFlags is {flags:#x}, which lacks LOAD_LIBRARY_SEARCH_SYSTEM32 (0x800)"),
        });
    }
    if flags & !ALLOWED_FLAGS != 0 {
        out.push(Violation {
            kind: ViolationKind::PeDependentLoadFlags,
            detail: format!(
                "DependentLoadFlags is {flags:#x}, which sets {}: only 0x800 and 0x400 are allowed, and the others either search the executable's folder for its imports or change how they are loaded",
                describe_bits(flags & !ALLOWED_FLAGS)
            ),
        });
    }

    // A DLL never carries the initializer: it must not change the search order of the process that loads it.
    let is_dll = file
        .nt_headers()
        .file_header()
        .characteristics
        .get(LE)
        .contains(IMAGE_FILE_DLL);
    if !is_dll && !has_initializer_section(&file)? {
        out.push(Violation {
            kind: ViolationKind::PeInitializer,
            detail: "has no `.lsguard` section, which the pre-main initializer that bins() links in contributes, so the initializer is not linked: a LoadLibrary call without flags still searches the executable's folder".into(),
        });
    }

    // A delay-loaded DLL is loaded by `LoadLibrary` at its first call, and is searched for like an imported one.
    let mut names = Vec::new();
    if let Some(imports) = file.import_table().map_err(unreadable)? {
        let mut descriptors = imports.descriptors().map_err(unreadable)?;
        while let Some(descriptor) = descriptors.next().map_err(unreadable)? {
            names.push(imports.name(descriptor.name.get(LE)).map_err(unreadable)?);
        }
    }
    if let Some(imports) = file.delay_load_import_table().map_err(unreadable)? {
        let mut descriptors = imports.descriptors().map_err(unreadable)?;
        while let Some(descriptor) = descriptors.next().map_err(unreadable)? {
            names.push(imports.name(descriptor.dll_name_rva.get(LE)).map_err(unreadable)?);
        }
    }
    for name in names {
        let name = String::from_utf8_lossy(name);
        if is_redistributable(&name.to_ascii_lowercase()) {
            out.push(Violation {
                kind: ViolationKind::PeRuntimeImport,
                detail: format!("imports {name}, which is searched for in the executable's folder first"),
            });
        }
    }
    Ok(())
}

/// Whether the image has the initializer's section.
///
/// The object that holds the initializer also defines the section, so an image has it exactly when the initializer
/// was linked. The `.CRT$XIAB` entry itself is merged into `.rdata`, and a release binary has no symbols, so
/// neither shows it; the section table always does. Only the names are read: a section's data is not. Every name
/// is read, and one that cannot be (a long name into a string table the image does not have) makes the image
/// unreadable: it could have been the initializer's.
fn has_initializer_section<'data, Pe: ImageNtHeaders>(
    file: &PeFile<'data, Pe, &'data [u8]>,
) -> Result<bool, super::VerifyError> {
    let mut found = false;
    for section in file.sections() {
        found |= section.name_bytes().map_err(unreadable)? == INITIALIZER_SECTION;
    }
    Ok(found)
}

/// `DependentLoadFlags` from the load config directory, or 0 where the directory is absent or too short to
/// hold the field (older linkers write a shorter one), which is how the loader reads it too.
fn dependent_load_flags<'data, Pe: ImageNtHeaders>(
    file: &PeFile<'data, Pe, &'data [u8]>,
    data: &'data [u8],
) -> object::Result<u16> {
    let Some(directory) = file.data_directory(IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG) else {
        return Ok(0);
    };
    if directory.virtual_address.get(LE) == 0 || directory.size.get(LE) == 0 {
        return Ok(0);
    }
    let bytes = directory.data(data, &file.section_table())?;
    let field_at = if file.nt_headers().is_type_64() {
        std::mem::offset_of!(ImageLoadConfigDirectory64, dependent_load_flags)
    } else {
        std::mem::offset_of!(ImageLoadConfigDirectory32, dependent_load_flags)
    };
    // The directory's own leading size field bounds what the linker wrote.
    let declared = bytes
        .first_chunk::<4>()
        .map_or(0, |size| u32::from_le_bytes(*size) as usize);
    let written = declared.min(bytes.len());
    match bytes.get(field_at..field_at + 2) {
        Some(field) if field_at + 2 <= written => Ok(u16::from_le_bytes([field[0], field[1]])),
        _ => Ok(0),
    }
}
