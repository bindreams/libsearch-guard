//! PE rules: the load config's `DependentLoadFlags` include `LOAD_LIBRARY_SEARCH_SYSTEM32`, and no Visual C++
//! redistributable DLL is imported, in the import table or the delay-load import table.

use object::pe::{ImageLoadConfigDirectory32, ImageLoadConfigDirectory64, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG};
use object::read::pe::{ImageNtHeaders, PeFile};
use object::LittleEndian as LE;

use super::{unreadable, Violation, ViolationKind};

const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x0800;

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
        suffix: debug_suffix,
    },
    Family {
        prefix: "vcomp",
        ships_in_windows: &[],
        suffix: debug_suffix,
    },
    Family {
        prefix: "vccorlib",
        ships_in_windows: &[],
        suffix: debug_suffix,
    },
    Family {
        prefix: "vcamp",
        ships_in_windows: &[],
        suffix: debug_suffix,
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

fn vcruntime_suffix(suffix: &str) -> bool {
    debug_suffix(suffix) || numbered_suffix(suffix) || matches!(suffix, "_threads" | "_threadsd")
}

fn msvcp_suffix(suffix: &str) -> bool {
    debug_suffix(suffix)
        || numbered_suffix(suffix)
        || matches!(
            suffix,
            "_atomic_wait" | "_codecvt_ids" | "d_atomic_wait" | "d_codecvt_ids"
        )
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
