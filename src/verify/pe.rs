//! PE rules: the load config's `DependentLoadFlags` include `LOAD_LIBRARY_SEARCH_SYSTEM32`, and no Visual C++
//! redistributable DLL is imported.

use object::pe::{ImageLoadConfigDirectory32, ImageLoadConfigDirectory64, IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG};
use object::read::pe::{ImageNtHeaders, PeFile};
use object::LittleEndian as LE;

use super::{unreadable, Violation, ViolationKind};

const LOAD_LIBRARY_SEARCH_SYSTEM32: u16 = 0x0800;

/// Name prefixes (lower case) of the Visual C++ redistributable DLLs: they are not in System32, so an import
/// is searched for in the executable's folder first.
const REDISTRIBUTABLE_PREFIXES: [&str; 7] = ["vcruntime", "concrt", "vcomp", "vccorlib", "vcamp", "mfc", "ucrtbased"];

/// Like [`REDISTRIBUTABLE_PREFIXES`], but a name matches only when a version digit follows: `msvcp_win.dll`,
/// `msvcrt.dll` (a KnownDLL) and `atl.dll` are part of Windows, and the redistributable ones are `msvcp140`,
/// `msvcr100`, `atl100`.
const VERSIONED_PREFIXES: [&str; 3] = ["msvcp", "msvcr", "atl"];

fn is_redistributable(lower: &str) -> bool {
    REDISTRIBUTABLE_PREFIXES.iter().any(|prefix| lower.starts_with(prefix))
        || VERSIONED_PREFIXES.iter().any(|prefix| {
            lower
                .strip_prefix(prefix)
                .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
        })
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

    if let Some(imports) = file.import_table().map_err(unreadable)? {
        let mut descriptors = imports.descriptors().map_err(unreadable)?;
        while let Some(descriptor) = descriptors.next().map_err(unreadable)? {
            let name = imports.name(descriptor.name.get(LE)).map_err(unreadable)?;
            let name = String::from_utf8_lossy(name);
            let lower = name.to_ascii_lowercase();
            if is_redistributable(&lower) {
                out.push(Violation {
                    kind: ViolationKind::PeRuntimeImport,
                    detail: format!("imports {name}, which is searched for in the executable's folder first"),
                });
            }
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
