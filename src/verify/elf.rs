//! ELF rules: no `RPATH` or `RUNPATH` element that is `$ORIGIN`-based or relative, and no `DT_NEEDED` that is a
//! relative path.
//!
//! The loader searches the executable's folder only when asked to, and `$ORIGIN` (or a relative path, resolved
//! against the working directory) is how a binary asks. Every element must be an absolute path. A `DT_NEEDED`
//! name with a `/` in it is opened as a path, so it too must be absolute; one without is looked up on the
//! search paths.
//!
//! The dynamic entries are read through the `PT_DYNAMIC` segment, as the loader reads them, and not through
//! the section headers, which a stripped or hand-linked binary may lack or falsify.

use object::elf::{DynamicTag, DT_NEEDED, DT_NULL, DT_RPATH, DT_RUNPATH, DT_STRSZ, DT_STRTAB, PT_DYNAMIC, PT_LOAD};
use object::read::elf::{Dyn, FileHeader, ProgramHeader};
use object::read::StringTable;

use super::{unreadable, VerifyError, Violation, ViolationKind};

pub(super) fn check<Elf: FileHeader<Endian = object::Endianness>>(
    data: &[u8],
    out: &mut Vec<Violation>,
) -> Result<(), VerifyError> {
    let header = Elf::parse(data).map_err(unreadable)?;
    let endian = header.endian().map_err(unreadable)?;
    let segments = header.program_headers(endian, data).map_err(unreadable)?;

    let Some(entries) = segments
        .iter()
        .find(|segment| segment.p_type(endian) == PT_DYNAMIC)
        .map(|segment| segment.dynamic(endian, data))
        .transpose()
        .map_err(unreadable)?
        .flatten()
    else {
        return Ok(());
    };
    // The loader stops at `DT_NULL`.
    let entries: Vec<_> = entries
        .iter()
        .take_while(|entry| entry.tag(endian) != DT_NULL)
        .collect();

    let reads_strings = |tag: DynamicTag| matches!(tag, DT_RPATH | DT_RUNPATH | DT_NEEDED);
    if !entries.iter().any(|entry| reads_strings(entry.tag(endian))) {
        return Ok(());
    }

    // `DT_STRTAB` is a virtual address; the loader reads it from memory, so it is found through the segments
    // that map the file.
    let value_of = |wanted: DynamicTag| {
        entries
            .iter()
            .find(|entry| entry.tag(endian) == wanted)
            .map(|entry| entry.val(endian))
    };
    let (Some(address), Some(size)) = (value_of(DT_STRTAB), value_of(DT_STRSZ)) else {
        return Err(VerifyError::Unreadable(
            "the dynamic section has no string table (DT_STRTAB, DT_STRSZ)".into(),
        ));
    };
    let mut table = None;
    for segment in segments.iter().filter(|segment| segment.p_type(endian) == PT_LOAD) {
        table = segment
            .data_range(endian, data, address, size)
            .map_err(|()| VerifyError::Unreadable("a loadable segment lies outside the file".into()))?;
        if table.is_some() {
            break;
        }
    }
    let Some(table) = table else {
        return Err(VerifyError::Unreadable(format!(
            "the dynamic string table at {address:#x} is not inside any loadable segment"
        )));
    };
    let strings = StringTable::<&[u8]>::new(table);

    for entry in entries {
        let tag = entry.tag(endian);
        let name = match tag {
            DT_RPATH => "RPATH",
            DT_RUNPATH => "RUNPATH",
            DT_NEEDED => "DT_NEEDED",
            _ => continue,
        };
        let value = entry.string(endian, strings).map_err(unreadable)?;
        let value = String::from_utf8_lossy(value);
        if tag == DT_NEEDED {
            if value.contains('/') && !value.starts_with('/') {
                out.push(Violation {
                    kind: ViolationKind::ElfNeeded,
                    detail: format!("{name} {value:?} is a relative path, opened against the working directory"),
                });
            }
            continue;
        }
        for element in value.split(':').filter(|element| !element.starts_with('/')) {
            out.push(Violation {
                kind: ViolationKind::ElfSearchPath,
                detail: format!("{name} element {element:?} is not an absolute path"),
            });
        }
    }
    Ok(())
}
