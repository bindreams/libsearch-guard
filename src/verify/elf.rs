//! ELF rule: no `RPATH` or `RUNPATH` element that is `$ORIGIN`-based or relative.
//!
//! The loader searches the executable's folder only when asked to, and `$ORIGIN` (or a relative path, resolved
//! against the working directory) is how a binary asks. Every element must be an absolute path.

use object::elf::{DT_RPATH, DT_RUNPATH};
use object::read::elf::{Dyn, FileHeader, ProgramHeader};

use super::{unreadable, VerifyError, Violation, ViolationKind};

pub(super) fn check<Elf: FileHeader<Endian = object::Endianness>>(
    data: &[u8],
    out: &mut Vec<Violation>,
) -> Result<(), VerifyError> {
    let header = Elf::parse(data).map_err(unreadable)?;
    let endian = header.endian().map_err(unreadable)?;
    let sections = header.sections(endian, data).map_err(unreadable)?;

    let Some((entries, strings_index)) = sections.dynamic(endian, data).map_err(unreadable)? else {
        // Without section headers an image's dynamic section cannot be located here. Refuse
        // rather than pass what was not inspected.
        let has_dynamic_segment = header
            .program_headers(endian, data)
            .map_err(unreadable)?
            .iter()
            .any(|segment| segment.p_type(endian) == object::elf::PT_DYNAMIC);
        if sections.is_empty() && has_dynamic_segment {
            return Err(VerifyError::Unreadable(
                "the file has a dynamic segment but no section headers, so its RPATH cannot be inspected".into(),
            ));
        }
        return Ok(());
    };
    let strings = sections.strings(endian, data, strings_index).map_err(unreadable)?;

    for entry in entries {
        let name = match entry.tag(endian) {
            DT_RPATH => "RPATH",
            DT_RUNPATH => "RUNPATH",
            _ => continue,
        };
        let value = entry.string(endian, strings).map_err(unreadable)?;
        let value = String::from_utf8_lossy(value);
        for element in value.split(':').filter(|element| !element.starts_with('/')) {
            out.push(Violation {
                kind: ViolationKind::ElfSearchPath,
                detail: format!("{name} element {element:?} is not an absolute path"),
            });
        }
    }
    Ok(())
}
