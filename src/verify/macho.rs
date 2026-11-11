//! Mach-O rules: no `LC_RPATH`, and no dylib load command that is `@executable_path`-, `@loader_path`- or
//! `@rpath`-based or relative. Every dylib reference must be an absolute path.

use object::read::macho::{LoadCommandVariant, MachHeader};

use super::{unreadable, VerifyError, Violation, ViolationKind};

pub(super) fn check<Mach: MachHeader<Endian = object::Endianness>>(
    data: &[u8],
    out: &mut Vec<Violation>,
) -> Result<(), VerifyError> {
    let header = Mach::parse(data, 0).map_err(unreadable)?;
    let endian = header.endian().map_err(unreadable)?;
    let mut commands = header.load_commands(endian, data, 0).map_err(unreadable)?;

    while let Some(command) = commands.next().map_err(unreadable)? {
        match command.variant().map_err(unreadable)? {
            LoadCommandVariant::Rpath(rpath) => {
                let path = command.string(endian, rpath.path).map_err(unreadable)?;
                out.push(Violation {
                    kind: ViolationKind::MachoRpath,
                    detail: format!("LC_RPATH {:?}", String::from_utf8_lossy(path)),
                });
            }
            // `LC_ID_DYLIB` (the `IdDylib` variant) names the library itself, not something it searches for.
            LoadCommandVariant::Dylib(dylib) => {
                let name = command.string(endian, dylib.dylib.name).map_err(unreadable)?;
                if !name.starts_with(b"/") {
                    out.push(Violation {
                        kind: ViolationKind::MachoDylib,
                        detail: format!("dylib {:?} is not an absolute path", String::from_utf8_lossy(name)),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}
