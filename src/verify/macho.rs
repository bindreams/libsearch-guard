//! Mach-O rules: no `LC_RPATH`; no dylib load command that is `@executable_path`-, `@loader_path`- or
//! `@rpath`-based or relative; and no `LC_DYLD_ENVIRONMENT` that puts such a directory on a `DYLD_*_PATH`
//! search path. Every dylib reference and every such directory must be an absolute path (an empty element
//! names the root directory and is not reported).

use object::read::macho::{LoadCommandVariant, MachHeader};

use super::{unreadable, utf8, VerifyError, Violation, ViolationKind};

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
                // Any `LC_RPATH` is a violation whatever its text, so a path that is not UTF-8 is reported lossily.
                out.push(Violation {
                    kind: ViolationKind::MachoRpath,
                    detail: format!("LC_RPATH {:?}", String::from_utf8_lossy(path)),
                });
            }
            // `LC_ID_DYLIB` (the `IdDylib` variant) names the library itself, not something it searches for.
            LoadCommandVariant::Dylib(dylib) => {
                let name = command.string(endian, dylib.dylib.name).map_err(unreadable)?;
                let name = utf8("dylib", name)?;
                if !name.starts_with('/') {
                    out.push(Violation {
                        kind: ViolationKind::MachoDylib,
                        detail: format!("dylib {name:?} is not an absolute path"),
                    });
                }
            }
            // The command's string is `VARIABLE=value`. The `DYLD_*_PATH` variables hold a `:`-separated list of
            // directories; the others (`DYLD_IMAGE_SUFFIX`, `DYLD_PRINT_*`) are not searches.
            LoadCommandVariant::DyldEnvironment(environment) => {
                let setting = command.string(endian, environment.name).map_err(unreadable)?;
                let Some(equals) = setting.iter().position(|&byte| byte == b'=') else {
                    continue;
                };
                let (variable, value) = (&setting[..equals], &setting[equals + 1..]);
                if !(variable.starts_with(b"DYLD_") && variable.ends_with(b"_PATH")) {
                    continue;
                }
                // Only a search path's value is read as text; any other variable's bytes do not matter.
                let variable = String::from_utf8_lossy(variable);
                let value = utf8(&format!("LC_DYLD_ENVIRONMENT {variable}"), value)?;
                // dyld joins an empty element to the leaf name as `/leaf` (a path in the root directory), so it
                // is not a search relative to anything.
                for element in value
                    .split(':')
                    .filter(|element| !element.is_empty() && !element.starts_with('/'))
                {
                    out.push(Violation {
                        kind: ViolationKind::MachoDyldEnvironment,
                        detail: format!("LC_DYLD_ENVIRONMENT {variable} element {element:?} is not an absolute path"),
                    });
                }
            }
            _ => {}
        }
    }
    Ok(())
}
