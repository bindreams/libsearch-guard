//! Checks that an executable does not search its own folder for libraries.

use std::fmt;
use std::path::Path;

use object::elf::{FileHeader32, FileHeader64};
use object::macho::{MachHeader32, MachHeader64};
use object::pe::{ImageNtHeaders32, ImageNtHeaders64};
use object::read::macho::{FatArch, MachOFatFile32, MachOFatFile64};
use object::{Endianness, FileKind};

mod elf;
mod macho;
mod pe;

#[cfg(test)]
mod crafted;
#[cfg(test)]
mod elf_tests;
#[cfg(test)]
mod macho_tests;
#[cfg(test)]
mod pe_tests;
#[cfg(test)]
mod verify_tests;

/// The rule a binary breaks. More rules may be added in a minor release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ViolationKind {
    /// PE: the load config's `DependentLoadFlags` lack `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800), or set a bit other
    /// than 0x800 and `LOAD_LIBRARY_SEARCH_USER_DIRS` (0x400). Among those, 0x100 (`DLL_LOAD_DIR`), 0x200
    /// (`APPLICATION_DIR`) and 0x1000 (`DEFAULT_DIRS`) each search the executable's folder.
    PeDependentLoadFlags,
    /// PE: imports, or delay-loads, a Visual C++ redistributable DLL (`vcruntime<n>`, `msvcp<n>`, `msvcr<n>`,
    /// `concrt<n>`, `vcomp<n>`, `vccorlib<n>`, `vcamp<n>`, `mfc<n>`, `mfcm<n>`, `atl<n>` with their `_<n>`, debug,
    /// language and UWP `_app` variants, and `ucrtbased`), which Windows searches for in the executable's folder first.
    /// The DLLs that ship in Windows (`msvcp_win`, `msvcrt`, `mfcore`, `mfc42`, ...) are not reported.
    PeRuntimeImport,
    /// PE: an executable without the `.lsguard` section that the object of the initializer `bins()` links in
    /// defines, so the initializer is not linked and a `LoadLibrary` call without flags still searches the
    /// executable's folder. A DLL is not checked: it never carries the initializer. A binary hardened by 0.1.x has
    /// no such section and is reported from 0.2.0 on: rebuild it with 0.2.0 or later.
    PeInitializer,
    /// ELF: an `RPATH` or `RUNPATH` element that is `$ORIGIN`-based or relative.
    ElfSearchPath,
    /// ELF: a `DT_NEEDED` entry that contains a `/` but does not start with one. The loader opens it relative to
    /// the working directory.
    ElfNeeded,
    /// ELF: an element of the `:`-separated list in `DT_AUDIT` or `DT_DEPAUDIT`, or the one name in `DT_FILTER` or
    /// `DT_AUXILIARY` (libraries the loader maps), that is `$ORIGIN`-based or a relative path.
    ElfLoaderLibrary,
    /// ELF: a `PT_INTERP` (the program interpreter) that does not start with `/`. The kernel opens it relative
    /// to the working directory.
    ElfInterpreter,
    /// Mach-O: an `LC_RPATH` command.
    MachoRpath,
    /// Mach-O: a dylib load command that is `@executable_path`-, `@loader_path`- or `@rpath`-based, or relative.
    MachoDylib,
    /// Mach-O: an `LC_DYLD_ENVIRONMENT` command that puts a `@executable_path`-, `@loader_path`- or
    /// `@rpath`-based or relative directory on a `DYLD_*_PATH` search path.
    MachoDyldEnvironment,
}

/// One broken rule, with what broke it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    pub kind: ViolationKind,
    pub detail: String,
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.kind, self.detail)
    }
}

/// Why [`verify`] did not pass a file. More variants may be added in a minor release.
#[derive(Debug)]
#[non_exhaustive]
pub enum VerifyError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file is not a PE, ELF or Mach-O executable this crate can read, a slice of a universal binary is not a
    /// Mach-O image, or a part of it (a library path, say) is not valid UTF-8, so a check could not be made.
    Unreadable {
        /// What could not be read.
        why: String,
        /// The violations found before the unreadable part; each keeps its kind.
        found: Vec<Violation>,
    },
    /// The file breaks one or more rules; every violation found is listed.
    Violations(Vec<Violation>),
}

impl VerifyError {
    fn unreadable(why: impl Into<String>) -> Self {
        VerifyError::Unreadable {
            why: why.into(),
            found: Vec::new(),
        }
    }
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Io(e) => write!(f, "cannot read the file: {e}"),
            VerifyError::Unreadable { why, found } => {
                write!(f, "cannot read the executable: {why}")?;
                if !found.is_empty() {
                    write!(f, "; found before that:")?;
                    for v in found {
                        write!(
                            f,
                            "
  {v}"
                        )?;
                    }
                }
                Ok(())
            }
            VerifyError::Violations(violations) => {
                write!(f, "{} library-search violation(s):", violations.len())?;
                for v in violations {
                    write!(
                        f,
                        "
  {v}"
                    )?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            VerifyError::Io(e) => Some(e),
            _ => None,
        }
    }
}

/// Verifies the executable at `path`.
///
/// It checks a developer's own build output for an accidental opt-in to a search of the executable's folder; a
/// binary crafted to deceive it (several `PT_DYNAMIC` segments, say) is out of scope.
pub fn verify(path: impl AsRef<Path>) -> Result<(), VerifyError> {
    let bytes = std::fs::read(path).map_err(VerifyError::Io)?;
    verify_bytes(&bytes)
}

fn verify_bytes(data: &[u8]) -> Result<(), VerifyError> {
    let mut violations = Vec::new();
    match check(data, &mut violations) {
        Ok(()) if violations.is_empty() => Ok(()),
        Ok(()) => Err(VerifyError::Violations(violations)),
        // What was found before the unreadable part is not lost.
        Err(VerifyError::Unreadable { why, .. }) => Err(VerifyError::Unreadable { why, found: violations }),
        Err(error) => Err(error),
    }
}

fn check(data: &[u8], out: &mut Vec<Violation>) -> Result<(), VerifyError> {
    match FileKind::parse(data).map_err(unreadable)? {
        FileKind::Pe32 => pe::check::<ImageNtHeaders32>(data, out),
        FileKind::Pe64 => pe::check::<ImageNtHeaders64>(data, out),
        FileKind::Elf32 => elf::check::<FileHeader32<Endianness>>(data, out),
        FileKind::Elf64 => elf::check::<FileHeader64<Endianness>>(data, out),
        FileKind::MachO32 => macho::check::<MachHeader32<Endianness>>(data, out),
        FileKind::MachO64 => macho::check::<MachHeader64<Endianness>>(data, out),
        FileKind::MachOFat32 => check_slices(MachOFatFile32::parse(data).map_err(unreadable)?.arches(), data, out),
        FileKind::MachOFat64 => check_slices(MachOFatFile64::parse(data).map_err(unreadable)?.arches(), data, out),
        other => Err(VerifyError::unreadable(format!(
            "{other:?} is not a PE, ELF or Mach-O executable"
        ))),
    }
}

/// Checks the slices of a universal binary, of which there must be at least one. A slice is a Mach-O image: anything else, a nested universal binary
/// included, is not something dyld loads from one.
fn check_slices<A: FatArch>(arches: &[A], data: &[u8], out: &mut Vec<Violation>) -> Result<(), VerifyError> {
    if arches.is_empty() {
        return Err(VerifyError::unreadable("a universal binary has no slices"));
    }
    for arch in arches {
        let slice = arch.data(data).map_err(unreadable)?;
        match FileKind::parse(slice).map_err(unreadable)? {
            FileKind::MachO32 => macho::check::<MachHeader32<Endianness>>(slice, out)?,
            FileKind::MachO64 => macho::check::<MachHeader64<Endianness>>(slice, out)?,
            other => {
                return Err(VerifyError::unreadable(format!(
                    "a slice of a universal binary is {other:?}, not a Mach-O image"
                )))
            }
        }
    }
    Ok(())
}

/// `bytes` as text, or an unreadable file: the loader reads them as bytes, and a lossy copy could pass what it
/// would load.
fn utf8<'a>(what: &str, bytes: &'a [u8]) -> Result<&'a str, VerifyError> {
    std::str::from_utf8(bytes).map_err(|_| {
        VerifyError::unreadable(format!(
            "{what} {:?} is not valid UTF-8",
            String::from_utf8_lossy(bytes)
        ))
    })
}

fn unreadable(error: object::Error) -> VerifyError {
    VerifyError::unreadable(error.to_string())
}
