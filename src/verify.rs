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
    /// PE: the load config's `DependentLoadFlags` lack `LOAD_LIBRARY_SEARCH_SYSTEM32` (0x800).
    PeDependentLoadFlags,
    /// PE: imports, or delay-loads, a Visual C++ redistributable DLL (`vcruntime*`, `msvcp<n>*`, `msvcr<n>*`, `atl<n>*`,
    /// `concrt*`, `vcomp*`, `vccorlib*`, `vcamp*`, `mfc*`, `ucrtbased*`), which Windows searches for in the
    /// executable's folder first.
    PeRuntimeImport,
    /// ELF: an `RPATH` or `RUNPATH` element that is `$ORIGIN`-based or relative.
    ElfSearchPath,
    /// ELF: a `DT_NEEDED` entry that contains a `/` but does not start with one. The loader opens it relative to
    /// the working directory.
    ElfNeeded,
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

/// Why [`verify`] did not pass a file.
#[derive(Debug)]
pub enum VerifyError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file is not a PE, ELF or Mach-O executable this crate can read.
    Unreadable(String),
    /// The file breaks one or more rules; every violation found is listed.
    Violations(Vec<Violation>),
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyError::Io(e) => write!(f, "cannot read the file: {e}"),
            VerifyError::Unreadable(why) => write!(f, "cannot read the executable: {why}"),
            VerifyError::Violations(violations) => {
                write!(f, "{} library-search violation(s):", violations.len())?;
                for v in violations {
                    write!(f, "\n  {v}")?;
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
pub fn verify(path: impl AsRef<Path>) -> Result<(), VerifyError> {
    let bytes = std::fs::read(path).map_err(VerifyError::Io)?;
    verify_bytes(&bytes)
}

fn verify_bytes(data: &[u8]) -> Result<(), VerifyError> {
    let mut violations = Vec::new();
    check(data, &mut violations)?;
    if violations.is_empty() {
        Ok(())
    } else {
        Err(VerifyError::Violations(violations))
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
        FileKind::MachOFat32 => {
            for arch in MachOFatFile32::parse(data).map_err(unreadable)?.arches() {
                check(arch.data(data).map_err(unreadable)?, out)?;
            }
            Ok(())
        }
        FileKind::MachOFat64 => {
            for arch in MachOFatFile64::parse(data).map_err(unreadable)?.arches() {
                check(arch.data(data).map_err(unreadable)?, out)?;
            }
            Ok(())
        }
        other => Err(VerifyError::Unreadable(format!(
            "{other:?} is not a PE, ELF or Mach-O executable"
        ))),
    }
}

fn unreadable(error: object::Error) -> VerifyError {
    VerifyError::Unreadable(error.to_string())
}
