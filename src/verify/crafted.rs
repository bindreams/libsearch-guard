//! Byte-level builders for the smallest PE, ELF and Mach-O images the verifier can read, so every rule is
//! tested on every host.

pub fn put(buf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    if buf.len() < at + bytes.len() {
        buf.resize(at + bytes.len(), 0);
    }
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

mod elf;
mod macho;
mod pe;

pub use elf::*;
pub use macho::*;
pub use pe::*;
