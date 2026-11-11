//! Byte-level builders for the smallest PE, ELF and Mach-O images the verifier can read, so every rule is
//! tested on every host.

pub fn put(buf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    if buf.len() < at + bytes.len() {
        buf.resize(at + bytes.len(), 0);
    }
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

/// `image` with the first byte of `marker`, which must occur once in it, replaced by 0xFF: the string that held
/// the marker is then not valid UTF-8.
pub fn not_utf8(mut image: Vec<u8>, marker: &str) -> Vec<u8> {
    let found: Vec<usize> = image
        .windows(marker.len())
        .enumerate()
        .filter(|(_, window)| *window == marker.as_bytes())
        .map(|(at, _)| at)
        .collect();
    assert_eq!(found.len(), 1, "{marker:?} must occur once in the image");
    image[found[0]] = 0xFF;
    image
}

mod elf;
mod macho;
mod pe;

pub use elf::*;
pub use macho::*;
pub use pe::*;
