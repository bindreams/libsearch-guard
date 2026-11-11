//! Crafted ELF images.

use super::put;

pub const DT_NEEDED: u64 = 1;
pub const DT_RPATH: u64 = 15;
pub const DT_RUNPATH: u64 = 29;
pub const DT_DEPAUDIT: u64 = 0x6fff_fefb;
pub const DT_AUDIT: u64 = 0x6fff_fefc;
pub const DT_AUXILIARY: u64 = 0x7fff_fffd;
pub const DT_FILTER: u64 = 0x7fff_ffff;

const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
/// Where the one `PT_LOAD` segment of a crafted image is mapped: the file's offset 0 is at this address.
const LOAD_ADDRESS: u64 = 0x40_0000;

/// ELF64, little-endian, with no section headers, as a stripped image has: a `PT_LOAD` segment that maps the
/// whole file, and a `PT_DYNAMIC` segment holding one string entry per `(tag, value)` plus `DT_STRTAB` and
/// `DT_STRSZ`. No entries gives an image with no `PT_DYNAMIC`.
pub fn elf(entries: &[(u64, &str)]) -> Vec<u8> {
    elf_image(entries, LOAD_ADDRESS, None)
}

/// [`elf`] with a `PT_INTERP` segment naming `interpreter`.
pub fn elf_with_interpreter(entries: &[(u64, &str)], interpreter: &str) -> Vec<u8> {
    elf_image(entries, LOAD_ADDRESS, Some(interpreter))
}

/// [`elf`], but `DT_STRTAB` points outside the file's one `PT_LOAD` segment, so the strings cannot be read.
pub fn elf_with_unmapped_strtab(entries: &[(u64, &str)]) -> Vec<u8> {
    elf_image(entries, LOAD_ADDRESS + 0x1000_0000, None)
}

fn elf_image(entries: &[(u64, &str)], base: u64, interpreter: Option<&str>) -> Vec<u8> {
    let mut dynstr = vec![0u8];
    let mut offsets = Vec::new();
    for (_, value) in entries {
        offsets.push(dynstr.len() as u64);
        dynstr.extend_from_slice(value.as_bytes());
        dynstr.push(0);
    }
    let have_dynamic = !entries.is_empty();
    let phnum: u16 = match (have_dynamic, interpreter.is_some()) {
        (false, false) => 0,
        (true, false) | (false, true) => 2,
        (true, true) => 3,
    };
    let interp_off = 64 + 56 * phnum as usize;
    let mut interp = interpreter.map(|name| name.as_bytes().to_vec()).unwrap_or_default();
    if interpreter.is_some() {
        interp.push(0);
    }
    let dynstr_off = interp_off + interp.len();
    let dynamic_off = (dynstr_off + dynstr.len()).next_multiple_of(8);

    let mut dynamic = Vec::new();
    let mut entry = |tag: u64, value: u64| {
        dynamic.extend_from_slice(&tag.to_le_bytes());
        dynamic.extend_from_slice(&value.to_le_bytes());
    };
    for ((tag, _), off) in entries.iter().zip(&offsets) {
        entry(*tag, *off);
    }
    entry(DT_STRTAB, base + dynstr_off as u64);
    entry(DT_STRSZ, dynstr.len() as u64);
    entry(0, 0); // DT_NULL

    let mut img = vec![0u8; 64];
    img[..4].copy_from_slice(b"ELF");
    img[4] = 2; // ELFCLASS64
    img[5] = 1; // little-endian
    img[6] = 1; // EV_CURRENT
    put(&mut img, 16, &3u16.to_le_bytes()); // ET_DYN
    put(&mut img, 18, &0x3eu16.to_le_bytes()); // x86-64
    put(&mut img, 20, &1u32.to_le_bytes());
    put(&mut img, 32, &64u64.to_le_bytes()); // e_phoff
    put(&mut img, 52, &64u16.to_le_bytes()); // e_ehsize
    put(&mut img, 54, &56u16.to_le_bytes()); // e_phentsize
    put(&mut img, 56, &phnum.to_le_bytes());
    put(&mut img, 58, &64u16.to_le_bytes()); // e_shentsize
    if phnum == 0 {
        return img;
    }
    put(&mut img, interp_off, &interp);
    if have_dynamic {
        put(&mut img, dynstr_off, &dynstr);
        put(&mut img, dynamic_off, &dynamic);
    }
    let len = img.len() as u64;
    let segment = |kind: u32, offset: u64, size: u64| {
        let mut h = [0u8; 56];
        h[0..4].copy_from_slice(&kind.to_le_bytes());
        h[4..8].copy_from_slice(&4u32.to_le_bytes()); // PF_R
        h[8..16].copy_from_slice(&offset.to_le_bytes());
        h[16..24].copy_from_slice(&(LOAD_ADDRESS + offset).to_le_bytes());
        h[32..40].copy_from_slice(&size.to_le_bytes());
        h[40..48].copy_from_slice(&size.to_le_bytes());
        h
    };
    let mut headers = vec![segment(1, 0, len)]; // PT_LOAD
    if interpreter.is_some() {
        headers.push(segment(3, interp_off as u64, interp.len() as u64)); // PT_INTERP
    }
    if have_dynamic {
        headers.push(segment(2, dynamic_off as u64, dynamic.len() as u64)); // PT_DYNAMIC
    }
    for (i, header) in headers.iter().enumerate() {
        put(&mut img, 64 + 56 * i, header);
    }
    img
}
