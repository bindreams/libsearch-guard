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
/// Where the first `PT_LOAD` segment of a crafted image is mapped: the file's offset 0 is at this address.
const LOAD_ADDRESS: u64 = 0x40_0000;
/// Where the second `PT_LOAD` segment is mapped, when there is one: it holds the string table.
const SECOND_LOAD_ADDRESS: u64 = 0x60_0000;

/// Which `PT_LOAD` segment maps the string table.
#[derive(Clone, Copy, Default)]
pub enum StringTable {
    /// The one segment that maps the whole file.
    #[default]
    WholeFile,
    /// A second segment, after one that maps only the headers: a reader must look past the first.
    SecondSegment,
    /// None: `DT_STRTAB` points outside every segment, so the strings cannot be read.
    Unmapped,
}

/// What a crafted ELF image contains. The default is ELF64, little-endian, with no section headers, as a
/// stripped image has: a `PT_LOAD` segment that maps the whole file, and a `PT_DYNAMIC` segment.
#[derive(Default)]
pub struct Elf<'a> {
    /// A string entry per `(tag, value)`, then `DT_STRTAB`, `DT_STRSZ` and the terminating `DT_NULL`. With
    /// neither entries nor `after_null` there is no `PT_DYNAMIC`.
    pub entries: &'a [(u64, &'a str)],
    /// String entries after the `DT_NULL`, which the loader never reads.
    pub after_null: &'a [(u64, &'a str)],
    /// A `PT_INTERP` segment naming this program interpreter.
    pub interpreter: Option<&'a str>,
    /// ELF32 (32-bit program headers and dynamic entries) instead of ELF64.
    pub is_32_bit: bool,
    pub is_big_endian: bool,
    pub string_table: StringTable,
}

/// An image with just these entries.
pub fn elf(entries: &[(u64, &str)]) -> Vec<u8> {
    elf_image(&Elf {
        entries,
        ..Elf::default()
    })
}

/// [`elf`] with a `PT_INTERP` segment naming `interpreter`.
pub fn elf_with_interpreter(entries: &[(u64, &str)], interpreter: &str) -> Vec<u8> {
    elf_image(&Elf {
        entries,
        interpreter: Some(interpreter),
        ..Elf::default()
    })
}

/// [`elf`], but `DT_STRTAB` points outside the file's one `PT_LOAD` segment, so the strings cannot be read.
pub fn elf_with_unmapped_strtab(entries: &[(u64, &str)]) -> Vec<u8> {
    elf_image(&Elf {
        entries,
        string_table: StringTable::Unmapped,
        ..Elf::default()
    })
}

pub fn elf_image(spec: &Elf) -> Vec<u8> {
    let big = spec.is_big_endian;
    let word_size = if spec.is_32_bit { 4 } else { 8 };
    let half = |v: u16| if big { v.to_be_bytes() } else { v.to_le_bytes() };
    let word32 = |v: u32| if big { v.to_be_bytes() } else { v.to_le_bytes() };
    // A native word: 4 bytes in ELF32, 8 in ELF64.
    let word = |v: u64| -> Vec<u8> {
        match (spec.is_32_bit, big) {
            (true, true) => (v as u32).to_be_bytes().to_vec(),
            (true, false) => (v as u32).to_le_bytes().to_vec(),
            (false, true) => v.to_be_bytes().to_vec(),
            (false, false) => v.to_le_bytes().to_vec(),
        }
    };
    let ehsize = if spec.is_32_bit { 52 } else { 64 };
    let phentsize = if spec.is_32_bit { 32 } else { 56 };

    let mut dynstr = vec![0u8];
    let mut string_offset = |value: &str| {
        let at = dynstr.len() as u64;
        dynstr.extend_from_slice(value.as_bytes());
        dynstr.push(0);
        at
    };
    let entries: Vec<(u64, u64)> = spec.entries.iter().map(|(tag, v)| (*tag, string_offset(v))).collect();
    let after_null: Vec<(u64, u64)> = spec
        .after_null
        .iter()
        .map(|(tag, v)| (*tag, string_offset(v)))
        .collect();

    let have_dynamic = !spec.entries.is_empty() || !spec.after_null.is_empty();
    let second_segment = matches!(spec.string_table, StringTable::SecondSegment);
    let phnum = if have_dynamic || spec.interpreter.is_some() {
        1 + usize::from(second_segment) + usize::from(spec.interpreter.is_some()) + usize::from(have_dynamic)
    } else {
        0
    };

    let interp_off = ehsize + phentsize * phnum;
    let mut interp = spec
        .interpreter
        .map(|name| name.as_bytes().to_vec())
        .unwrap_or_default();
    if spec.interpreter.is_some() {
        interp.push(0);
    }
    let dynstr_off = interp_off + interp.len();
    let dynamic_off = (dynstr_off + dynstr.len()).next_multiple_of(8);
    let strtab_address = match spec.string_table {
        StringTable::WholeFile => LOAD_ADDRESS + dynstr_off as u64,
        StringTable::SecondSegment => SECOND_LOAD_ADDRESS,
        StringTable::Unmapped => LOAD_ADDRESS + 0x1000_0000 + dynstr_off as u64,
    };

    let mut dynamic = Vec::new();
    let mut entry = |tag: u64, value: u64| {
        dynamic.extend_from_slice(&word(tag));
        dynamic.extend_from_slice(&word(value));
    };
    for (tag, value) in &entries {
        entry(*tag, *value);
    }
    entry(DT_STRTAB, strtab_address);
    entry(DT_STRSZ, dynstr.len() as u64);
    entry(0, 0); // DT_NULL
    for (tag, value) in &after_null {
        entry(*tag, *value);
    }
    entry(0, 0);

    let mut img = vec![0u8; ehsize];
    img[..4].copy_from_slice(b"\x7fELF");
    img[4] = if spec.is_32_bit { 1 } else { 2 }; // ELFCLASS32, ELFCLASS64
    img[5] = if big { 2 } else { 1 }; // ELFDATA2MSB, ELFDATA2LSB
    img[6] = 1; // EV_CURRENT
    put(&mut img, 16, &half(3)); // ET_DYN
    put(&mut img, 18, &half(if spec.is_32_bit { 3 } else { 0x3e })); // x86 or x86-64
    put(&mut img, 20, &word32(1));
    // `e_entry`, `e_phoff` and `e_shoff` are a native word each, so what follows them moves between ELF32 and ELF64.
    put(&mut img, 24 + word_size, &word(ehsize as u64)); // e_phoff
    let after_offsets = 24 + 3 * word_size;
    put(&mut img, after_offsets + 4, &half(ehsize as u16)); // e_ehsize
    put(&mut img, after_offsets + 6, &half(phentsize as u16)); // e_phentsize
    put(&mut img, after_offsets + 8, &half(phnum as u16)); // e_phnum
    put(
        &mut img,
        after_offsets + 10,
        &half(if spec.is_32_bit { 40 } else { 64 }),
    ); // e_shentsize
    if phnum == 0 {
        return img;
    }
    put(&mut img, interp_off, &interp);
    put(&mut img, dynstr_off, &dynstr);
    put(&mut img, dynamic_off, &dynamic);
    let len = img.len() as u64;
    let segment = |kind: u32, address: u64, offset: u64, size: u64| {
        let (flags, align) = (word32(4), word(0x1000)); // PF_R
        let mut h = Vec::new();
        h.extend_from_slice(&word32(kind));
        if !spec.is_32_bit {
            h.extend_from_slice(&flags);
        }
        h.extend_from_slice(&word(offset));
        h.extend_from_slice(&word(address));
        h.extend_from_slice(&word(address)); // p_paddr
        h.extend_from_slice(&word(size));
        h.extend_from_slice(&word(size));
        if spec.is_32_bit {
            h.extend_from_slice(&flags);
        }
        h.extend_from_slice(&align);
        h
    };
    let mut headers = Vec::new();
    if second_segment {
        headers.push(segment(1, LOAD_ADDRESS, 0, dynstr_off as u64)); // PT_LOAD: the headers only
        headers.push(segment(1, SECOND_LOAD_ADDRESS, dynstr_off as u64, dynstr.len() as u64));
    // PT_LOAD: strings
    } else {
        headers.push(segment(1, LOAD_ADDRESS, 0, len)); // PT_LOAD
    }
    if spec.interpreter.is_some() {
        let at = interp_off as u64;
        headers.push(segment(3, LOAD_ADDRESS + at, at, interp.len() as u64)); // PT_INTERP
    }
    if have_dynamic {
        let at = dynamic_off as u64;
        headers.push(segment(2, LOAD_ADDRESS + at, at, dynamic.len() as u64)); // PT_DYNAMIC
    }
    for (i, header) in headers.iter().enumerate() {
        put(&mut img, ehsize + phentsize * i, header);
    }
    img
}
