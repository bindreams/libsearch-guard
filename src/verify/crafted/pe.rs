//! Crafted PE images.

use super::put;

/// What a crafted PE32+ ([`pe`]) or PE32 ([`pe32`]) image should contain.
pub struct Pe<'a> {
    /// DLLs in the import directory. `"dll"` imports one function, `f`, from it; `"dll!function"` imports that
    /// function.
    pub imports: &'a [&'a str],
    /// DLLs in the delay-load import directory, spelled like `imports`.
    pub delay_imports: &'a [&'a str],
    /// `None`: no load config directory. `Some((flags, size))`: a directory of `size` bytes with these flags;
    /// a `size` too small to reach the field omits it.
    pub load_config: Option<(u16, u32)>,
}

/// A 64-bit image: PE32+, x86-64.
pub fn pe(spec: &Pe) -> Vec<u8> {
    pe_image(spec, Bits::B64)
}

/// A 32-bit image: PE32, x86.
pub fn pe32(spec: &Pe) -> Vec<u8> {
    pe_image(spec, Bits::B32)
}

#[derive(Clone, Copy, PartialEq)]
enum Bits {
    B32,
    B64,
}

/// Where `DependentLoadFlags` is in the load config directory, from the `IMAGE_LOAD_CONFIG_DIRECTORY` layouts in
/// winnt.h: after `CSDVersion`, at 54 in the 32-bit directory and 78 in the 64-bit one. Written out, and not
/// taken from the `object` crate, so a wrong offset there fails a test.
fn dependent_load_flags_at(bits: Bits) -> usize {
    match bits {
        Bits::B32 => 0x36,
        Bits::B64 => 0x4e,
    }
}

fn pe_image(spec: &Pe, bits: Bits) -> Vec<u8> {
    const SECTION_RVA: u32 = 0x1000;
    const SECTION_FILE: usize = 0x200;
    let thunk_size = if bits == Bits::B64 { 8 } else { 4 };

    // Section contents, laid out at increasing offsets from SECTION_RVA.
    let mut sec: Vec<u8> = Vec::new();
    let descriptors_at = sec.len();
    sec.resize((spec.imports.len() + 1) * 20, 0); // import descriptors + null terminator
    let mut descriptors = Vec::new();
    for import in spec.imports {
        let (dll, function) = import.split_once('!').unwrap_or((import, "f"));
        let name_rva = SECTION_RVA + sec.len() as u32;
        sec.extend_from_slice(dll.as_bytes());
        sec.push(0);
        sec.resize(sec.len().next_multiple_of(8), 0);
        let hint_rva = SECTION_RVA + sec.len() as u32;
        sec.extend_from_slice(&[0, 0]); // hint 0
        sec.extend_from_slice(function.as_bytes());
        sec.push(0);
        sec.resize(sec.len().next_multiple_of(8), 0);
        let thunk_rva = SECTION_RVA + sec.len() as u32;
        sec.extend_from_slice(&(hint_rva as u64).to_le_bytes()[..thunk_size]);
        sec.extend_from_slice(&[0u8; 8][..thunk_size]);
        descriptors.push((thunk_rva, name_rva));
    }
    for (i, (thunk_rva, name_rva)) in descriptors.iter().enumerate() {
        let at = descriptors_at + i * 20;
        put(&mut sec, at, &thunk_rva.to_le_bytes()); // OriginalFirstThunk
        put(&mut sec, at + 12, &name_rva.to_le_bytes());
        put(&mut sec, at + 16, &thunk_rva.to_le_bytes()); // FirstThunk
    }
    let import_dir = (
        SECTION_RVA + descriptors_at as u32,
        ((spec.imports.len() + 1) * 20) as u32,
    );

    let mut delay_dir = (0u32, 0u32);
    if !spec.delay_imports.is_empty() {
        sec.resize(sec.len().next_multiple_of(8), 0);
        let descriptors_at = sec.len();
        sec.resize(descriptors_at + (spec.delay_imports.len() + 1) * 32, 0); // descriptors + null terminator
        for (i, import) in spec.delay_imports.iter().enumerate() {
            let (dll, function) = import.split_once('!').unwrap_or((import, "f"));
            let name_rva = SECTION_RVA + sec.len() as u32;
            sec.extend_from_slice(dll.as_bytes());
            sec.push(0);
            sec.resize(sec.len().next_multiple_of(8), 0);
            let hint_rva = SECTION_RVA + sec.len() as u32;
            sec.extend_from_slice(&[0, 0]); // hint 0
            sec.extend_from_slice(function.as_bytes());
            sec.push(0);
            sec.resize(sec.len().next_multiple_of(8), 0);
            let thunk_rva = SECTION_RVA + sec.len() as u32;
            sec.extend_from_slice(&(hint_rva as u64).to_le_bytes()[..thunk_size]);
            sec.extend_from_slice(&[0u8; 8][..thunk_size]);
            let at = descriptors_at + i * 32;
            put(&mut sec, at, &1u32.to_le_bytes()); // IMAGE_DELAYLOAD_RVA_BASED
            put(&mut sec, at + 4, &name_rva.to_le_bytes());
            put(&mut sec, at + 12, &thunk_rva.to_le_bytes()); // import address table
            put(&mut sec, at + 16, &thunk_rva.to_le_bytes()); // import name table
        }
        delay_dir = (
            SECTION_RVA + descriptors_at as u32,
            ((spec.delay_imports.len() + 1) * 32) as u32,
        );
    }

    let mut load_dir = (0u32, 0u32);
    if let Some((flags, size)) = spec.load_config {
        sec.resize(sec.len().next_multiple_of(8), 0);
        let at = sec.len();
        let mut config = vec![0u8; (size as usize).max(dependent_load_flags_at(bits) + 2)];
        config[..4].copy_from_slice(&size.to_le_bytes());
        let flags_at = dependent_load_flags_at(bits);
        config[flags_at..flags_at + 2].copy_from_slice(&flags.to_le_bytes());
        config.truncate(size as usize);
        sec.extend_from_slice(&config);
        load_dir = (SECTION_RVA + at as u32, size);
    }
    let section_size = sec.len().next_multiple_of(0x200);
    sec.resize(section_size, 0);

    let mut img = vec![0u8; 0x40];
    img[..2].copy_from_slice(b"MZ");
    img[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    img.extend_from_slice(b"PE\0\0");
    // COFF header.
    let (machine, optional_size, characteristics) = match bits {
        Bits::B64 => (0x8664u16, 240u16, 0x0022u16), // x86-64; executable, large-address-aware
        Bits::B32 => (0x014cu16, 224u16, 0x0102u16), // x86; executable, 32-bit machine
    };
    img.extend_from_slice(&machine.to_le_bytes());
    img.extend_from_slice(&1u16.to_le_bytes()); // one section
    img.extend_from_slice(&[0u8; 12]); // timestamp, symbol table, symbol count
    img.extend_from_slice(&optional_size.to_le_bytes());
    img.extend_from_slice(&characteristics.to_le_bytes());
    // Optional header. PE32 has no 64-bit `ImageBase` and has `BaseOfData`, so what follows it moves by 4.
    let mut opt = vec![0u8; optional_size as usize];
    let (magic, data_dirs_at) = match bits {
        Bits::B64 => (0x20bu16, 112),
        Bits::B32 => (0x10bu16, 96),
    };
    opt[..2].copy_from_slice(&magic.to_le_bytes());
    match bits {
        Bits::B64 => opt[24..32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()), // ImageBase
        Bits::B32 => opt[28..32].copy_from_slice(&0x40_0000u32.to_le_bytes()),
    }
    opt[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    opt[36..40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    opt[56..60].copy_from_slice(&(SECTION_RVA + section_size as u32).to_le_bytes()); // SizeOfImage
    opt[60..64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    opt[68..70].copy_from_slice(&3u16.to_le_bytes()); // console subsystem
    opt[data_dirs_at - 4..data_dirs_at].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let dir = |opt: &mut [u8], index: usize, (rva, size): (u32, u32)| {
        opt[data_dirs_at + index * 8..data_dirs_at + index * 8 + 4].copy_from_slice(&rva.to_le_bytes());
        opt[data_dirs_at + index * 8 + 4..data_dirs_at + index * 8 + 8].copy_from_slice(&size.to_le_bytes());
    };
    dir(&mut opt, 1, import_dir);
    dir(&mut opt, 10, load_dir);
    dir(&mut opt, 13, delay_dir);
    img.extend_from_slice(&opt);
    // Section header.
    let mut header = [0u8; 40];
    header[..6].copy_from_slice(b".rdata");
    header[8..12].copy_from_slice(&(section_size as u32).to_le_bytes()); // VirtualSize
    header[12..16].copy_from_slice(&SECTION_RVA.to_le_bytes());
    header[16..20].copy_from_slice(&(section_size as u32).to_le_bytes()); // SizeOfRawData
    header[20..24].copy_from_slice(&(SECTION_FILE as u32).to_le_bytes());
    header[36..40].copy_from_slice(&0x4000_0040u32.to_le_bytes()); // readable initialized data
    img.extend_from_slice(&header);
    img.resize(SECTION_FILE, 0);
    img.extend_from_slice(&sec);
    img
}
