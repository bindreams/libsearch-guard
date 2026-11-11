//! Byte-level builders for the smallest PE, ELF and Mach-O images the verifier can read, so every rule is
//! tested on every host.

pub fn put(buf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
    if buf.len() < at + bytes.len() {
        buf.resize(at + bytes.len(), 0);
    }
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

// ELF =====

pub const DT_NEEDED: u64 = 1;
pub const DT_RPATH: u64 = 15;
pub const DT_RUNPATH: u64 = 29;

const DT_STRTAB: u64 = 5;
const DT_STRSZ: u64 = 10;
/// Where the one `PT_LOAD` segment of a crafted image is mapped: the file's offset 0 is at this address.
const LOAD_ADDRESS: u64 = 0x40_0000;

/// ELF64, little-endian, with no section headers, as a stripped image has: a `PT_LOAD` segment that maps the
/// whole file, and a `PT_DYNAMIC` segment holding one string entry per `(tag, value)` plus `DT_STRTAB` and
/// `DT_STRSZ`. No entries gives an image with no `PT_DYNAMIC`.
pub fn elf(entries: &[(u64, &str)]) -> Vec<u8> {
    elf_with_strtab_at(entries, LOAD_ADDRESS)
}

/// [`elf`], but `DT_STRTAB` points outside the file's one `PT_LOAD` segment, so the strings cannot be read.
pub fn elf_with_unmapped_strtab(entries: &[(u64, &str)]) -> Vec<u8> {
    elf_with_strtab_at(entries, LOAD_ADDRESS + 0x1000_0000)
}

fn elf_with_strtab_at(entries: &[(u64, &str)], base: u64) -> Vec<u8> {
    let mut dynstr = vec![0u8];
    let mut offsets = Vec::new();
    for (_, value) in entries {
        offsets.push(dynstr.len() as u64);
        dynstr.extend_from_slice(value.as_bytes());
        dynstr.push(0);
    }
    let have_dynamic = !entries.is_empty();
    let phnum: u16 = if have_dynamic { 2 } else { 0 };
    let dynstr_off = 64 + 56 * phnum as usize;
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
    if !have_dynamic {
        return img;
    }
    put(&mut img, dynstr_off, &dynstr);
    put(&mut img, dynamic_off, &dynamic);
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
    put(&mut img, 64, &segment(1, 0, len)); // PT_LOAD
    put(&mut img, 64 + 56, &segment(2, dynamic_off as u64, dynamic.len() as u64)); // PT_DYNAMIC
    img
}

// Mach-O =====

pub const LC_LOAD_DYLIB: u32 = 0x0c;
pub const LC_ID_DYLIB: u32 = 0x0d;
pub const LC_RPATH: u32 = 0x8000_001c;
pub const LC_LOAD_DYLINKER: u32 = 0x0e;
pub const LC_DYLD_ENVIRONMENT: u32 = 0x27;

/// One load command, ready for [`macho`].
pub struct Command(Vec<u8>);

pub fn rpath_command(path: &str) -> Command {
    let mut body = Vec::new();
    body.extend_from_slice(&12u32.to_le_bytes()); // path offset
    body.extend_from_slice(path.as_bytes());
    body.push(0);
    Command(command(LC_RPATH, body))
}

/// `LC_DYLD_ENVIRONMENT` or `LC_LOAD_DYLINKER`: a `dylinker_command` whose string is `value`.
pub fn dylinker_command(cmd: u32, value: &str) -> Command {
    let mut body = Vec::new();
    body.extend_from_slice(&12u32.to_le_bytes()); // string offset
    body.extend_from_slice(value.as_bytes());
    body.push(0);
    Command(command(cmd, body))
}

pub fn dylib_command(cmd: u32, name: &str) -> Command {
    let mut body = Vec::new();
    body.extend_from_slice(&24u32.to_le_bytes()); // name offset
    body.extend_from_slice(&[0u8; 12]); // timestamp, current_version, compatibility_version
    body.extend_from_slice(name.as_bytes());
    body.push(0);
    Command(command(cmd, body))
}

fn command(cmd: u32, mut body: Vec<u8>) -> Vec<u8> {
    let size = (8 + body.len()).next_multiple_of(8);
    body.resize(size - 8, 0);
    let mut out = Vec::new();
    out.extend_from_slice(&cmd.to_le_bytes());
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&body);
    out
}

/// 64-bit little-endian arm64 Mach-O executable with the given load commands.
pub fn macho(commands: &[Command]) -> Vec<u8> {
    let body: Vec<u8> = commands.iter().flat_map(|c| c.0.iter().copied()).collect();
    let mut img = Vec::new();
    img.extend_from_slice(&0xfeed_facfu32.to_le_bytes());
    img.extend_from_slice(&0x0100_000cu32.to_le_bytes()); // CPU_TYPE_ARM64
    img.extend_from_slice(&0u32.to_le_bytes());
    img.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    img.extend_from_slice(&(commands.len() as u32).to_le_bytes());
    img.extend_from_slice(&(body.len() as u32).to_le_bytes());
    img.extend_from_slice(&[0u8; 8]); // flags, reserved
    img.extend_from_slice(&body);
    img
}

/// A universal ("fat") binary holding `slices`.
pub fn macho_fat(slices: &[Vec<u8>]) -> Vec<u8> {
    let mut img = Vec::new();
    img.extend_from_slice(&0xcafe_babeu32.to_be_bytes());
    img.extend_from_slice(&(slices.len() as u32).to_be_bytes());
    let mut offset = (8 + 20 * slices.len()).next_multiple_of(16);
    let mut placed = Vec::new();
    for slice in slices {
        img.extend_from_slice(&0x0100_000cu32.to_be_bytes());
        img.extend_from_slice(&0u32.to_be_bytes());
        img.extend_from_slice(&(offset as u32).to_be_bytes());
        img.extend_from_slice(&(slice.len() as u32).to_be_bytes());
        img.extend_from_slice(&4u32.to_be_bytes()); // align 2^4
        placed.push(offset);
        offset = (offset + slice.len()).next_multiple_of(16);
    }
    for (slice, at) in slices.iter().zip(placed) {
        put(&mut img, at, slice);
    }
    img
}

// PE =====

/// What a crafted PE32+ image should contain.
pub struct Pe<'a> {
    pub imports: &'a [&'a str],
    /// DLLs in the delay-load import directory.
    pub delay_imports: &'a [&'a str],
    /// `None`: no load config directory. `Some((flags, size))`: a directory of `size` bytes with these flags;
    /// a `size` too small to reach the field omits it.
    pub load_config: Option<(u16, u32)>,
}

pub fn pe(spec: &Pe) -> Vec<u8> {
    use object::pe::ImageLoadConfigDirectory64;
    const SECTION_RVA: u32 = 0x1000;
    const SECTION_FILE: usize = 0x200;
    let full_size = size_of::<ImageLoadConfigDirectory64>();

    // Section contents, laid out at increasing offsets from SECTION_RVA.
    let mut sec: Vec<u8> = Vec::new();
    let descriptors_at = sec.len();
    sec.resize((spec.imports.len() + 1) * 20, 0); // import descriptors + null terminator
    let mut descriptors = Vec::new();
    for dll in spec.imports {
        let name_rva = SECTION_RVA + sec.len() as u32;
        sec.extend_from_slice(dll.as_bytes());
        sec.push(0);
        sec.resize(sec.len().next_multiple_of(8), 0);
        let hint_rva = SECTION_RVA + sec.len() as u32;
        sec.extend_from_slice(&[0, 0, b'f', 0]); // hint 0, name "f"
        sec.resize(sec.len().next_multiple_of(8), 0);
        let thunk_rva = SECTION_RVA + sec.len() as u32;
        sec.extend_from_slice(&(hint_rva as u64).to_le_bytes());
        sec.extend_from_slice(&0u64.to_le_bytes());
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
        for (i, dll) in spec.delay_imports.iter().enumerate() {
            let name_rva = SECTION_RVA + sec.len() as u32;
            sec.extend_from_slice(dll.as_bytes());
            sec.push(0);
            let at = descriptors_at + i * 32;
            put(&mut sec, at, &1u32.to_le_bytes()); // IMAGE_DELAYLOAD_RVA_BASED
            put(&mut sec, at + 4, &name_rva.to_le_bytes());
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
        let mut config = vec![0u8; full_size];
        config[..4].copy_from_slice(&size.to_le_bytes());
        let flags_at = std::mem::offset_of!(ImageLoadConfigDirectory64, dependent_load_flags);
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
    img.extend_from_slice(&0x8664u16.to_le_bytes()); // x86-64
    img.extend_from_slice(&1u16.to_le_bytes()); // one section
    img.extend_from_slice(&[0u8; 12]); // timestamp, symbol table, symbol count
    img.extend_from_slice(&240u16.to_le_bytes()); // optional header size
    img.extend_from_slice(&0x0022u16.to_le_bytes()); // executable, large-address-aware
                                                     // Optional header (PE32+).
    let mut opt = vec![0u8; 240];
    opt[..2].copy_from_slice(&0x20bu16.to_le_bytes());
    opt[24..32].copy_from_slice(&0x1_4000_0000u64.to_le_bytes()); // ImageBase
    opt[32..36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    opt[36..40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    opt[56..60].copy_from_slice(&(SECTION_RVA + section_size as u32).to_le_bytes()); // SizeOfImage
    opt[60..64].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfHeaders
    opt[68..70].copy_from_slice(&3u16.to_le_bytes()); // console subsystem
    opt[108..112].copy_from_slice(&16u32.to_le_bytes()); // NumberOfRvaAndSizes
    let dir = |opt: &mut [u8], index: usize, (rva, size): (u32, u32)| {
        opt[112 + index * 8..116 + index * 8].copy_from_slice(&rva.to_le_bytes());
        opt[116 + index * 8..120 + index * 8].copy_from_slice(&size.to_le_bytes());
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
