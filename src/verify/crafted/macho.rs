//! Crafted Mach-O images.

use super::put;

pub const LC_LOAD_DYLIB: u32 = 0x0c;
pub const LC_LAZY_LOAD_DYLIB: u32 = 0x20;
pub const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
pub const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
pub const LC_LOAD_UPWARD_DYLIB: u32 = 0x8000_0023;
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
    macho_image(commands, true)
}

/// 32-bit little-endian x86 Mach-O executable with the given load commands. Its header has no `reserved` field.
pub fn macho32(commands: &[Command]) -> Vec<u8> {
    macho_image(commands, false)
}

fn macho_image(commands: &[Command], is64: bool) -> Vec<u8> {
    let body: Vec<u8> = commands.iter().flat_map(|c| c.0.iter().copied()).collect();
    let mut img = Vec::new();
    let (magic, cpu_type) = if is64 {
        (0xfeed_facfu32, 0x0100_000cu32) // MH_MAGIC_64, CPU_TYPE_ARM64
    } else {
        (0xfeed_faceu32, 7u32) // MH_MAGIC, CPU_TYPE_X86
    };
    img.extend_from_slice(&magic.to_le_bytes());
    img.extend_from_slice(&cpu_type.to_le_bytes());
    img.extend_from_slice(&0u32.to_le_bytes());
    img.extend_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
    img.extend_from_slice(&(commands.len() as u32).to_le_bytes());
    img.extend_from_slice(&(body.len() as u32).to_le_bytes());
    img.extend_from_slice(&[0u8; 4]); // flags
    if is64 {
        img.extend_from_slice(&[0u8; 4]); // reserved
    }
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
