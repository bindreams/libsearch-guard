#!/usr/bin/env bash
# Probe, part 1: does a carriage return in OUT_DIR break a link argument? Unix host, windows-msvc targets.
# Each build links a tiny no_std bin through libsearch_guard::bins(), with the real rust-lld (lld-link flavor).
set -uo pipefail

repo=$PWD
work=$(mktemp -d)
sysroot=$(rustc --print sysroot)
host=$(rustc -vV | sed -n 's/^host: //p')
lld=$sysroot/lib/rustlib/$host/bin/rust-lld
llvm_bin=$sysroot/lib/rustlib/$host/bin
echo "== versions"
rustc -vV
"$lld" -flavor link --version || true
ls "$llvm_bin"

# A linker wrapper that logs what the linker is handed, then runs the real linker.
cat >"$work/lld-link-logged" <<EOF
#!/usr/bin/env bash
log=\$LSG_LINK_LOG
{
  echo "argc=\$#"
  for a in "\$@"; do
    case "\$a" in
      @*) echo "arg: \${a:0:80} (response file)"
          cp "\${a:1}" "\$log.rsp" ;;
      *) echo "arg: \${a:0:100}\$([ \${#a} -gt 100 ] && echo "... (\${#a} bytes)")" ;;
    esac
  done
} >"\$log.args" 2>&1
exec "$lld" "\$@"
EOF
chmod +x "$work/lld-link-logged"

# The probe consumer: a no_std bin that needs no C runtime, built through bins().
mkdir -p "$work/consumer/src"
cat >"$work/consumer/Cargo.toml" <<EOF
[package]
name = "cr"
version = "0.0.0"
edition = "2021"

[build-dependencies]
libsearch-guard = { path = "$repo" }

[profile.dev]
panic = "abort"

[workspace]
EOF
cat >"$work/consumer/build.rs" <<'EOF'
fn main() {
    libsearch_guard::bins();
    println!("cargo:rustc-link-arg-bins=/ENTRY:entry");
    println!("cargo:rustc-link-arg-bins=/SUBSYSTEM:CONSOLE");
    println!("cargo:rerun-if-env-changed=PAD_LEN");
    if let Some(len) = std::env::var_os("PAD_LEN") {
        let len: usize = len.to_str().unwrap().parse().unwrap();
        // One argument larger than Linux's per-argument limit (128 KiB): the linker cannot be spawned with it on the command line.
        println!("cargo:rustc-link-arg-bins=/LIBPATH:/nonexistent/{}", "a".repeat(len));
    }
}
EOF
cat >"$work/consumer/src/main.rs" <<'EOF'
#![no_std]
#![no_main]
use core::ffi::c_void;

#[link(name = "kernel32", kind = "raw-dylib")]
extern "system" {
    fn SetDefaultDllDirectories(directory_flags: u32) -> i32;
    fn GetLastError() -> u32;
    fn GetStdHandle(std_handle: u32) -> *mut c_void;
    fn WriteFile(file: *mut c_void, buffer: *const u8, len: u32, written: *mut u32, overlapped: *mut c_void) -> i32;
    fn OutputDebugStringA(message: *const u8);
    fn GetCurrentProcess() -> *mut c_void;
    fn TerminateProcess(process: *mut c_void, exit_code: u32) -> i32;
    fn ExitProcess(exit_code: u32) -> !;
}

#[no_mangle]
pub extern "C" fn entry() -> ! {
    unsafe {
        if SetDefaultDllDirectories(0x800) == 0 {
            let _ = GetLastError();
            let _ = GetStdHandle(0);
            let _ = WriteFile(core::ptr::null_mut(), core::ptr::null(), 0, core::ptr::null_mut(), core::ptr::null_mut());
            OutputDebugStringA(core::ptr::null());
            let _ = TerminateProcess(GetCurrentProcess(), 1);
        }
        ExitProcess(0)
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}
EOF

# The checker: libsearch_guard::verify on an image.
mkdir -p "$work/checker/src"
cat >"$work/checker/Cargo.toml" <<EOF
[package]
name = "checker"
version = "0.0.0"
edition = "2021"

[dependencies]
libsearch-guard = { path = "$repo" }

[workspace]
EOF
cat >"$work/checker/src/main.rs" <<'EOF'
fn main() {
    let path = std::env::args().nth(1).unwrap();
    match libsearch_guard::verify(&path) {
        Ok(()) => println!("verify: Ok (no violation)"),
        Err(e) => {
            println!("verify: {e}");
            std::process::exit(1);
        }
    }
}
EOF
cargo build --manifest-path "$work/checker/Cargo.toml" --target-dir "$work/checker-target" >"$work/checker-build.log" 2>&1 || { cat "$work/checker-build.log"; exit 1; }
checker=$work/checker-target/debug/checker

fail=0
# The C runtime libraries bins() names as default libraries (libcmt, libvcruntime, ucrt) belong to the Windows SDK /
# Visual C++, which this host has not. lld-link errors on a missing default library, so each is an empty archive:
# the link arguments, the response file and the image are the real ones; no code from those libraries is linked.
stub_libs() { # <triple> <dir>
  mkdir -p "$2"
  echo '#![no_std]' >"$2/empty.rs"
  rustc --edition 2021 --crate-type lib --emit=obj --target "$1" -C panic=abort -o "$2/empty.obj" "$2/empty.rs"
  for l in libcmt libvcruntime ucrt; do ar rcs "$2/$l.lib" "$2/empty.obj"; done
}
# build <label> <triple> <target-dir-path> <pad-len or empty>
build() {
  local label=$1 triple=$2 tdir=$3 pad=$4
  local upper=${triple//-/_}; upper=${upper^^}
  echo
  echo "=================== $label  [$triple]  target dir: $(printf %q "$tdir")  pad: ${pad:-none}"
  rm -rf "$tdir"
  local log="$work/$label.$triple"
  stub_libs "$triple" "$work/stub-$triple"
  (
    export "CARGO_TARGET_${upper}_LINKER=$work/lld-link-logged"
    export RUSTFLAGS="-C linker-flavor=lld-link -C link-arg=/LIBPATH:$work/stub-$triple"
    export LSG_LINK_LOG=$log
    export CARGO_TARGET_DIR=$tdir
    if [ -n "$pad" ]; then export PAD_LEN=$pad; fi
    cargo build --manifest-path "$work/consumer/Cargo.toml" --target "$triple" -vv 2>&1
  ) >"$log.cargo" 2>&1
  local rc=$?
  echo "cargo exit: $rc"
  if [ $rc -ne 0 ]; then
    grep -E "^(error|warning: unused)|error:|lld-link|undefined|could not|cannot" "$log.cargo" | head -20
    echo "---- last 30 lines of cargo output"; tail -30 "$log.cargo" | cut -c1-300
    fail=1
  fi
  echo "-- cargo's view of the link argument that carries OUT_DIR (cat -A shows CR as ^M):"
  grep -a "rustc-link-arg-bins=.*libsearch_guard_pre_main" "$log.cargo" | head -2 | cat -A | cut -c1-260
  echo "-- linker argv (from wrapper):"; head -8 "$log.args" 2>/dev/null | cut -c1-160; echo "   ... total $(wc -l <"$log.args" 2>/dev/null) lines"
  if grep -q "(response file)" "$log.args" 2>/dev/null; then
    echo "-- response file used. Encoding:"; file "$log.rsp" || true
    echo "-- response file, decoded; lines that mention libsearch_guard_pre_main (cat -A shows CR as ^M):"
    { iconv -f UTF-16 -t UTF-8 "$log.rsp" 2>/dev/null || cat "$log.rsp"; } | grep -a "libsearch_guard_pre_main" | cat -A | cut -c1-260
  else
    echo "-- no response file: arguments passed directly"
  fi
  local exe
  exe=$(find "$tdir/$triple/debug" -maxdepth 1 -name 'cr.exe' | head -1)
  if [ -z "$exe" ]; then echo "no image produced"; fail=1; return; fi
  echo "-- image: $(basename "$exe") $(stat -c %s "$exe") bytes"
  "$checker" "$exe" || fail=1
  cp "$exe" "$work/$label.$triple.exe"
}

targets="x86_64-pc-windows-msvc i686-pc-windows-msvc aarch64-pc-windows-msvc arm64ec-pc-windows-msvc"
for t in $targets; do
  build control-short "$t" "$work/plain-short" ""
  build control-long "$t" "$work/plain-long" 140000
  build cr-short "$t" "$work/with"$'\r'"cr-short" ""
  build cr-long "$t" "$work/with"$'\r'"cr-long" 140000
  # The CR image against the control: same sections, imports, load config?
  for kind in short long; do
    if [ -f "$work/control-$kind.$t.exe" ] && [ -f "$work/cr-$kind.$t.exe" ]; then
      for f in control cr; do
        python3 - "$work/$f-$kind.$t.exe" >"$work/$f-$kind.$t.sum" <<'PY'
import sys, struct
d = open(sys.argv[1], 'rb').read()
pe = struct.unpack_from('<I', d, 0x3c)[0]
nsec = struct.unpack_from('<H', d, pe + 6)[0]
opt = struct.unpack_from('<H', d, pe + 20)[0]
magic = struct.unpack_from('<H', d, pe + 24)[0]
secs = pe + 24 + opt
names = []
for i in range(nsec):
    o = secs + 40 * i
    names.append((d[o:o+8].rstrip(b'\0').decode(), struct.unpack_from('<I', d, o + 8)[0]))
print('machine', hex(struct.unpack_from('<H', d, pe + 4)[0]), 'magic', hex(magic))
print('sections', names)
import re
print('imports', sorted({m.decode() for m in re.findall(rb'[A-Za-z0-9_.-]+\.dll', d)}))
PY
      done
      if diff -q "$work/control-$kind.$t.sum" "$work/cr-$kind.$t.sum" >/dev/null; then
        echo ">>> $t $kind: CR image equals control (machine, sections+sizes, imports)"
      else
        echo ">>> $t $kind: CR image DIFFERS from control"; diff "$work/control-$kind.$t.sum" "$work/cr-$kind.$t.sum"; fail=1
      fi
      cat "$work/cr-$kind.$t.sum"
    fi
  done
done

echo
echo "overall: fail=$fail"
mkdir -p probe-out && cp "$work"/*.args "$work"/*.cargo probe-out/ 2>/dev/null || true
exit 0
