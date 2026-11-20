#!/usr/bin/env bash
# Probe, part 2a/2b (build side, Linux): can the linker rustc uses for windows-gnullvm set DependentLoadFlags,
# and does the .CRT$XIAB initializer link under that target's CRT? Programs are run by part2-run.sh on Windows.
set -uo pipefail

repo=$PWD
out=$repo/probe-out/part2
mkdir -p "$out"
target=x86_64-pc-windows-gnullvm

echo "== versions"
rustc -vV
echo "-- rustc's linker for $target:"
rustc --print target-spec-json -Z unstable-options --target $target 2>/dev/null | grep -E '"(linker|linker-flavor|crt-objects-fallback|pre-link-args)"' || RUSTC_BOOTSTRAP=1 rustc --print target-spec-json -Z unstable-options --target $target | grep -E '"linker"|linker-flavor'
for tool in x86_64-w64-mingw32-clang x86_64-w64-mingw32-clang++ ld.lld lld llvm-readobj; do
  if command -v $tool >/dev/null; then echo "-- $tool:"; $tool --version 2>&1 | head -3; else echo "-- $tool: not found"; fi
done
echo "-- llvm-mingw bin:"; ls "$(dirname "$(command -v x86_64-w64-mingw32-clang)")" | tr '\n' ' '; echo
echo "-- the MinGW lld driver's options mentioning load flags (ld.lld -m i386pep --help):"
ld.lld -m i386pep --help 2>&1 | grep -i -E 'dependent|load-flag' || echo "(no match)"
echo "-- lld-link flavor, for contrast (lld-link --help):"
lld-link --help 2>&1 | grep -i -E 'dependentload' || echo "(no match)"

# A plain Rust bin (std), and the planted DLL, for the gnullvm target.
work=$(mktemp -d)
mkdir -p "$work/plain/src"
cat >"$work/plain/Cargo.toml" <<'EOF'
[package]
name = "plain"
version = "0.0.0"
edition = "2021"

[workspace]
EOF
echo 'fn main() { println!("hello"); }' >"$work/plain/src/main.rs"

echo
echo "== 2a: DependentLoadFlags through the linker rustc uses"
try() { # <label> <link-arg...>
  local label=$1; shift
  local flags=""
  for a in "$@"; do flags="$flags -C link-arg=$a"; done
  echo "---- $label: $*"
  if RUSTFLAGS="$flags" cargo build --manifest-path "$work/plain/Cargo.toml" --target $target --target-dir "$work/t-$label" >"$work/$label.log" 2>&1; then
    echo "link OK"
    cp "$work/t-$label/$target/debug/plain.exe" "$out/plain-$label.exe"
    llvm-readobj --coff-load-config "$out/plain-$label.exe" 2>&1 | grep -i -E "DependentLoadFlags|Size:" | head -4
  else
    echo "link FAILED:"; grep -E "error|unknown|unsupported|lld" "$work/$label.log" | cut -c1-300 | head -8
  fi
}
try none
try wl-dashdash -Wl,--dependent-load-flag=0x800
try wl-dash -Wl,-dependent-load-flag=0x800
try wl-slash -Wl,/dependentloadflag:0x800
try wl-slash-eq -Wl,/dependentloadflag=0x800
try wl-slash-upper -Wl,/DEPENDENTLOADFLAG:0x800
try wl-space -Wl,--dependent-load-flag,0x800

echo
echo "== 2b: the .CRT\$XIAB initializer under the gnullvm CRT"
# The real initializer, compiled as bins() does, for the gnullvm target.
rustc --edition 2021 --crate-type lib --crate-name libsearch_guard_pre_main --emit=obj --target $target \
  -C panic=abort -C opt-level=s -C codegen-units=1 -C debuginfo=0 -o "$out/pre_main.o" initializer/pre_main.rs
echo "initializer object: $(stat -c %s "$out/pre_main.o") bytes"
llvm-objdump -h "$out/pre_main.o" 2>/dev/null | grep -E 'CRT|lsguard' || llvm-readobj --sections "$out/pre_main.o" | grep -E 'Name: (\.CRT|\.lsguard)'
x86_64-w64-mingw32-clang++ -O1 -c probe/order.cpp -o "$out/order_cxx.o"

mkdir -p "$work/order/src"
cat >"$work/order/Cargo.toml" <<'EOF'
[package]
name = "order"
version = "0.0.0"
edition = "2021"

[workspace]
EOF
cp probe/order.rs "$work/order/src/main.rs"

DLF=-Wl,--dependent-load-flag=0x800
build_order() { # <label> <extra link args...>
  local label=$1; shift
  local flags="-C target-feature=+crt-static -C link-arg=$out/order_cxx.o"
  for a in "$@"; do flags="$flags -C link-arg=$a"; done
  echo "---- build $label: $*"
  if RUSTFLAGS="$flags" cargo build --manifest-path "$work/order/Cargo.toml" --target $target --target-dir "$work/t-order-$label" >"$work/order-$label.log" 2>&1; then
    cp "$work/t-order-$label/$target/debug/order.exe" "$out/order-$label.exe"
    echo "link OK; imports:"; llvm-readobj --coff-imports "$out/order-$label.exe" | grep -E 'Name: .*\.dll' | sort -u | tr '
' ' '; echo
  else
    echo "link FAILED:"; grep -E "error|undefined|unknown" "$work/order-$label.log" | cut -c1-300 | head -8
  fi
}
build_order plain
build_order guard "$out/pre_main.o"
build_order guard-dlf "$out/pre_main.o" $DLF

for f in order-guard order-guard-dlf; do
  [ -f "$out/$f.exe" ] || continue
  echo "---- $f: sections holding the initializers, and load config"
  llvm-readobj --sections "$out/$f.exe" | grep -E 'Name: (\.CRT|\.lsguard)' | sort | uniq -c
  llvm-readobj --coff-load-config "$out/$f.exe" 2>&1 | grep -i -E "DependentLoadFlags" || echo "(no DependentLoadFlags line)"
done

# The planted DLL (a cdylib) for the Windows job.
cargo build --locked -p planted --target $target --target-dir "$work/t-planted" && cp "$work/t-planted/$target/debug/planted.dll" "$out/planted.dll"

# verify's view of the images.
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
        Err(e) => println!("verify: {e}"),
    }
}
EOF
cargo build --manifest-path "$work/checker/Cargo.toml" --target-dir "$work/checker-target" >"$work/checker-build.log" 2>&1 || { cat "$work/checker-build.log"; }
for f in "$out"/plain-wl-*.exe "$out"/order-*.exe; do
  [ -f "$f" ] || continue
  echo "---- verify $(basename "$f")"
  "$work/checker-target/debug/checker" "$f"
done
exit 0
