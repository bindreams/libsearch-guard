#!/usr/bin/env bash
# Probe, part 3 (Windows): does LOAD_LIBRARY_SEARCH_APPLICATION_DIR alone load a sidecar from a hardened exe?
set -euo pipefail
export MSYS_NO_PATHCONV=1 MSYS2_ARG_CONV_EXCL='*'
echo "== $(cmd //c ver | tr -d '\r' | tail -1)"
rustc -vV
T=$(cygpath -m "$PWD")/probe-out/p3
mkdir -p "$T"
SEMI=""
for l in libvcruntimed.lib vcruntime.lib vcruntimed.lib libcmtd.lib msvcrt.lib msvcrtd.lib libucrt.lib libucrtd.lib; do SEMI="$SEMI -C link-arg=/NODEFAULTLIB:$l"; done
for l in libcmt.lib libvcruntime.lib ucrt.lib; do SEMI="$SEMI -C link-arg=/DEFAULTLIB:$l"; done
b() { local name=$1 pkg=$2 flags=$3; shift 3
  env "$@" RUSTFLAGS="$flags" cargo build --locked -p "$pkg" --target-dir "$T/$name" >"$T/$name.log" 2>&1 || { cat "$T/$name.log"; exit 1; }; }
b probe-h probe "" LIBSEARCH_GUARD_HARDEN_PROBE=1
b probe-hs probe "-C target-feature=+crt-static" LIBSEARCH_GUARD_HARDEN_PROBE=1
b pl-dyn planted ""
b pl-semi planted "$SEMI"
b pl-static planted "-C target-feature=+crt-static"
cat >"$T/imports.py" <<'PY'
import re,sys
for p in sys.argv[1:]:
    d=open(p,'rb').read()
    names=sorted({m.decode().lower() for m in re.findall(rb'[A-Za-z0-9_\-\.]{3,60}\.dll',d)})
    print(p, [n for n in names if n.startswith(('api-ms','vcruntime','ucrt','msvcp','msvcrt','kernel32'))])
PY
cd "$T"
python -I imports.py pl-dyn/debug/planted.dll pl-semi/debug/planted.dll pl-static/debug/planted.dll probe-h/debug/probe.exe probe-hs/debug/probe.exe
for exe in probe-h probe-hs; do
 for dll in pl-dyn pl-semi pl-static; do
  for mode in app app_system32; do
   app=$(mktemp -d); work=$(mktemp -d)
   cp $exe/debug/probe.exe "$app/probe.exe"; cp $dll/debug/planted.dll "$app/planted.dll"
   set +e; out=$(cd "$work" && "$app/probe.exe" planted.dll $mode 2>&1); rc=$?; set -e
   echo "$exe | $dll | $mode | rc=$rc | $out"
   rm -r "$app" "$work"
  done
 done
done
