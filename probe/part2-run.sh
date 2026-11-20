#!/usr/bin/env bash
# Probe, part 2b (Windows side): run the order programs built by part2-build.sh. Each runs from a fresh folder
# holding a copy of the exe and one planted DLL per initializer slot, with an empty working directory.
set -uo pipefail
out=$PWD/probe-out/part2
echo "== $(cmd //c ver | tr -d '\r' | tail -1)"
for exe in "$out"/order-*.exe; do
  name=$(basename "$exe" .exe)
  app=$(mktemp -d); work=$(mktemp -d)
  cp "$exe" "$app/order.exe"
  for slot in xiaa xiac xic xct xcu cxx cattr; do cp "$out/planted.dll" "$app/planted-$slot.dll"; done
  echo "---- $name"
  (cd "$work" && "$app/order.exe") 2>&1
  echo "exit code: $?"
  rm -r "$app" "$work"
done
