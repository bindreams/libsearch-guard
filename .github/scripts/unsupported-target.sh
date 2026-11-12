#!/usr/bin/env bash
# Assert what `libsearch_guard::bins()` does on a Windows target it cannot
# harden (windows-gnu, windows-gnullvm): the linker rejects every `[[bin]]`
# with an error that names the problem, and the library, the examples and a
# package that only depends on it still build. Needs that target's linker.
#
# Builds the `probe` fixture, which calls `bins()` when
# LIBSEARCH_GUARD_HARDEN_PROBE is set, in two target directories: build
# scripts do not rerun when that variable changes.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: ${0##*/} <target>" >&2
	exit 2
fi

target=$1
marker=libsearch-guard-cannot-harden-this-target-see-README
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Runs a build that must fail, and requires the marker in its output.
expect_marker_failure() {
	local output
	if output=$("$@" 2>&1); then
		echo "::error::expected '$*' to fail"
		exit 1
	fi
	if ! grep -q -- "$marker" <<<"$output"; then
		echo "::error::'$*' failed without naming $marker:"
		echo "$output"
		exit 1
	fi
	echo "ok (failed, names the problem): $*"
}

cd "$repo"

echo "control: without bins(), every target builds"
cargo build -p probe --bins --examples --tests --target "$target" --target-dir "$work/plain"

export LIBSEARCH_GUARD_HARDEN_PROBE=1

echo "the library and the examples still build"
cargo build -p probe --lib --examples --target "$target" --target-dir "$work/hardened"

expect_marker_failure cargo build -p probe --bins --target "$target" --target-dir "$work/hardened"
expect_marker_failure cargo test -p probe --bin probe --no-run --target "$target" --target-dir "$work/hardened"

echo "a package that only depends on the library still builds and links"
mkdir "$work/consumer"
cat >"$work/consumer/Cargo.toml" <<TOML
[package]
name = "consumer"
version = "0.0.0"
edition = "2021"

[dependencies]
probe = { path = "$repo/fixtures/probe" }

[workspace]
TOML
mkdir "$work/consumer/src"
echo 'fn main() {}' >"$work/consumer/src/main.rs"
cargo build --manifest-path "$work/consumer/Cargo.toml" --target "$target" --target-dir "$work/hardened"
