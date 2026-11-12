#!/usr/bin/env bash
# Assert what `libsearch_guard::bins()` does on a Windows target it cannot
# harden (windows-gnu, windows-gnullvm): the linker rejects every `[[bin]]`
# with an error that names the problem, and the library, the examples and a
# package that only depends on it still build. Needs that target's linker.
#
# Builds the `probe` fixture, which calls `bins()` when
# LIBSEARCH_GUARD_HARDEN_PROBE is set. Two target directories, because build
# scripts do not rerun when that variable changes.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: ${0##*/} <target>" >&2
	exit 2
fi

target=$1
marker=libsearch-guard-cannot-harden-this-target-see-README
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
# A path written into Cargo.toml is read by cargo, not by bash: under Git Bash on Windows it needs the
# Windows form.
if command -v cygpath >/dev/null; then
	repo_manifest_path=$(cygpath -m "$repo")
else
	repo_manifest_path=$repo
fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# Runs a build that must fail on the missing marker input. Matches the linker's error line, not the marker alone:
# rustc prints the whole link command on any link failure.
#   gnu (gcc, whose GNU ld reports it): "ld: cannot find <path>/<marker>: No such file or directory"
#   gnullvm (clang, which checks its inputs itself): "clang: error: no such file or directory: '<path>/<marker>'"
# Fixed strings around the marker, so the path may hold any character.
expect_marker_failure() {
	local output
	if output=$("$@" 2>&1); then
		echo "::error::expected '$*' to fail"
		exit 1
	fi
	if ! grep -Fq -- "$marker: No such file or directory" < <(grep -F -- "cannot find " <<<"$output" || true) &&
		! grep -Fq -- "$marker'" < <(grep -F -- "no such file or directory: '" <<<"$output" || true); then
		echo "::error::'$*' failed without the linker reporting the missing $marker:"
		echo "$output"
		exit 1
	fi
	echo "ok (failed, linker names the problem): $*"
}

cd "$repo"

echo "control: without bins(), every target builds"
cargo build -p probe --bins --examples --tests --target "$target" --target-dir "$work/plain"

export LIBSEARCH_GUARD_HARDEN_PROBE=1

echo "the library and the examples still build, and the build says the target cannot be hardened"
build_status=0
build_output=$(cargo build -p probe --lib --examples --target "$target" --target-dir "$work/hardened" 2>&1) || build_status=$?
echo "$build_output"
if ((build_status != 0)); then
	echo "::error::the hardened library build failed"
	exit 1
fi
if ! grep -Fq -- "cannot be hardened" <<<"$build_output"; then
	echo "::error::the hardened library build did not warn that the target cannot be hardened"
	exit 1
fi

expect_marker_failure cargo build -p probe --bins --target "$target" --target-dir "$work/hardened"
expect_marker_failure cargo test -p probe --bin probe --no-run --target "$target" --target-dir "$work/hardened"
expect_marker_failure cargo test -p probe --test scope --no-run --target "$target" --target-dir "$work/hardened"

echo "a package that only depends on the library still builds and links"
mkdir "$work/consumer"
cat >"$work/consumer/Cargo.toml" <<TOML
[package]
name = "consumer"
version = "0.0.0"
edition = "2021"

[dependencies]
probe = { path = "$repo_manifest_path/fixtures/probe" }

[workspace]
TOML
mkdir "$work/consumer/src"
echo 'fn main() {}' >"$work/consumer/src/main.rs"
cargo build --manifest-path "$work/consumer/Cargo.toml" --target "$target" --target-dir "$work/hardened"
