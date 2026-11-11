#!/usr/bin/env bash
# Print the workspace's publishable member names, one per line — crates whose
# manifest does not set `publish = false`.
#
# `cargo metadata` reports a member's `publish` field as `null` (unrestricted)
# or a non-empty allow-list for anything publishable, both of which satisfy
# `.publish != []`. Only an explicit `publish = false` becomes the empty array
# `.publish == []` that this filter excludes.
#
# No `mapfile`: this is also meant to be run by hand during recovery, and
# macOS ships bash 3.2, which does not have it.
set -euo pipefail

members=$(cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.publish != []) | .name')
if [ -z "$members" ]; then
	msg="no publishable workspace members found. Expected at least one."
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		echo "::error::${msg}" >&2
	else
		echo "${0##*/}: ${msg}" >&2
	fi
	exit 1
fi

printf '%s\n' "$members"
