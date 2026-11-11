#!/usr/bin/env bash
# Validate a release version string and print it back unchanged, or fail.
#
# Accepts three dot-separated non-negative integers with no leading zeros, no
# leading `v`, and no pre-release or build suffix (e.g. `1.2.3`).
#
# `v` is rejected, not stripped: 1.2.3 and v1.2.3 would get different concurrency groups yet name one release.
# Leading zeros are invalid semver, so cargo would never match them. Shared by both release workflows.
set -euo pipefail

if [ "$#" -ne 1 ]; then
	echo "usage: ${0##*/} <version>" >&2
	exit 2
fi

v="$1"
if ! [[ "$v" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
	msg="invalid version '${v}'. Expected three dot-separated numbers with no leading zeros, no leading 'v', and no pre-release or build suffix (e.g. 1.2.3)."
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		echo "::error::${msg}" >&2
	else
		echo "${0##*/}: ${msg}" >&2
	fi
	exit 1
fi

printf '%s\n' "$v"
