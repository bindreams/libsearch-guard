#!/usr/bin/env bash
# Report a crate's state, at one version, on crates.io: never-published |
# absent | yanked | "published <checksum>". The checksum is crates.io's own
# sha256 of the uploaded `.crate` file, so a caller can compare it against a
# local build's own hash to prove — not assume — that "published" is *this*
# build.
#
# Queries the crate as a whole (`/api/v1/crates/<crate>`), not the per-version
# endpoint: its `versions` array carries every version's `yanked` flag and
# checksum, so one request answers both "does this crate exist at all" and
# "what is this version's state" — a caller that needs both (draft-release.yaml
# does, for every member) needs one request per crate instead of two.
#
# Uses the JSON API rather than the sparse index: the index is CDN-cached for
# 600s and this runs seconds after a publish. The API needs a User-Agent —
# without one it answers 403.
#
# Refuses rather than guesses. A dropped connection, an unexpected status, or
# a 200 whose body cannot be parsed all exit non-zero, because the caller's
# only remedy for a wrong "absent" is `cargo yank`, which spends the version
# slot permanently. Callers must treat a non-zero exit as fatal — `set -e`
# does not see through `$(...)` in a `[` test or an unmatched `case`.
set -euo pipefail

if [ "$#" -ne 2 ]; then
	echo "usage: ${0##*/} <crate> <version>" >&2
	exit 2
fi

crate=$1
version=$2
ua="libsearch-guard-release-pipeline (https://github.com/bindreams/libsearch-guard)"
url="https://crates.io/api/v1/crates/${crate}"

fail() {
	local msg=$1
	if [ "${GITHUB_ACTIONS:-}" = "true" ]; then
		echo "::error::${msg}" >&2
	else
		echo "${0##*/}: ${msg}" >&2
	fi
	exit 1
}

# --retry-max-time bounds retries by elapsed time (--retry is set high so the count never cuts them short; curl
# honours Retry-After). --max-time bounds one attempt. The body goes to a file so a retry overwrites it and stdout
# carries only the final %{http_code}. `code=$(...) || {` keeps curl's exit status in $?; `if !` would not. -S keeps
# curl's error line.
tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
code=$(curl -sSL -A "$ua" -o "$tmp" -w '%{http_code}' --retry 1000 --retry-max-time 30 --max-time 45 "$url") || {
	rc=$?
	# curl writes literal `000` for %{http_code} when no response arrived at
	# all (e.g. DNS failure, connection refused) — that is the absence of a
	# code, not a code, so it is excluded here rather than reported as one.
	if [[ "$code" =~ ^[0-9]{3}$ ]] && [ "$code" != 000 ]; then
		fail "curl exit $rc contacting crates.io for ${crate} (last HTTP status seen: $code) — refusing to guess its state"
	else
		fail "curl exit $rc contacting crates.io for ${crate} — refusing to guess its state"
	fi
}
body=$(cat "$tmp")

if [ "$code" = 404 ]; then
	echo never-published
	exit 0
fi

if [ "$code" != 200 ]; then
	fail "unexpected HTTP $code from crates.io for ${crate} — refusing to guess its state"
fi

# `versions` must actually be an array before it is indexed below — an HTML
# error page or an `{"errors": [...]}` body would otherwise read as "no
# matching version" (i.e. absent) instead of refusing.
kind=$(printf '%s' "$body" | jq -er '.versions | type') || fail "unreadable crates.io response for ${crate} — refusing to guess its state"
if [ "$kind" != array ]; then
	fail "unreadable crates.io response for ${crate}: '.versions' is ${kind}, not an array — refusing to guess its state"
fi

# crates.io keeps `+meta` in `.num` and a `1.2.3+a` still occupies the 1.2.3 slot: match on the core to find it,
# then require exact equality.
matches=$(printf '%s' "$body" | jq -c --arg v "$version" '[.versions[] | select((.num | split("+")[0]) == $v)]') || fail "unreadable crates.io response for ${crate} — refusing to guess its state"
match_count=$(printf '%s' "$matches" | jq -er 'length') || fail "unreadable crates.io response for ${crate} — refusing to guess its state"
if [ "$match_count" -eq 0 ]; then
	echo absent
	exit 0
fi
if [ "$match_count" -gt 1 ]; then
	fail "crates.io has ${match_count} versions of ${crate} whose version core matches ${version} (differing only in build metadata) — refusing to guess which one, if any, is ${version} exactly."
fi

entry=$(printf '%s' "$matches" | jq -c '.[0]') || fail "unreadable crates.io response for ${crate} — refusing to guess its state"
num=$(printf '%s' "$entry" | jq -er '.num') || fail "unreadable version entry for ${crate} ${version} — refusing to guess its state"
if [ "$num" != "$version" ]; then
	fail "crates.io has ${crate} ${num}, whose version core matches ${version} but carries build metadata — refusing to treat that as ${version} exactly."
fi

yanked=$(printf '%s' "$entry" | jq -er '.yanked | tostring') || fail "unreadable version entry for ${crate} ${version} — refusing to guess its state"
case "$yanked" in
	true) echo yanked ;;
	false)
		checksum=$(printf '%s' "$entry" | jq -er '.checksum') || fail "unreadable checksum for ${crate} ${version} — refusing to guess its state"
		echo "published $checksum"
		;;
	*) fail "unexpected .yanked='$yanked' for ${crate} ${version}" ;;
esac
