# Contributing to libsearch-guard

## Releasing

Releases go through two GitHub Actions workflows, both started by hand. Stage 1 is fully reversible; stage 2 does the irreversible things (publishing to crates.io, creating the tag). Reviewing the draft release between them is the last chance to catch a problem.

### Prerequisites

- `Cargo.toml` already has the release version (`X.Y.Z`) on `main`.
- The GitHub CLI (`gh`) is authenticated for `bindreams/libsearch-guard`.
- The crate has a **trusted publisher** on crates.io: GitHub, owner `bindreams`, repository `libsearch-guard`, workflow `publish-release.yaml`, environment `Deploy`. Stage 2 mints a short-lived token by OIDC and holds no long-lived secret. All four fields are matched exactly, so renaming the workflow file or dropping `environment: Deploy` breaks publishing, and nothing shows it until the irreversible step.
- The `Deploy` environment's deployment branch policy allows only `main`. A trusted-publisher config has no ref field, so this policy is the one place a restriction on the workflow's ref can live. It restricts the dispatch ref only: stage 2's `resolve` job also refuses a draft whose target is not on `main` at or after the floor pinned in `.github/scripts/require-target-on-main.sh`. The trust basis for the published tree, and what it rests on (a default-branch ruleset with linear history and squash-only merges), are in the header of `publish-release.yaml`. Raise the floor only to a later commit on `main`.
- **The first release is manual.** A crate that does not exist on crates.io cannot have a trusted publisher, and stage 1 refuses to create a draft for it. Publish `0.1.0` once by hand with a temporary token that has `publish-new` (`cargo publish --locked`), configure the trusted publisher, confirm it is listed under the crate's Settings, Trusted Publishing, and revoke the token. Nothing automated checks that the publisher is configured.
- **For recovery only:** a personal crates.io token with the `yank` scope.

### Stage 1: Draft Release

```sh
gh workflow run draft-release.yaml -R bindreams/libsearch-guard -f version=X.Y.Z
```

It refuses unless the commit is on `main` (advisory; stage 2 enforces), validates the version, runs the full CI matrix on the release commit, dry-runs `cargo publish`, checks crates.io (the crate exists, the version is **not already taken**, and the manifest version equals the input), and creates a **draft** release pinned to the commit SHA.

Review the draft at `https://github.com/bindreams/libsearch-guard/releases`. Do not publish it by hand; stage 2 does.

### Stage 2: Publish Release

```sh
gh workflow run publish-release.yaml -R bindreams/libsearch-guard -f version=X.Y.Z
```

Three jobs, so no credential shares a job with code that compiles:

- **resolve** (write token, compiles nothing): finds the draft, requires its target to be on `main`, reads the toolchain pin from that commit.
- **build** (read-only token, no environment, no OIDC): packages and verify-builds the crate, and publishes a sha256 manifest.
- **publish** (`Deploy` environment, `id-token: write`, compiles nothing): re-checks the manifest version, re-derives the package with `cargo package --no-verify` and refuses on any hash that differs from the build job's, skips the upload if crates.io already holds this exact build, mints the token, runs `cargo publish --no-verify`, and flips the draft to published, which creates the `vX.Y.Z` tag.

### Toolchain pin

`.github/release-toolchain` holds one exact `X.Y.Z`. Both stages install exactly that toolchain, because different cargo versions can package the same tree into different bytes and stage 2 holds its re-derived archive to the build job's hash. CI's lint and test jobs use the same pin. Bump it in a normal PR (Renovate opens them); a draft must target a commit that contains the file.

### Recovery

**Check the job summary first.** A red run whose summary or log says `RELEASE COMPLETE` is a finished release: the failure came from a post step. Take no action.

Otherwise, find the registry's state with the scripts the workflow uses, from the repository root:

```sh
.github/scripts/crate-state.sh libsearch-guard X.Y.Z
```

- **`published`, no `RELEASE COMPLETE`:** re-run stage 2 with the same version. It checks the checksum matches this tree's build, skips the upload, and finishes the flip. A checksum mismatch means a different build occupies the version: stop and find out which commit it is before doing anything else.
- **`absent`:** the failure was before the upload. If environmental (registry outage, runner failure, a refused ref: dispatch stage 2 from `main`), re-run stage 2. If it is the tree (packaging, the version re-check, crates.io rejecting the content), stage 2 replays it identically: `gh release delete "vX.Y.Z" --yes -R bindreams/libsearch-guard`, push the fix, then re-run stage 1 and stage 2.
- **`yanked`:** the version slot is spent for good; abandon the version (below).
- **"Refusing to publish" from the re-derive step:** a hash mismatch between the build and publish jobs can mean the build job was compromised. Investigate from the first occurrence, before re-running. Nothing was uploaded.

### Abandoning a version

Yank it, then tag the commit by hand (only the final flip creates the tag, and it never ran), delete the draft, bump the manifest to `X.Y.(Z+1)`, fix the cause, and re-run both stages.

```sh
cargo yank libsearch-guard@X.Y.Z
SHA=<the commit printed as "Resolved vX.Y.Z -> <sha>" by the failed run's "Verify draft release exists and resolve commit SHA" step>
git fetch origin && git tag "vX.Y.Z" "$SHA" && git push origin "vX.Y.Z" &&
  gh release delete "vX.Y.Z" --yes -R bindreams/libsearch-guard   # not --cleanup-tag: it would delete the tag just pushed
```

Read `SHA` from the run's log, not from the live draft: the draft can be edited after the run resolved it.

## Workflow conventions

Each job's first step is the checkout that provides what its steps run. A step that runs a `.github/scripts/` script or a local action needs the repo on disk. In stage 2's `resolve` job the `main` check precedes any release-tree checkout, and the `publish` job runs only `../workflow-ref/.github/scripts/` scripts, never the release tree's; review holds those two invariants. Stage 2 cannot be exercised without publishing, so a step there that runs before its checkout fails only in a real release; stage 1 is reversible and can be dispatched to test.
