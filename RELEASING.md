# Releasing siphon-rs

This document records the release conventions for the siphon-rs workspace. The
first release cut under these rules was `v2026.08.19`.

## The two-layer versioning model

siphon-rs deliberately separates two things that single-crate projects collapse
into one:

1. **Release tags are CalVer** (`v2026.08.19`). A tag names a *snapshot of the
   whole repository*. An aggregate of 18 crates cannot make a single honest
   compatibility promise (one release may break sip-uas while sip-core gets a
   patch fix), so the tag deliberately doesn't try — it's a pinnable,
   changelog-aligned name for a commit.
2. **Crate versions are SemVer** (`sip-uac = 0.5.0`). Compatibility lives at
   the crate level, and each crate's `Cargo.toml` version is where that signal
   is kept honest.

Keep the layers distinct. Do **not** copy the CalVer date into crate versions —
that would erase the per-crate compatibility signal — and do not invent a
workspace-wide SemVer number, since it would be meaningless for the same reason.

## Tag format

- One annotated tag per release: `vYYYY.MM.DD` (e.g. `v2026.08.19`), matching
  the changelog section heading for that release.
- **Same-day counter**: if a second release must ship on the same day (e.g. a
  hotfix right after a deployment), suffix a counter starting at `.1`:
  `v2026.08.19.1`, `v2026.08.19.2`, … The un-suffixed tag is implicitly the
  day's first release.
- Tags are **immutable**. Never move or delete a pushed tag; if a tagged
  release is bad, cut a new one.
- The tag message lists every crate's version in the release (see
  `git tag -n99 v2026.08.19` for the template).

## Crate version bump conventions

All crates are pre-1.0, so per the Cargo interpretation of SemVer the middle
digit is the compatibility boundary:

| Change since the crate's last bump | Bump |
|---|---|
| Breaking API change (signature, return type, removed/renamed item, `Result`-ification) | minor (`0.x.0`) |
| New public API, additive (new methods, defaulted trait methods, new config fields) | minor (`0.x.0`) |
| Fixes / behavior corrections only | patch (`0.x.y`) |
| Only fmt drift, clippy chores, or ride-along test edits | no bump |

Notes:

- A return-type change counts as breaking even when existing callers compile
  (e.g. `()` → `bool` used in statement position) — version it as breaking and
  note the source-compatibility in the changelog.
- Internal dependency migrations (e.g. a `rand` major bump) with no public API
  change do not by themselves require a bump; a major bump of a dependency
  whose types appear in public API does.
- Inter-crate dependencies are `path`-only (no version requirements), so
  bumping a crate never requires editing its dependents' manifests.

To audit what changed since a crate's last bump (the repo pre-dates tags, and
tags don't record per-crate bump points):

```bash
# Find the commit that last changed the version line
git log -L '/^version/,+1:crates/<crate>/Cargo.toml' --format='%h %ad %s' --date=short

# List commits touching the crate since then
git log --oneline <bump-commit>..HEAD -- crates/<crate>/src crates/<crate>/Cargo.toml
```

## Changelog

`CHANGELOG.md` follows Keep a Changelog. Ongoing work accumulates under
`## [Unreleased]`; a release converts that section into
`## [YYYY-MM-DD] — workspace release`, which must include:

1. The full list of crate versions in the release (including "unchanged"
   crates).
2. A **Breaking changes** paragraph naming each breaking API change and its
   PR/issue number.
3. The accumulated entries.

A fresh empty `## [Unreleased]` goes above it.

## Release checklist

1. **Audit**: for each crate, determine what landed since its last bump and
   classify per the table above.
2. **Bump** the `version =` lines in the affected `Cargo.toml`s.
3. **Changelog**: backfill any commits missing from `[Unreleased]`, then
   convert it into the dated release section.
4. **Verify**: `cargo check --all` and `cargo test --all` pass; clippy is
   clean on the pinned CI toolchain.
5. **PR** the bump + changelog to `main` and merge it.
6. **Tag** the merge commit: 

   ```bash
   git tag -a vYYYY.MM.DD -m "workspace release YYYY-MM-DD

   <crate version list>" <merge-sha>
   git push origin vYYYY.MM.DD
   ```

   Anything merged to `main` after the changelog PR but before tagging either
   gets a changelog entry first, or an explicit callout in the release notes.
7. **GitHub Release**: `gh release create vYYYY.MM.DD` with the crate version
   table, the breaking-changes summary, and the downstream pinning snippet.
8. **Downstream**: update consumers (siphon-ai, forge-media) when they're
   ready to absorb the release — see below.

## Downstream consumption

Consumers depend on siphon-rs via git dependencies and should pin tags, not
branches:

```toml
sip-uac = { git = "https://github.com/thevoiceguy/siphon-rs", tag = "v2026.08.19" }
```

- **Pin every `sip-*` crate in a consumer to the same tag.** Different refs of
  the same repo are different sources to Cargo, which duplicates shared crates
  (two `sip-core`s) and produces impossible type-mismatch errors. Defining the
  pin once in the consumer's `[workspace.dependencies]` keeps it single-sourced.
- Upgrading = bump the tag, `cargo update`, then work through that release's
  breaking-changes paragraph in the changelog.
- For a consumer that needs a fix without absorbing newer breakage: branch
  from its pinned tag, cherry-pick, and tag the result with the same-day
  counter rule.

## If crates are ever published to crates.io

Per-crate SemVer becomes the real release mechanism: version requirements
replace git pins, per-crate tags (`sip-uac-v0.5.0`) become meaningful, and
tooling like `release-plz`/`cargo-release` can automate bumps. The dated
workspace tags remain valid alongside — nothing above needs to be undone.
