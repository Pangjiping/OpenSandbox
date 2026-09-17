---
title: Release Automation
description: How OpenSandbox releases work — one umbrella release, one tag, every artifact.
---

# Release Automation

OpenSandbox ships as a **unified umbrella release** (OSEP-0016): every
artifact of a release — platform images, Helm charts (in-repo), CLI, and
all SDKs — carries the same `X.Y.Z`, driven by a single workflow.
Per-component and per-SDK release entry points have been removed; the
umbrella is the only release path. See
[Versioning](/community/versioning) for naming and cadence.

## Release Preparation (manual, on the release branch)

```bash
# 1. one-command bump: chart versions, image references, SDK versions,
#    and dependency ranges rewritten to the target version in one commit
manifests/release/create-umbrella-release.sh --version 1.1.0 --bump-only

# 2. hand-author the release notes (copy docs/releases/TEMPLATE.md),
#    then push
cp docs/releases/TEMPLATE.md docs/releases/1.1.0.md
$EDITOR docs/releases/1.1.0.md
git push
```

## Release Execution (workflow)

Dispatch `.github/workflows/release-umbrella.yml`
(`dry_run=false`, `version`, `channel`, `release_branch`). A release
approver other than the triggerer must approve the `release`
environment. The workflow then runs:

| Stage | What happens |
|---|---|
| preflight | commit reachability + notes presence (`docs/releases/<version>.md`) |
| scan | version-consistency scan (release-blocking) |
| build | 13 images pushed to staging tags; all packages built and held |
| BOM | digests pinned into `docs/releases/<version>.yaml`, committed as `C_bom` |
| publish | images promoted `staging → release-X.Y.Z` (same digest); packages published in verify-then-continue order (PyPI → npm → NuGet → Maven Central last) |
| tag | `release-X.Y.Z` + `sdks/sandbox/go/vX.Y.Z` minted on `C_bom`, GitHub Release created with the notes and BOM |

Any failure before the tag step leaves no trace consumers can resolve;
the weekly scheduled dry-run (`dry_run=true`) keeps the fan-out healthy
between release windows.

## Release Artifacts

- `docs/releases/<version>.yaml` — BOM, authoritative for image digests
- `docs/releases/<version>.md` — hand-authored release notes (mirrored
  to the GitHub Release)
- container images: `opensandbox/<component>:release-X.Y.Z` on Docker
  Hub, GHCR, and ACR
- packages: PyPI (server, CLI, 3 SDKs), npm (2), Maven Central (5
  Kotlin/JVM coordinates), NuGet (2) — all at the umbrella version
- Helm charts: **not published**; they ship in-repo at the release tag

## Legacy Releases

Historical per-component tags (`server/v0.2.3`, `docker/execd/v1.1.0`,
…) are frozen and keep resolving forever. Verification instructions for
those older artifacts (and their workflow identities) are in
[Release Verification](/community/release-verification).
