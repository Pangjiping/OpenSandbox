<!--
Release notes template (docs/releases/TEMPLATE.md).

Usage: copy this file to docs/releases/X.Y.Z.md, fill it in, remove all
HTML comments, and commit it on the release branch BEFORE triggering
release-umbrella.yml — preflight fails if the file is missing or empty.

Conventions: entries reference PRs as (#NNNN); mark experimental or
unstable items with **[EXPERIMENTAL]** / **[UNSTABLE]**; keep the
section order below (GitHub Release mirrors this file verbatim).
-->

# OpenSandbox X.Y.Z

<!-- One paragraph: the headline of this release and who should upgrade. -->

## Highlights

<!-- 1-3 bullets max. The things a user scanning for 10 seconds must see. -->

-

## What's New

### ✨ Features

<!-- feat:/feat(scope): commits; link PRs as (#NNNN) -->

### 🐛 Bug Fixes

<!-- fix:/fix(scope): commits -->

### ⚠️ Breaking Changes

<!-- BREAKING CHANGE footers or type!:/feat!:/fix!: commits; include the migration path inline -->

- None

### 📦 Misc

<!-- chores, deps, docs, CI -->

## Upgrade & Compatibility

<!-- Everything an operator needs to move from the previous line. -->

- Images: `opensandbox/<component>:release-X.Y.Z` (all three registries)
- Packages: server / CLI / SDKs all at `X.Y.Z`
- Charts: render from this tag (`helm template ./manifests/charts/opensandbox`)
- Kubernetes: supported range vX.Y – vW.Z
- Skew: server ↔ CLI/SDK same line supported; ±1 minor warns

## 👥 Contributors

Thanks to these contributors ❤️

-
