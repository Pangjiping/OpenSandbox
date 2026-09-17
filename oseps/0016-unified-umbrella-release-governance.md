---
title: Unified Umbrella Release Governance
authors:
  - "@Pangjiping"
creation-date: 2026-07-21
last-updated: 2026-09-17
status: implementing
---

# OSEP-0016: Unified Umbrella Release Governance

<!-- toc -->
- [Summary](#summary)
- [Key Decisions](#key-decisions)
- [Motivation](#motivation)
- [Goals](#goals)
- [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Unified Versioning](#unified-versioning)
  - [Naming Rules](#naming-rules)
  - [Starting Version: `1.1.0` as GA](#starting-version-110-as-ga)
  - [First Umbrella Version of Every Artifact](#first-umbrella-version-of-every-artifact)
  - [Cadence and Support](#cadence-and-support)
- [Design Details](#design-details)
  - [Bill of Materials (BOM)](#bill-of-materials-bom)
  - [Release Workflow](#release-workflow)
  - [Compatibility](#compatibility)
  - [User-facing Surface](#user-facing-surface)
- [Test Plan](#test-plan)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Migration](#migration)
<!-- /toc -->

## Summary

OpenSandbox ships 19+ independently versioned targets (server, component
images, K8s controllers, Helm chart, CLI, five language SDKs). There is no
single "OpenSandbox version" a user can install, audit, or roll back to.

This OSEP unifies release governance: every artifact of an umbrella
release carries the **same `X.Y.Z`**, cut from one release commit, built
by one fan-out workflow, and pinned in a signed BOM. Cadence is one line
every two weeks; only the latest line is supported.

## Key Decisions

| # | Decision | Value |
|---|---|---|
| 1 | First umbrella version (GA) | **`1.1.0`** — `1.0.0` is skipped, see [floor rule](#starting-version-110-as-ga) |
| 2 | Git tag & image tag | **`release-X.Y.Z`** — one identity string for both, e.g. `release-1.1.0` |
| 3 | Package registries (PyPI/npm/Maven/NuGet/Helm) | bare **`X.Y.Z`** |
| 4 | Go SDK tags | companion tags `sdks/sandbox/go/vX.Y.Z`, `sdks/sandbox/go/poolredis/vX.Y.Z` (toolchain-required, same commit) |
| 5 | Cadence / support | line every 2 weeks, **latest-only**, no LTS |
| 6 | Legacy per-component tags | **frozen** at `release-1.1.0-rc.1` — never deleted, never extended |
| 7 | Out of scope | sandbox template images (e.g. `opensandbox/code-interpreter`) version independently |

## Motivation

Latest per-component tags (`server/v0.2.3`, `docker/execd/v1.1.0`,
`docker/egress/v1.1.7`, `helm/opensandbox/0.2.2`,
`java/sandbox/v1.0.19`, `python/sandbox/v0.1.17.dev0`,
`js/sandbox/v0.1.11`, `sdks/sandbox/go/v1.0.5`,
`csharp/sandbox/v0.1.5`) encode no relationship between components:

1. **No platform version** — advisories, docs, and installers must
   enumerate ~10 tags.
2. **Unverified combinations** — no `{server, execd, ingress, …}` set is
   asserted as e2e-tested together.
3. **Opaque client compatibility** — "does python SDK 0.1.17 work with
   server 0.2.3?" is unanswerable from release notes alone.
4. **Drift** — docs, Helm defaults, and examples slip out of sync.
5. **Fragmented release notes** — 6–10 GitHub Releases per month, no
   single "what changed" entry point.

## Goals

- One version on every artifact of every umbrella release.
- One canonical git tag per release, backed by a signed BOM.
- Single-trigger fan-out; partial releases are structurally impossible.
- 2-week cadence, no LTS, latest-only support.
- Start at `1.1.0` and treat it as GA.

## Non-Goals

- No repo restructuring and no package renaming.
- The API/CRD/spec stability contract implied by GA — deferred to a
  follow-up OSEP.
- No per-component hotfix tags after the first umbrella; hotfixes are
  new umbrella snapshots.
- No redesign of per-target build logic; only the release driver changes.

## Proposal

### Unified Versioning

Every artifact publishes at the same semver core `X.Y.Z` from the same
commit. Example at umbrella `1.4.0`:

| Artifact | Identity |
|---|---|
| Platform images | `opensandbox/{server,execd,ingress,egress,image-committer,controller,task-executor}:release-1.4.0` |
| Git tag | `release-1.4.0` (plus Go companion tags, see [Naming Rules](#naming-rules)) |
| Server PyPI / CLI | `opensandbox-server==1.4.0`, `opensandbox-cli==1.4.0` |
| Helm chart | `opensandbox-1.4.0.tgz`, `appVersion: 1.4.0` |
| Python SDKs | `opensandbox`, `opensandbox-code-interpreter`, `opensandbox-mcp` — all `==1.4.0` |
| JS SDKs | `@alibaba-group/opensandbox`, `@alibaba-group/opensandbox-code-interpreter` — both `@1.4.0` |
| Kotlin/JVM | `com.alibaba.opensandbox:{sandbox-bom,sandbox,sandbox-api,sandbox-pool-redis,code-interpreter}:1.4.0` |
| .NET / Go | `Alibaba.OpenSandbox 1.4.0` / `sdks/sandbox/go v1.4.0` |

Package identities are the ones the repository already publishes; only
the version string unifies.

**Scope**: platform runtime images, Helm chart, CLI, and all published
SDKs. **Excluded**: sandbox template images such as
`opensandbox/code-interpreter` — users select them at sandbox-creation
time and they version independently in
[opensandbox-group/sandbox-images](https://github.com/opensandbox-group/sandbox-images).
The code-interpreter **SDK library** is a client of that API and *is*
in scope.

**No component versions exist separately.** Any change that ships
triggers a new umbrella snapshot, and every umbrella release rebuilds
every image (fresh digest, fresh push) even without source changes —
making umbrella `X.Y.Z` a byte-exact fingerprint of the platform.

### Naming Rules

| Surface | Format | Example at `1.4.0` |
|---|---|---|
| Git tag (annotated, on `C_bom`) | `release-X.Y.Z` | `release-1.4.0` |
| Container image tags | same string as the git tag | `opensandbox/execd:release-1.4.0` |
| Package registries | bare `X.Y.Z` | `1.4.0` |
| Go SDK companion tags (same commit) | `sdks/sandbox/go/vX.Y.Z` | `sdks/sandbox/go/v1.4.0` |
| Go poolredis companion tag (same commit) | `sdks/sandbox/go/poolredis/vX.Y.Z` | `sdks/sandbox/go/poolredis/v1.4.0` |

Notes:

- Users never write `release-` by hand — the Helm chart resolves
  `image.tag` from `.Chart.AppVersion`.
- The `release-` prefix is empty today and disjoint from every legacy
  `v` tag.
- The Go companion tags are a toolchain requirement (subdirectory
  modules need the path-prefixed VCS tag), not a governance exception.
  The namespace reuses legacy Go tags (`v1.0.0`–`v1.0.5` exist), so the
  first companion tags are `v1.1.0`.
- Historical per-component tags (`server/v*`, `docker/*/v*`,
  `helm/opensandbox/*`, …) are frozen when `release-1.1.0-rc.1` is cut.

### Starting Version: `1.1.0` as GA

> **Floor rule**: the starting version must be strictly greater than the
> highest version already consumed in registries where versions are
> **immutable or monotonic**.

| Registry | Highest consumed | Why it binds |
|---|---|---|
| Maven Central (`com.alibaba.opensandbox:*`) | `sandbox` `1.0.19`, `code-interpreter` `1.0.16` | Central versions are permanently immutable; republishing `1.0.0` fails outright. |
| Go proxy (`sdks/sandbox/go`) | `v1.0.5` | Companion tags share the legacy namespace; the sum database forbids re-pointing, and `go get` never downgrades. |
| Go proxy (`sdks/sandbox/go/poolredis`) | never published | No constraint. |

All other surfaces are collision-free at any `1.x`, and semver makes
`1.1.0` strictly greater than both floors (`1.0.19`, `1.0.5`): the
minimal safe start.

**The jump is monotonic everywhere but conditional.** Every SDK can
legally move to `1.1.0`, but the jump only materializes if the Phase 2
PR lands these enablers in the same release commit:

| # | Enabler | Why it blocks the jump |
|---|---|---|
| 1 | hatch-vcs `tag_regex` → `^release-(?P<version>\d+\.\d+\.\d+(?:[.\w+\-]*)?)$` in every Python `pyproject.toml` | Without it the derived version falls back to `0.0.0` and the jump silently fails. |
| 2 | Python ranges `opensandbox>=0.1.10,<0.2.0` → `>=1.1.0,<2.0.0` | Otherwise pip resolves `opensandbox` back to `0.1.x`. |
| 3 | .NET `<OpenSandboxDependencyVersionRange>` → `[1.1.0,2.0.0)` | Blind substitution yields the empty range `[1.1.0,0.2.0)` and breaks NuGet restore. |
| 4 | Kotlin `sandbox-bom` constraints + umbrella chart `version`/`appVersion`/sub-chart versions → `1.1.0` | Prevents mixing legacy `1.0.x` siblings with umbrella artifacts. |

**The `1.0.0` gap.** Most registries jump from `0.x` straight to
`1.1.0`; release notes and `docs/community/releases.md` must state why
(consumed by legacy `java/sandbox` and `sdks/sandbox/go` releases) and
label `1.1.0` explicitly as the unified-umbrella GA.

`1 → 2` stays reserved for breaking cross-component changes. The
API/CRD/spec stability contract that "GA" implies is out of scope here
and must land in a follow-up OSEP before or alongside `1.1.0`.

### First Umbrella Version of Every Artifact

Every artifact's **first umbrella version is `1.1.0`** — git tag
`release-1.1.0`, image tags `:release-1.1.0`, packages `1.1.0`. The
table records each artifact's last legacy version, which is frozen
forever:

**Platform images** (Docker Hub / GHCR / ACR, `opensandbox/<component>`):

| Component | Last legacy tag (frozen) | First umbrella |
|---|---|---|
| server | `v0.2.3` | `release-1.1.0` |
| execd | `v1.1.0` | `release-1.1.0` |
| ingress | `v1.0.10` | `release-1.1.0` |
| egress | `v1.1.7` | `release-1.1.0` |
| image-committer | `v0.1.1` | `release-1.1.0` |
| controller | `v0.2.0` | `release-1.1.0` |
| task-executor | `v0.2.0` | `release-1.1.0` |

**Charts, CLI, server:**

| Artifact | Registry | Last legacy version (frozen) | First umbrella |
|---|---|---|---|
| `opensandbox` umbrella chart | Helm OCI | `0.2.2` | `1.1.0` |
| `opensandbox-node-agent` chart | Helm OCI | never released | `1.1.0` |
| `opensandbox-server` | PyPI | `0.2.3` | `1.1.0` |
| `opensandbox-cli` | PyPI | `0.1.1` | `1.1.0` |

**SDKs:**

| SDK | Registry | Last legacy version (frozen) | First umbrella |
|---|---|---|---|
| `opensandbox` | PyPI | `0.1.17.dev0` | `1.1.0` |
| `opensandbox-code-interpreter` | PyPI | `0.1.2` | `1.1.0` |
| `opensandbox-mcp` | PyPI | `0.1.1` | `1.1.0` |
| `@alibaba-group/opensandbox` | npm | `0.1.11` | `1.1.0` |
| `@alibaba-group/opensandbox-code-interpreter` | npm | `0.1.3` | `1.1.0` |
| `com.alibaba.opensandbox:sandbox` / `:sandbox-api` / `:sandbox-bom` / `:sandbox-pool-redis` | Maven Central | `1.0.19` | `1.1.0` |
| `com.alibaba.opensandbox:code-interpreter` | Maven Central | `1.0.16` | `1.1.0` |
| `Alibaba.OpenSandbox` | NuGet | `0.1.5` | `1.1.0` |
| `Alibaba.OpenSandbox.CodeInterpreter` | NuGet | `0.1.0` | `1.1.0` |
| `github.com/alibaba/OpenSandbox/sdks/sandbox/go` | Go proxy | `v1.0.5` | `v1.1.0` |
| `github.com/alibaba/OpenSandbox/sdks/sandbox/go/poolredis` | Go proxy | never released | `v1.1.0` |

**Excluded**: the `opensandbox/code-interpreter` sandbox image lives in
[opensandbox-group/sandbox-images](https://github.com/opensandbox-group/sandbox-images)
and keeps versioning independently.

### Cadence and Support

| Release type | Frequency | Support | Tag |
|---|---|---|---|
| Line birth (`X.Y.0`) | Every 2 weeks (even ISO-week Wednesdays) | Latest only | `release-X.Y.0` |
| In-line snapshot (`X.Y.Z`, `Z > 0`) | On demand within the current window | Same as current line | `release-X.Y.Z` |
| N-1 emergency CVE | CVSS ≥ 8.0, ≤72h from disclosure, no current-line fix | One-off snapshot | `release-X.(Y-1).Z` |
| Pre-release | Ahead of a line birth | Not supported | `release-X.Y.0-rc.N` |

**No LTS.** At 2-week cadence a backport is a full umbrella rebuild
anyway. When `X.(Y+1).0` ships, `X.Y.*` is EOL except for the single
emergency-CVE window. Old tags remain resolvable forever but stop
receiving fixes. The emergency snapshot is one-shot per line; anything
that is not a qualifying CVE waits for the next line birth (≤ 2 weeks).

## Design Details

### Bill of Materials (BOM)

Every release adds workflow-authored, Sigstore-signed files on the
release branch, flat under `releases/` (the umbrella is the only
release train, so no per-product nesting):

```
releases/
  1.1.0.yaml               # BOM — authoritative for image digests
  1.1.0.md                 # release notes — authoritative copy
  1.1.0.yaml.sigstore.json # BOM signature bundle
```

The BOM pins image digests (built at `release-X.Y.Z`), package
versions (`==X.Y.Z`), Helm
`version`/`appVersion`, spec file SHA-256s, and the build commit:

```yaml
apiVersion: opensandbox.io/v1
kind: UmbrellaRelease
metadata: { version: 1.4.0, line: "1.4", channel: stable, releaseDate: "2026-10-15", gitCommit: 6b1e… }
images:
  execd: { image: docker.io/opensandbox/execd, tag: release-1.4.0, digest: sha256:… }
  # …one entry per platform image (see table above). Sandbox template
  #   images are NOT part of the umbrella.
helm:   { chart: opensandbox, version: "1.4.0", appVersion: "1.4.0" }
server: { pypi: opensandbox-server==1.4.0 }
cli:    { pypi: opensandbox-cli==1.4.0 }
sdks:
  - { product: sandbox, language: python, package: "pypi:opensandbox==1.4.0" }
  - { product: sandbox, language: kotlin, package: "maven:com.alibaba.opensandbox:sandbox:1.4.0" }
  # …one entry per SDK per product/language (python ×3, js ×2,
  #   kotlin ×5, csharp ×2, go ×2)
specs:
  - { path: specs/sandbox-lifecycle.yml, sha256: … }
attestation: { bomSha256: …, signatures: […] }
```

The BOM is authoritative for **digests**, not versions — the version is
the file name. It is workflow-generated, so version-string drift is
impossible (~4 KB per release).

**Release notes in-repo.** The workflow aggregates notes from per-PR
labels (changes up to `C_build`) into `releases/X.Y.Z.md`, committed in
the same `C_bom` commit. The in-repo copy is **authoritative**; the
GitHub Release mirrors the same bytes. Rationale: notes must survive
org migrations and stay reachable for users behind GitHub-blocked
networks (ACR mirror users), and they feed generated docs
(`docs/community/releases.md`, compatibility matrix). Legacy-era notes
are not backfilled — `releases/` starts at `release-1.1.0-rc.1`.

### Release Workflow

New `.github/workflows/release-umbrella.yml` (`workflow_dispatch`) with
inputs `version`, `channel: stable|rc`, `release_branch`, and `dry_run`
(default true). It uses a **build-hold-publish** model: no
user-pullable artifact carries the release identity until every target
has built successfully — partial releases are structurally impossible.

| Artifact class | Mechanism |
|---|---|
| Images | **Stage-then-promote**: push once to `opensandbox/<comp>:staging-<commit>-<runid>`; after all legs succeed, `crane tag` adds `release-X.Y.Z` to the same digest (attestations carry over, no rebuild). Staging tags GC'd after 14 days. |
| Packages / chart | **Hold-then-publish**: build final `X.Y.Z` artifact, upload as a workflow artifact with SHA-256; publish externally only after the BOM commit exists. |

Steps:

1. **Preflight** — reuse `release-preflight.yml` (approval + commit
   reachability of the build commit `C_build`).
2. **Version-consistency scan** — scoped, path-listed check
   (`scripts/release/version-consistency-paths.txt`): umbrella chart
   `version`/`appVersion` and every sub-chart image ref =
   `release-${version}`; SDK `package.json` / `gradle.properties` /
   `*.csproj` + `Directory.Build.props`; Go version constant; server
   `/version` source; every hatch-vcs `tag_regex` on the umbrella
   pattern; every inter-OpenSandbox range with lower bound =
   `${version}` and same-major upper bound (upper ≤ lower is
   release-blocking). OpenAPI fields, lockfiles, examples out of scope.
3. **Fan-out build** — images to staging; packages held as workflow
   artifacts. Any leg failure aborts before any publish, tag, or BOM.
4. **BOM commit (`C_bom`)** — assemble the BOM and the aggregated
   release notes (`releases/X.Y.Z.yaml` + `releases/X.Y.Z.md`), commit
   both on `<release_branch>` on top of `C_build`; no code changes.
5. **Publish** — `crane tag` images to `release-X.Y.Z`; Helm first
   (largest blast radius), then language packages in parallel; each leg
   verified externally before the next starts.
6. **Umbrella tag** — annotated `release-X.Y.Z` on `C_bom` plus the two
   Go companion tags, pushed only after the last verification; GitHub
   Release with BOM + attestations, mirroring the committed notes.

**Failure-safe publish.** The publish step is the only place partial
state is possible. The contract: ordered verify-then-continue; a
rollback ledger of per-ecosystem revocation commands (PyPI yank; npm
unpublish→deprecate; Maven staged-repo `drop` with auto-release ordered
last; NuGet delete→unlist; `oras rm` for Helm OCI; `crane delete` for
image tags) walked in reverse on any failure, filing a P0 incident;
idempotent retry; the umbrella tag is the commit-fence — never pushed
on rollback, while `C_bom` remains as an auditable attempted-release
record. Known limits: Maven Central after auto-release is immutable,
and downstream mirror caches cannot be invalidated.

**Two commits, one release.** `C_build` is what artifacts are built
from (no BOM in its tree); `C_bom` is the release commit (its tree
contains the BOM pinning `C_build` digests). The tag points at `C_bom`;
the BOM's `metadata.gitCommit` points at `C_build` — a single-hop
audit chain from tag → BOM → source.

**Script and workflow changes.** `manifests/release/create-release.sh`
gains `--target opensandbox` (computes `release-X.Y.Z`; umbrella mode
suppresses legacy `<target>/v<version>` tags, forces `release-<version>`
image tags, and syncs chart `version` + `appVersion` before packaging).
`publish-server.yml`, `publish-components.yml`, `publish-helm-chart.yml`,
`publish-cli.yml`, and `publish-*-sdks.yml` accept umbrella-mode inputs
and the staging → promotion contract; their per-target
`workflow_dispatch` triggers are retired (or gated behind a
manual-override flag for emergencies only).

**Release branches.** Cut `release-X.Y` from `main`; tag
`release-X.Y.0` on it (branch and tag are separate git namespaces).
In-line snapshots go on `release-X.Y`; N-1 emergency backports rerun
the same workflow on `release-X.(Y-1)` — a backport is always a full
umbrella rebuild, never a cherry-picked artifact set.

### Compatibility

- **Server ↔ CLI/SDK**: same line supported; ±1 minor warns; beyond
  that destructive commands are refused (warnings are non-fatal for one
  line before graduating to refusal).
- **Server ↔ Kubernetes**: declared per release in the BOM
  (`compatibility.kubernetes`), exercised by `kubernetes-test.yml`.
- **Ingress ↔ server**: shipped as an umbrella pair; cross-umbrella
  mixing is untested by construction.
- **CRD deprecation**: ≥1 line's notice; removal only on a major bump.

### User-facing Surface

Installation is exclusively via the Helm chart (`osb` is a lifecycle
client, not an installer). Docs: `docs/community/releases.md`
(umbrella-first listing, legacy tag appendix),
`docs/reference/compatibility-matrix.md` (generated from BOMs), and an
installation quickstart pinned to `--version X.Y.Z`. CLI: `osb version`
prints the server's umbrella version and skew status; `osb devops
doctor` compares cluster images against the BOM bundled with the CLI.

## Test Plan

- **BOM schema** (`specs/schemas/umbrella-release.schema.json`) validated in CI.
- **Consistency scan unit test**: every listed path updated on
  `C_build`; no coverage outside the list.
- **Weekly dry-run** (`dry_run: true` on `main`) to catch fan-out regressions.
- **Atomicity**: a synthetic build-leg failure aborts before any
  publish, chart release, or tag.
- **Verify-then-continue**: per ecosystem, a synthetic verification
  failure stops subsequent legs, walks the rollback ledger in reverse,
  and never pushes the tag.
- **Idempotency**: re-running at the same version short-circuits to no-ops.
- **Staging GC**: tags from runs that never reached publish are deleted after 14 days.
- **hatch-vcs / dependency-range tests**: no legacy `tag_regex` remains;
  all inter-package ranges are `[X.Y.0, X+1.0.0)`-shaped.
- **Skew tests** (`±1`/`±2` minor) and a Helm golden test against
  BOM-derived values.
- **`osb devops doctor` e2e** on Kind: an out-of-BOM image is flagged.

## Drawbacks

- ~450 artifact publishes/year regardless of churn; registry noise
  (~26 no-op version bumps per SDK per year). Accepted cost of unification.
- No per-component hotfix agility — a 1-line ingress fix is a full
  rebuild. The central trade.
- `1.1.0` = GA is a strong claim; the stability OSEP must land in time.
- The `1.0.0` gap reads like a routine minor bump for Java/Go users;
  mitigated by explicit GA labeling in release notes.

## Alternatives

| Option | Verdict |
|---|---|
| A. Per-component versions + umbrella manifest | Rejected — loses the single installable version. |
| B. Unified versioning without a BOM | Rejected — no digest authority, no `devops doctor` basis. |
| C. Two-tier umbrella (platform + sdks) | Rejected — doubles the surface users reason about. |
| D. Longer cadence + LTS | Deferred to `2.0.0` — backports are full rebuilds either way. |
| E. Start at `1.0.0` | Rejected — already consumed by Maven Central and the Go proxy (see floor rule). |

## Migration

| Phase | Milestone | Notes |
|---|---|---|
| 1 — Provisional | BOM schema + workflow land | `dry_run: true` forced; no user-visible tag change. |
| 2 — `release-1.1.0-rc.1` | First pre-release | Legacy tag namespaces frozen here; version-jump enablers land in the same PR. |
| 3 — GA `release-1.1.0` | Workflow unconditionally enabled | Docs, Helm defaults, `osb version` switch to the umbrella. |
| 4 — Steady state | 2-week line births | On-demand in-line and emergency-CVE snapshots. |

Historical tags are never deleted and keep resolving forever; docs keep
a legacy tag appendix for at least six lines after `1.1.0`, plus a
lookup script mapping legacy tags to their superseding umbrella.
