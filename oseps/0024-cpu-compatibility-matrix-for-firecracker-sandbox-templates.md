---
title: CPU Compatibility Matrix for Firecracker Sandbox Templates
authors:
  - "@Pangjiping"
creation-date: 2026-09-23
last-updated: 2026-09-23
status: draft
---

# OSEP-0024: CPU Compatibility Matrix for Firecracker Sandbox Templates

<!-- toc -->
- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-Goals)
- [Requirements](#requirements)
- [Proposal](#proposal)
  - [Baseline and Per-Vendor Artifacts](#baseline-and-per-vendor-artifacts)
  - [Compatibility Matrix](#compatibility-matrix)
  - [Enforcement Points](#enforcement-points)
  - [Notes/Constraints/Caveats](#notesconstraintscaveats)
  - [Risks and Mitigations](#risks-and-mitigations)
- [Design Details](#design-details)
  - [CPU Identity](#cpu-identity)
  - [Matrix File](#matrix-file)
  - [Manifest Schema Extension](#manifest-schema-extension)
  - [Artifact Store Layout](#artifact-store-layout)
  - [Build Flow](#build-flow)
  - [Node Agent](#node-agent)
  - [Restore Admission](#restore-admission)
  - [Baseline Rebalance](#baseline-rebalance)
  - [Matrix Regeneration Triggers](#matrix-regeneration-triggers)
- [Test Plan](#test-plan)
- [Drawbacks](#drawbacks)
- [Alternatives](#alternatives)
- [Infrastructure Needed](#infrastructure-needed)
- [Upgrade & Migration Strategy](#upgrade--migration-strategy)
<!-- /toc -->

## Summary

A Firecracker golden image produced by a `SandboxTemplate` is a **full
microVM snapshot**: `vmstate.snap` bakes in the vCPU register and MSR state of
the build host. Restoring that snapshot on a host whose CPU exposes different
features is unsafe — MSR writes fail, XSAVE areas reference state components
the destination lacks, and the guest kernel observes a CPUID different from
the one it booted with.

Today the builder pins the static `T2` CPU template and silently falls back to
the host's raw CPUID on hosts that refuse `T2` (Ice Lake, Sapphire Rapids, and
every AMD part). The resulting snapshots are host-CPU-specific, and the
`cpuModel` recorded in the manifest is purely informational: nothing enforces
it at scheduling or restore time.

This OSEP introduces **per-vendor CPU baselines** and a **tool-verified
compatibility matrix**:

- one baseline per vendor (the oldest in-service generation), declared
  explicitly in a versioned matrix file;
- golden images are **always built on baseline nodes**, producing one artifact
  set per vendor (`SandboxTemplate` → 2 artifacts);
- a `cpu-template-helper` dump on the baseline plus a `check verify` pass on
  every in-service model yields a static, evidence-backed compatibility
  matrix;
- the matrix drives build placement, node labels, and a restore-time admission
  check that fails fast.

The result: one build per vendor restores on every generation the matrix has
verified, with no custom CPU template design and no silent
host-specific snapshots.

## Motivation

The Fast Sandbox Firecracker runtime (see OSEP-0007 and the golden-image
builder) restores sandboxes from published snapshot sets on demand. Snapshot
restore is only safe when the destination CPU is feature-compatible with the
CPU the snapshot was created on. Real fleets mix generations and vendors:

- Intel Xeon Scalable: Skylake-SP / Cascade Lake-SP (CPUID family 6, model 85,
  e.g. 8163 / 8269CY), Ice Lake-SP (model 106), Sapphire Rapids (model 143);
- AMD EPYC: Milan and Genoa (family 25).

The current builder behavior has three problems:

1. **The static `T2` template is model-gated.** Firecracker only permits
   applying a static template on the models it was derived from. On newer or
   non-Intel hosts the builder falls back to the host's raw CPUID, and the
   published snapshot silently becomes host-CPU-specific.
2. **Nothing enforces the compatibility tuple.** The manifest records
   `compatibility: {firecrackerVersion, hostKernel, cpuModel}` by design
   "for consumers to match against node labels", but neither the scheduler nor
   the restore path reads it. The node agent's `/v1/compatibility` endpoint
   returns a placeholder (`native-stage-1`).
3. **Restore failures surface at user time.** A snapshot restored on an
   incompatible host fails (or misbehaves) when a sandbox is created, not when
   the artifact is published.

Matching on the `/proc/cpuinfo` marketing string is also too strict: 8163 and
8269CY have different marketing names but the same CPUID identity
(family 6, model 85) and are mutually compatible.

### Goals

- Declare an explicit, versioned **CPU baseline per vendor** (not inferred
  from fleet composition at build time).
- Guarantee that every published golden image is a **baseline artifact**: its
  guest CPU profile equals the baseline, regardless of when or by which
  pipeline instance it was built.
- Produce **one artifact set per vendor** from a single `SandboxTemplate`
  (Intel + AMD), selected automatically by the consuming node's vendor.
- Generate the compatibility matrix **mechanically** with Firecracker's
  `cpu-template-helper` (`dump` / `check create` / `check verify`), so every
  "model X can restore baseline artifacts" claim is backed by tool output.
- Enforce compatibility at **three** points: build placement (baseline-only),
  scheduling (labels), and restore admission (fail-fast in the node agent).
- Keep snapshot portability within the **officially safe direction** (baseline
  build → newer-generation restore) and make the unsafe direction impossible.

### Non-Goals

- **Cross-vendor snapshot portability.** Intel and AMD differ structurally in
  MSR layouts; a snapshot never crosses vendors regardless of masking.
- A universal hand-crafted **custom CPU template** lowest-common-denominator
  baseline (see [Alternatives](#alternatives)); this proposal deliberately
  avoids designing and maintaining custom template JSON.
- Exposing post-baseline CPU features (e.g. AMX on Sapphire Rapids) to guest
  sandboxes. All guests observe baseline capability by construction.
- Cross-Firecracker-version snapshot portability. `firecrackerVersion` stays
  part of the admission tuple.
- Live migration of running microVMs, and non-KVM runtimes (the container
  runtime is unaffected by this proposal).

## Requirements

- Builds run on KVM nodes; the builder image pins Firecracker and
  `cpu-template-helper` to matching versions.
- Each vendor's baseline node pool must exist for builds to proceed. If the
  baseline pool is empty or unschedulable, the build **fails closed** — the
  builder must never fall back to a newer generation.
- Restore admission must be decidable offline from the manifest alone: any
  node must be able to evaluate "can I restore this snapshot?" from local
  CPUID and the manifest, without control-plane round trips.
- New CPU models must not silently join the restore pool before they are
  verified against the matrix.

## Proposal

### Baseline and Per-Vendor Artifacts

For each vendor, the baseline is the **oldest in-service server generation**,
recorded explicitly in the matrix file:

```text
Intel: baseline = family 6, model 85   (Skylake-SP / Cascade Lake-SP)
AMD:   baseline = family 25, model 1   (Milan)
```

A `SandboxTemplate` build fans out into **one build Pod per vendor**, each
pinned via node selector to its vendor's baseline pool. Each build produces an
independent, complete artifact set (rootfs + vmstate + memory + manifest).
The image index gains a vendor dimension so consumers resolve exactly one
manifest for their vendor.

```text
                     SandboxTemplate spec
                              |
              +---------------+---------------+
              |                               |
      build Pod @ Intel baseline       build Pod @ AMD baseline
      (f6/m85 node pool)               (f25/m1 node pool)
              |                               |
      artifact set (intel)             artifact set (amd)
              |                               |
              +------- vendor-keyed index -----+
                              |
        node pulls the artifact matching its vendor
```

Because every artifact is created on the baseline generation, its CPU profile
**is** the baseline. Restoring on any newer generation of the same vendor is
the feature-superset direction, which the compatibility matrix verifies
explicitly per model.

The builder dumps the **raw** baseline CPUID/MSRs (not a `T2`-derived mask).
`T2` masks `RDRAND`/`RDSEED`, which is why the current builder must attach
virtio-rng to keep the guest CRNG initialized; a raw dump keeps those bits, so
the entropy workaround is no longer load-bearing. Optionally the builder still
applies the dumped template during the build to neutralize microcode-level
CPUID variance on the baseline pool itself; on baseline hardware the template
is near-identity and is not required for portability.

### Compatibility Matrix

Firecracker ships `cpu-template-helper` with three subcommands that map
directly onto this workflow:

```text
cpu-template-helper dump           # on a baseline node: raw CPUID+MSR -> JSON
cpu-template-helper check create   # package the baseline as a compatibility bundle
cpu-template-helper check verify   # on every in-service model: PASS/FAIL
```

Running `check verify` on every in-service model produces a static, per-vendor
matrix: one boolean per (baseline, model) pair. The matrix is committed to the
repository as a versioned file (never hand-written; always generated from tool
output) and drives everything downstream.

### Enforcement Points

```text
1. Build placement   build Pods are scheduled ONLY onto baseline nodes
                     (vendor + baseline tier labels); no fallback.

2. Scheduling        node agents publish their CPU identity and their matrix
                     verdict as labels; SandboxPool / warm-image placement
                     filters on them.

3. Restore admission the node agent evaluates the manifest compatibility
                     tuple against its own CPUID before snapshot/load and
                     fails fast on mismatch. This is the backstop that also
                     covers paths that bypass the scheduler (pre-warm, cache
                     priming, label drift, node recommissioning).
```

Admission rule:

```text
allow(node, artifact) :=
      artifact.vendor      == node.vendor            # hard equality, never crossed
   && artifact.baseline    is registered             # matrix file knows it
   && node.satisfiesBaseline                          # tool-verified superset
   && artifact.firecrackerVersion == node.firecrackerVersion
```

### Notes/Constraints/Caveats

- **TSC frequency differs across generations and SKUs.** The guest kernel
  calibrates TSC at boot and the value is frozen in the snapshot; cross-SKU
  restore has a clock-drift window until guest NTP converges. Workloads
  sensitive to sub-second clock jumps should pin to same-SKU restore.
- **Microcode and stepping variance** within one CPUID model is not visible to
  the matrix. The `check verify` pass should cover the steppings actually
  deployed.
- All builds for one vendor concentrate on the baseline pool. Builds are
  infrequent (per template revision), but pool sizing must absorb them.
- When the baseline generation retires from the fleet, previously published
  artifacts remain valid (they restore on newer nodes in the superset
  direction), but new builds require an explicit baseline rebalance (see
  [Baseline Rebalance](#baseline-rebalance)).

### Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Baseline pool capacity zero → builds stuck | Fail closed with an explicit condition on the SandboxTemplate status; alert on pool emptiness instead of silently degrading the baseline |
| Baseline drift ("whatever node is oldest today") | Baseline is declared in the matrix file, not observed; changes require an explicit review + regeneration |
| New model joins fleet unverified | Nodes report their identity; an unregistered model gets no matrix verdict, and restore admission rejects artifacts (conservative) until verified |
| Tool/FC version skew invalidates old matrix results | Matrix records the `cpu-template-helper` and Firecracker versions used; FC upgrades trigger full regeneration |
| A verified model later fails in production | Matrix entry can be revoked (model removed); admission flips closed without code changes |

## Design Details

### CPU Identity

The canonical identity is read from `/proc/cpuinfo` (equivalent to CPUID
leaf 0x1 and leaf 0x0 vendor string):

```go
type CPUIdentity struct {
    Vendor     string   // "GenuineIntel" | "AuthenticAMD"
    CPUFamily  int      // /proc/cpuinfo "cpu family"
    CPUModel   int      // /proc/cpuinfo "model"
    Flags      []string // /proc/cpuinfo "flags"
}
```

The marketing name ("model name") is retained in manifests for display only.
Matching logic never compares marketing strings — 8163 and 8269CY must
resolve to the same identity.

### Matrix File

Versioned, generated by tooling, consumed by the builder, node agent, and
scheduler integrations:

```yaml
# config/cpu-compat-matrix.yaml
schemaVersion: 1
generatedBy:
  cpuTemplateHelper: v1.9.0     # must pair with firecracker below
  firecracker: v1.16.1
vendors:
  GenuineIntel:
    baseline:
      cpuFamily: 6
      cpuModel: 85
      flags: [sse4_2, popcnt, avx2, avx512f, rdrand, ...]   # from dump
    verifiedModels:           # every entry backed by check verify PASS
      - { cpuFamily: 6,  cpuModel: 85  }   # Skylake-SP / Cascade Lake-SP
      - { cpuFamily: 6,  cpuModel: 106 }   # Ice Lake-SP
      - { cpuFamily: 6,  cpuModel: 143 }   # Sapphire Rapids
  AuthenticAMD:
    baseline:
      cpuFamily: 25
      cpuModel: 1
      flags: [...]
    verifiedModels:
      - { cpuFamily: 25, cpuModel: 1  }    # Milan
      - { cpuFamily: 25, cpuModel: 17 }    # Genoa
```

Semantics: a node whose `(cpuFamily, cpuModel)` appears under a vendor's
`verifiedModels` may restore that vendor's baseline artifacts. A node not
listed (including unknown future models) may not, until the matrix is
regenerated with a passing `check verify` for it.

### Manifest Schema Extension

The existing `compatibility` tuple (currently informational) becomes
admission-authoritative:

```json
"compatibility": {
  "vendor": "GenuineIntel",
  "cpuFamily": 6,
  "cpuModel": 85,
  "baseline": "intel-clx",
  "requiresFlags": ["sse4_2", "avx512f", "..."],
  "firecrackerVersion": "1.16.1",
  "hostKernel": "5.10.134-18.al8.x86_64",
  "cpuModelName": "Intel(R) Xeon(R) Platinum 8269CY CPU @ 2.60GHz"
}
```

`cpuModelName` is display-only. Consumers MUST evaluate admission from the
structured fields.

### Artifact Store Layout

Today the image index maps one image reference to one manifest
(`index/<sha256(image)>.json`, last-writer-wins). With two artifacts per
template the index gains a vendor dimension:

```text
s3://<store>/publish/
├── <sha256(manifest-intel)[:16]>/…      # per-build digest namespace (unchanged)
├── <sha256(manifest-amd)[:16]>/…
└── index/
    └── <sha256(image)>/
        ├── GenuineIntel.json             # → intel manifestRef + artifactDigest
        └── AuthenticAMD.json             # → amd manifestRef  + artifactDigest
```

The legacy single-document index entry remains readable during migration:
a node that finds `index/<sha256(image)>.json` (file, not directory) resolves
it as today and relies on restore admission to reject vendor mismatch.

### Build Flow

1. The `SandboxTemplate` controller fans out one build Pod per vendor present
   in the matrix, each with a node selector for
   `sandbox.fast.io/cpu-vendor=<vendor>` and
   `sandbox.fast.io/cpu-baseline=true` (labels maintained by node agents).
2. If a vendor's baseline pool admits no Pod within the existing Pending
   timeout, the build fails with an explicit `BaselinePoolUnavailable`
   condition. No fallback, no other-generation substitution.
3. The builder runs its existing stages (convert, validate-boot, snapshot,
   restore validation, package). `configureVM` drops the static-`T2` pin and
   its fallback branch; it optionally applies the dumped baseline template
   from the matrix bundle.
4. The manifest gains the structured `compatibility` object; publication
   writes the vendor-keyed index entries.

### Node Agent

- Computes its `CPUIdentity` at startup and on configuration reload.
- Resolves its verdict against the matrix file (shipped with the agent image,
  overridable via ConfigMap for fleet-specific baselines).
- Maintains node labels:
  - `sandbox.fast.io/cpu-vendor=GenuineIntel`
  - `sandbox.fast.io/cpu-verified=true|false`
- Answers `/v1/compatibility` with the structured identity and verdict,
  replacing the `native-stage-1` placeholder.

### Restore Admission

In the Firecracker driver's restore path, before `snapshot/load`:

```text
manifest.compatibility.vendor        == local identity.vendor
manifest.compatibility.(family, model) in matrix.verifiedModels  # or exact
                                                  match when unregistered
manifest.compatibility.firecrackerVersion == local firecracker version
else: fail fast with a structured error naming the mismatching field
```

This runs in the node agent before resources are staged for restore, so an
incompatible pull is rejected before it can boot.

### Baseline Rebalance

When a baseline generation is retired fleet-wide:

1. Pick the new oldest in-service generation; update the matrix file's
   `baseline` entries and re-run `check verify` across all models.
2. Rebuild all `SandboxTemplate`s (they publish artifacts pinned to the new
   baseline).
3. Previously published artifacts stay restorable: old baseline ⊆ new baseline
   is the superset direction. Admission accepts them until they expire
   naturally; operators may force-rebuild to converge faster.

Rebalance is a reviewable change to a committed file, not an emergent
consequence of fleet composition.

### Matrix Regeneration Triggers

| Trigger | Action |
|---|---|
| New CPU model onboarded | `check verify` the model; add or reject; nodes join the restore pool only after the matrix update |
| Firecracker / builder image upgrade | Full regeneration; matrix records tool versions |
| Baseline rebalance | Full regeneration + template rebuilds |
| Host kernel major upgrade | Re-run verify (KVM behavior is part of the compatibility surface) |

## Test Plan

- **Unit**: CPU identity parsing (x86 vendor/family/model variants, marketing
  strings sharing one identity); admission function (vendor mismatch,
  unregistered model, FC version skew, happy paths); matrix file loading and
  validation (tool-version pairing).
- **Builder integration**: build fan-out produces two complete artifact sets;
  baseline pool empty → `BaselinePoolUnavailable` failure (no fallback);
  manifest fields present and structured.
- **E2E cross-product (the evidence behind the matrix)**: for each vendor,
  build a golden image on the baseline node, then restore it on every
  verified model, booting to the existing restore-to-heartbeat gate. The
  committed matrix must equal the set of passing pairs.
- **Admission E2E**: tamper a manifest's vendor/family/model and confirm the
  node agent rejects restore before `snapshot/load`.
- **Rebalance drill**: simulate baseline retirement; verify old artifacts
  remain restorable and new builds pin to the new baseline.

## Drawbacks

- **Feature ceiling at the baseline.** Guests never see post-baseline
  features; workloads that would benefit from AMX or newer AVX-512 subsets on
  Sapphire Rapids do not get them. This is the definitional cost of
  bidirectional compatibility without masking.
- **Dual artifacts** double build time, storage, and cache footprint per
  template revision.
- **Baseline pool is critical infrastructure.** Its availability gates all
  builds.
- **Matrix maintenance** is a real (if small) operational duty: onboarding a
  model requires a verify run on real hardware.

## Alternatives

- **Exact model matching with per-model builds** (build the same template on
  every in-service model; schedule restores to the exact matching model).
  Fully inside the officially guaranteed envelope, but multiplies builds by
  the number of in-service models and cannot consolidate; adopted as the
  Phase 1 stepping stone (below) because it is behavior-preserving for
  homogeneous fleets.
- **Universal hand-crafted custom CPU template** (mask every host down to a
  lowest-common-denominator CPUID/MSR set). Achieves one-artifact universality
  but requires designing and maintaining template JSON, re-validating every
  workload under a reduced feature set, and owning MSR-whitelist correctness
  across vendors. Rejected as disproportionate to the fleet's needs; the
  raw-dump baseline captures most of the benefit with none of the template
  design.
- **Static `T2`/`T2A` templates only.** Model-gated: builds fail on newer
  generations (today's silent fallback exists precisely because of this), and
  no cross-vendor story. Rejected.
- **Feature-superset admission without baseline pinning.** Allows building on
  any node and admitting restores onto supersets. Requires blessing N×N
  directed pairs, and the unsafe direction (newer build → older restore) is
  one scheduling bug away from production. Baseline pinning collapses the
  matrix to one column.
- **Do nothing.** Snapshots remain silently host-specific on non-`T2` hosts;
  incompatibility surfaces as user-visible sandbox creation failures.

## Infrastructure Needed

- CI or lab access to one node of each in-service vendor generation, for
  `check verify` runs and the cross-product restore E2E.
- `cpu-template-helper` added to the builder image, version-paired with the
  pinned Firecracker release.
- No new external services; the artifact store schema change is additive.

## Upgrade & Migration Strategy

- **Phase 1 — record and match exactly.** Publish structured CPU identity in
  manifests, implement the agent identity endpoint and restore admission with
  strict equality. No behavior change for homogeneous fleets; incompatible
  restores start failing fast instead of failing weirdly.
- **Phase 2 — introduce the matrix.** Commit the generated matrix file, add
  node labels, keep admission at exact-match semantics (each verified model
  may restore only artifacts built on the same model).
- **Phase 3 — baseline-pinned builds and dual artifacts.** Fan out builds per
  vendor, publish vendor-keyed indexes, and relax admission to
  "verified superset of the baseline". Existing artifacts continue to restore
  under exact-match until rebuilt.
- **Phase 4 — retire the `T2` pin.** Remove the static template and its
  fallback branch once baseline builds cover all vendors.

Each phase is independently deployable and reversible; no phase requires
downtime or coordinated upgrades across the fleet.
