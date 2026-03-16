# OpenSandbox Fork — PAOP WebSocket Steering Integration

This is `danieliser/OpenSandbox`, a fork of [`alibaba/OpenSandbox`](https://github.com/alibaba/OpenSandbox).

## Purpose

This fork adds WebSocket-based steering support to `execd` so that PAOP (Persistent Agent
Orchestration Platform) can replace its tmux/poll executor with a push-based, in-container
execution model.

Key goals:

- Add `GET /ws/session/:sessionId` WebSocket endpoint to `components/execd` (Phase 1)
- Add PTY opt-in via `?pty=1` query parameter for interactive programs (Phase 2)
- Fix residual bugs from upstream PR #104 (`feat/bash-session`) (Phase 0)

The PAOP-side counterpart lives in the `persistence` repo under `paop/executor/`.

## Working Branch

All active development happens on `feat/paop-steering`.

## Upstream Sync

To pull in upstream changes from `alibaba/OpenSandbox`:

```bash
git fetch upstream
git checkout feat/paop-steering
git merge upstream/main
# Resolve conflicts, then push
git push origin feat/paop-steering
```

If the `upstream` remote is not yet configured:

```bash
git remote add upstream https://github.com/alibaba/OpenSandbox.git
```

## What's PAOP-Only vs. Upstream Candidates

| Phase | Changes | Upstream candidate? |
|-------|---------|---------------------|
| Phase 0 | Bug fixes for PR #104 (TOCTOU race, stderr routing, sentinel collision, context leak, shutdown race) | **Yes** — these are correctness fixes valuable to all users |
| Phase 1 | `GET /ws/session/:sessionId` WebSocket endpoint | **Possibly** — generic enough; needs upstream discussion |
| Phase 2 | PTY opt-in (`?pty=1`) | **Possibly** — generic; needs upstream discussion |
| Phase 3 | PAOP `WSExecutor` integration (lives in `persistence` repo) | **No** — PAOP-specific, stays here / in persistence repo |

Phase 0 bug fixes are the strongest upstream PR candidates. They fix real correctness issues
independent of any PAOP integration and should be submitted back once validated.

## CI

GitHub Actions runs on every push and pull request targeting `feat/paop-steering` or `main`.
Matrix: Go 1.21 and 1.22. Steps: build, vet, race-detector test suite (60s timeout).
See `.github/workflows/ci.yml`.
