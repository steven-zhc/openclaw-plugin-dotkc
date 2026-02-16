# dotkc-openclaw roadmap (L2)

This roadmap focuses on the **OpenClaw plugin for dotkc** (typed tools + policy + safe responses).

## What OpenClaw needs (pain-driven)

OpenClaw plugins run in-process with the Gateway (trusted), but **tool outputs** may be sent to model providers.
The main pain points we must solve:

1) **Transcript leakage:** secrets accidentally printed (stdout/stderr) or returned in JSON.
2) **Over-broad execution:** agents use `exec` too freely; we need constrained runners.
3) **Path exfiltration:** spec/cwd paths escaping workspace.
4) **Config ergonomics:** users shouldn’t have to wire many env vars to be safe.
5) **Observability:** when something is blocked, users need actionable reasons.

## Principles

- Tools are **typed**, predictable, minimal.
- Plugin is **fail-closed** on suspected leakage.
- Default stance: **never return secrets to the model**.
- Prefer *policy in the plugin* over “remember to configure X”.

---

## P0 — Safety guardrails (must-have)

### 0) Defensive redaction
**Status:** ✅ shipped

- Redact obvious value-bearing fields before returning tool output (`env`, `value`, `token`, `apiKey`, etc.)

### 1) Leak detection + fail-closed
**Status:** ✅ shipped

- Detect:
  - dotenv-like `KEY=VALUE`
  - common token prefixes (`sk-`, `ghp_`, `xoxb-`, etc.)
  - high-entropy long strings (heuristic)
- On match: return `LEAK_BLOCKED` and never include plaintext in any response fields

### 2) Path restrictions
**Status:** 🟡 partial

- ✅ Reject absolute paths, `~`, and traversal (`..`) for `specFile` / `cwd`
- ⬜ Enforce workspace-root containment (needs reliable workspace root from OpenClaw runtime or explicit config)

### 3) Config hardening
**Status:** 🟡 partial

- ✅ `allowUnsafe` exists but discouraged
- ⬜ Make `allowUnsafe` require an additional break-glass env/config (two-step)
- ⬜ Add explicit docs warning that OpenClaw installs deps with `npm install --ignore-scripts` (avoid deps needing postinstall)

---

## P1 — Real integration value (replace shell exec)

### 4) `dotkc_run` tool (safe execution)
**Status:** ✅ shipped

- Requires `specFile`
- Enforces `commandAllowlist[]`
- Returns only: `exitCode`, `durationMs`, `stdoutTail`, `stderrTail`
- Applies leak detection before returning

Next:
- ⬜ Allow regex allowlist (careful: denial-of-service / overly broad patterns)
- ⬜ Add approvals mode (first-run approval per command)

### 5) Default no-leak (no env config required)
**Status:** ✅ shipped

- Plugin sets `DOTKC_NO_LEAK=1` for dotkc subprocesses by default

---

## P2 — Packaging / UX

### 6) Bundle dotkc
**Status:** ✅ shipped

- Plugin installs `dotkc` as a dependency and runs via `node + dotkc/bin/dotkc.mjs` by default
- Users do not need global dotkc install

### 7) Tests
**Status:** ⬜ not yet

- Golden tests for JSON parsing
- Leak detector test corpus (positive/negative)
- Failure modes: missing spec file, disallowed command, bad cwd

---

## P3 — Distribution

### 8) Publish to npm
**Status:** 🟡 in progress

- Package name: `dotkc-openclaw`
- Target install: `openclaw plugins install dotkc-openclaw@<version>` (includes bundled dotkc)

Blocker:
- Set `NPM_TOKEN` in GitHub Actions secrets so `release.published` can publish
