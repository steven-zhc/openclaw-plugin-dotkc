# dotkc-openclaw roadmap (L2)

This roadmap focuses on the **OpenClaw plugin for dotkc** (typed tools + policy + safe responses).

## What OpenClaw needs (pain-driven)

OpenClaw plugins run in-process with the Gateway (trusted), but **tool outputs** may be sent to model providers and persisted to local transcripts.
Key pain points surfaced in the OpenClaw community/documentation:

1) **Plaintext secrets in config** (encrypted secrets are not first-class yet; see OpenClaw issue #7916).
2) **Transcript persistence**: once a secret is printed/returned, it can land in session transcripts and logs.
3) **Over-broad execution**: `exec` + approvals/sandbox complexity makes it easy to over-permit.
4) **Path exfiltration**: untrusted paths can escape the workspace.
5) **Ergonomics**: users forget env/config hardening steps; safety should be the default.
6) **Observability**: when blocked, users need actionable (non-leaky) reasons.

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
- ⬜ Add explicit docs note: OpenClaw installs plugin deps with `npm install --ignore-scripts` (avoid deps needing postinstall/native builds)
- ⬜ Document recommended OpenClaw tool policy: deny `exec/process` by default; prefer `dotkc_run`

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
- ⬜ Tighten argv policy (not just `argv[0]`): allowlist subcommands/flags to reduce prompt-injection risk

### 5) Default no-leak (no env config required)
**Status:** ✅ shipped

- Plugin sets `DOTKC_NO_LEAK=1` for dotkc subprocesses by default

---

## P2 — Packaging / UX / operations

### 6) Bundle dotkc
**Status:** ✅ shipped

- Plugin installs `dotkc` as a dependency and runs via `node + dotkc/bin/dotkc.mjs` by default
- Users do not need global dotkc install

### 7) Tests

### 7.5) Local audit log (non-secret)
**Status:** ⬜ not yet

- Append-only local log for: `LEAK_BLOCKED`, `COMMAND_NOT_ALLOWED`, `SPEC_PATH_REJECTED`
- Must not include plaintext values
- Helps post-incident review without exposing secrets

### 7.6) Workspace-root enforcement
**Status:** ⬜ not yet

- Add `workspaceRoot` config (or detect via OpenClaw runtime if available)
- Enforce `specFile` and `cwd` under workspaceRoot

### 7) Tests
**Status:** ⬜ not yet

- Golden tests for JSON parsing
- Leak detector test corpus (positive/negative + known token formats)
- Failure modes: missing spec file, disallowed command, bad cwd
- Ensure blocked responses never echo plaintext secrets (stderr tails, reasons, etc.)

---

## P3 — Distribution

### 8) Publish to npm
**Status:** 🟡 in progress

- Package name: `dotkc-openclaw`
- Target install: `openclaw plugins install dotkc-openclaw@<version>` (includes bundled dotkc)

Blocker:
- Set `NPM_TOKEN` in GitHub Actions secrets so `release.published` can publish
