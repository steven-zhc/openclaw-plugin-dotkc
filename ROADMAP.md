# dotkc-openclaw roadmap (L2)

This roadmap focuses on the **OpenClaw plugin for dotkc** (typed tools + policy + safe responses).

## Principles

- Tools are **typed** (schema-driven), predictable, and minimal.
- Plugin is **fail-closed** on suspected leakage.
- Default stance: **never return secrets to the model**.

## P0 — Safety guardrails (agent-safe by default)

### 0) Defensive redaction
**Status:** ✅ shipped

- Redact obvious value-bearing fields before returning tool output to the model (`env`, `value`, `token`, `apiKey`, etc.)

### 1) Leak detection + fail-closed (in addition to redaction)
**Status:** ✅ shipped

**Goal:** even if dotkc (or an integration) accidentally emits plaintext, do not return it to the LLM.

Add a detector pass on tool output before returning:
- Block `KEY=VALUE` patterns
- Block common token prefixes (`sk-`, `ghp_`, etc.) (configurable)
- Block high-entropy long strings (heuristic)

On match:
- Return an error like `LEAK_BLOCKED`
- Provide a short hint (inspect on host manually)

### 2) Path restrictions
**Status:** 🟡 partial

- ✅ Reject traversal (`..`)
- ✅ Reject absolute paths / `~` expansion
- ⬜ Enforce "workspace-only" root (requires OpenClaw workspace path access)

### 3) Config hardening
- `allowUnsafe` should require explicit opt-in + loud warning
- Consider a second "break glass" flag (two keys) for unsafe values

## P1 — Real integration value

### 4) Add `dotkc_run` tool (safe execution)
**Status:** ✅ shipped

**Goal:** replace `exec "dotkc run ..."` patterns with a constrained tool.

Inputs:
- `specFile`
- `command[]` (argv)
- optional `cwd`

Policies:
- ✅ Require `specFile` (no ad-hoc specs)
- ✅ Enforce command allowlist (exact list)
- ✅ Return only tails + metadata (`exitCode`, `durationMs`, `stdoutTail`, `stderrTail`)
- ✅ Fail-closed leak detection on tool output

### 5) Approvals integration
- First time a command is run, require approval (optional mode)

## P2 — Quality

### 6) Tests
- Golden tests for JSON parse
- Failure modes for missing dotkc / bad spec file
- Leak detector tests

### 7) Better UX
- Structured tool errors (code + hint + suggested commands)
- Better docs examples by scenario

## P2.5 — Packaging / UX

### 8) Bundle dotkc
**Status:** ✅ shipped

- Plugin installs `dotkc` as a dependency and runs it via `node + dotkc/bin/dotkc.mjs` by default (no global install required)
- Plugin enforces `DOTKC_NO_LEAK=1` for dotkc subprocesses by default (no Gateway env config required)

## P3 — Distribution

### 9) Publish to npm
**Status:** 🟡 in progress

- Package name: `dotkc-openclaw`
- Target install: `openclaw plugins install dotkc-openclaw@<version>` (includes bundled dotkc)
- Versioning + release notes

Note: npm publish requires setting `NPM_TOKEN` in GitHub Actions (release.published workflow already configured).
