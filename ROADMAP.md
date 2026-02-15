# openclaw-plugin-dotkc roadmap (L2)

This roadmap focuses on the **OpenClaw plugin** (typed tools + policy + safe responses).

## Principles

- Tools are **typed** (schema-driven), predictable, and minimal.
- Plugin is **fail-closed** on suspected leakage.
- Default stance: **never return secrets to the model**.

## P0 — Safety guardrails

### 1) Leak detection + fail-closed (in addition to redaction)
**Goal:** even if dotkc (or an integration) accidentally emits plaintext, do not return it to the LLM.

Add a detector pass on tool output before returning:
- Block `KEY=VALUE` patterns
- Block common token prefixes (`sk-`, `ghp_`, etc.) (configurable)
- Block high-entropy long strings (heuristic)

On match:
- Return an error like `LEAK_BLOCKED`
- Provide a short hint (inspect on host manually)

### 2) Path restrictions
- Ensure `specFile` is within workspace (no `~`, no `/etc/...`)
- Reject traversal (`..`) unless explicitly allowed

### 3) Config hardening
- `allowUnsafe` should require explicit opt-in + loud warning
- Consider a second "break glass" flag (two keys) for unsafe values

## P1 — Real integration value

### 4) Add `dotkc_run` tool (safe execution)
**Goal:** replace `exec "dotkc run ..."` patterns with a constrained tool.

Inputs:
- `specFile`
- `command[]` (argv)
- optional `cwd`

Policies:
- Require `specFile` (no ad-hoc specs)
- Enforce command allowlist (exact or regex)
- Return only:
  - `exitCode`
  - `durationMs`
  - `stderrTail` (capped)
  - optionally `stdoutTail` (capped)

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

## P3 — Distribution

### 8) Publish to npm
- `openclaw plugins install @hcz/openclaw-plugin-dotkc`
- Versioning + release notes
