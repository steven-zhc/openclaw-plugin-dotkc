---
title: dotkc OpenClaw Plugin
---

# dotkc OpenClaw Plugin (L2)

Typed OpenClaw tools for **dotkc** so agents can interact with secrets workflows through a constrained interface.

- **dotkc** is the vault + encryption + allowlist runner. Manual: https://dotkc.hczhang.com/
- This plugin is the **OpenClaw-side adapter**: it exposes safe, typed tools instead of “just run a shell command”.

## What problem this solves

OpenClaw agents often need credentials (API keys, tokens) to run local tools.
The unsafe default is to fetch a secret and print it, which can:

- land in the model transcript/context
- leak into logs or debugging output
- get pasted into chat accidentally

This plugin focuses on the safer pattern:

1. Keep an allowlist file in the repo (`dotkc.spec`, **no values**)
2. Let dotkc resolve values at runtime
3. Prefer **inspect redaction** and **env injection** (values are not printed)

## Tools exposed to the agent

### `dotkc_status` (required)

Runs:

```bash
dotkc status --openclaw
```

Returns the OpenClaw JSON envelope from dotkc (paths + decrypt capability).

### `dotkc_doctor` (optional)

Runs:

```bash
dotkc doctor --openclaw
```

Returns diagnostics and suggested fixes.

### `dotkc_inspect` (optional)

Runs (default):

```bash
dotkc run --spec-file ./dotkc.spec --openclaw
```

This is intended to be **redacted output**. This tool should be used for sanity checks.

> By default, this plugin does **not** enable unsafe/raw values.

## Install

### Prerequisites

- OpenClaw Gateway running on the host
- `dotkc` installed on the host (and able to decrypt the vault)

### Install plugin from local path (dev)

```bash
openclaw plugins install -l /path/to/openclaw-plugin-dotkc
openclaw gateway restart
```

Confirm it loaded:

```bash
openclaw plugins list
openclaw plugins info dotkc
```

## Configure

Edit `~/.openclaw/openclaw.json`:

```json5
{
  plugins: {
    entries: {
      dotkc: {
        enabled: true,
        config: {
          dotkcBin: "dotkc",
          specFile: "./dotkc.spec",

          // optional overrides
          // vaultPath: "/path/to/dotkc.vault",
          // keyPath: "~/.dotkc/key",

          // strongly discouraged
          allowUnsafe: false
        }
      }
    }
  },

  // opt-in plugin tools (optional tools require allow)
  tools: {
    allow: ["dotkc"]
  }
}
```

Restart:

```bash
openclaw gateway restart
```

## How it works (principles)

- The plugin runs **in-process** with the OpenClaw Gateway.
- Each tool spawns `dotkc` as a subprocess and expects a single `--openclaw` JSON object on stdout.
- We keep the tool surface small and avoid “return raw secret values” APIs.

## Security model / guardrails

- `dotkc_inspect` is designed for redacted output.
- The plugin also applies **defensive redaction**: it redacts obvious value-bearing fields (`env`, `value`, `token`, `apiKey`, etc.) unless you explicitly enable `allowUnsafe`.
- `allowUnsafe` exists only for debugging on a trusted machine; it is **off by default**.
- Do **not** build workflows that call `dotkc get` in agent mode; it prints raw values.

Recommended workflow:

- Put only allowlist specs in the repo: `dotkc.spec`
- Use `dotkc run --spec-file ./dotkc.spec -- <cmd>` to inject secrets

## Troubleshooting

### "dotkc not found"

Set plugin config `dotkcBin` to an absolute path, or ensure `dotkc` is on PATH for the Gateway service.

### "failed to parse dotkc --openclaw JSON"

- Run the underlying command by hand on the host:

```bash
dotkc status --openclaw
```

- Ensure nothing else is writing to stdout (no banners, no extra logs).

### Vault/key problems

Run:

```bash
dotkc doctor --openclaw
```

And verify:

- vault exists (synced ciphertext)
- key exists (local file)
- dotkc can decrypt

## What else we should add (next)

- Stronger output filtering: reject any plaintext-looking env output defensively
- A safe “run” tool: allow execution only via a spec file allowlist + command allowlist
- Tests (golden JSON parsing + failure modes)
- Publish to npm as an installable plugin package (optional)
