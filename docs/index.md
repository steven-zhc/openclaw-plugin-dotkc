---
title: dotkc OpenClaw Plugin
---

<div class="badges">
  <a href="https://dotkc.hczhang.com/"><img alt="dotkc" src="https://img.shields.io/badge/dotkc-manual-2d6cdf"></a>
  <a href="https://github.com/steven-zhc/openclaw-plugin-dotkc"><img alt="GitHub" src="https://img.shields.io/badge/GitHub-repo-181717"></a>
  <a href="https://docs.openclaw.ai/tools/plugin"><img alt="OpenClaw plugins" src="https://img.shields.io/badge/OpenClaw-plugins_docs-ff5a2d"></a>
</div>

<div class="callout">
<strong>Start here:</strong> dotkc manual + best practices → <a href="https://dotkc.hczhang.com/"><strong>dotkc.hczhang.com</strong></a>
</div>

# dotkc OpenClaw Plugin (L2)

Typed OpenClaw tools for **dotkc** so agents can use secrets workflows through a **constrained interface**.

<div class="callout">
<strong>Goal:</strong> let OpenClaw <em>use</em> secrets without printing them (avoid secrets entering model transcripts).
</div>

## Quick start

1) Install dotkc and make sure it can decrypt on the OpenClaw host:

```bash
dotkc status
```

2) Install this plugin (local dev link):

```bash
# from npm (recommended)
openclaw plugins install @hcz/openclaw-plugin-dotkc@0.1.0
openclaw gateway restart

# or local dev link
openclaw plugins install -l /path/to/openclaw-plugin-dotkc
openclaw gateway restart
```

3) Enable the plugin + opt-in tools:

```json5
{
  plugins: {
    entries: {
      dotkc: {
        enabled: true,
        config: {
          dotkcBin: "dotkc",
          specFile: "./dotkc.spec",
          allowUnsafe: false
        }
      }
    }
  },
  tools: { allow: ["dotkc"] }
}
```

<div class="callout">
<strong>Recommended install:</strong> <code>openclaw plugins install @hcz/openclaw-plugin-dotkc@0.1.0</code>
</div>

## What problem this solves

OpenClaw agents often need credentials (API keys, tokens) to run local tools. The unsafe default is to fetch a secret and print it, which can:

- land in the model transcript/context
- leak into logs or debugging output
- get pasted into chat accidentally

This plugin promotes the safer pattern:

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

Intended for **redacted** sanity checks.

<div class="callout callout--warn">
<strong>Important:</strong> by default this plugin does <em>not</em> enable unsafe/raw values.
</div>

## How it works

- The plugin runs **in-process** with the OpenClaw Gateway.
- Each tool spawns `dotkc` as a subprocess and expects a single `--openclaw` JSON object on stdout.
- The tool surface is intentionally small (no “return raw secret values” API).

## Security model / guardrails

- `dotkc_inspect` is designed for redacted output.
- The plugin also applies **defensive redaction**: it redacts obvious value-bearing fields (`env`, `value`, `token`, `apiKey`, etc.) unless you explicitly enable `allowUnsafe`.
- `allowUnsafe` is for debugging on a trusted machine only.
- Do **not** build agent workflows that call `dotkc get` (it prints raw values).

<div class="callout callout--danger">
<strong>Threat model:</strong> if a secret is printed, it can enter model transcripts and/or be sent to the model provider.
Design workflows so secrets are injected into child processes, not displayed.
</div>

## Troubleshooting

### “dotkc not found”

Set `dotkcBin` to an absolute path, or ensure `dotkc` is on PATH for the Gateway service.

### “failed to parse dotkc --openclaw JSON”

Run the underlying command on the host:

```bash
dotkc status --openclaw
```

Ensure nothing else writes to stdout (no banners, no extra logs).

### Vault/key problems

```bash
dotkc doctor --openclaw
```

Check:

- vault exists (synced ciphertext)
- key exists (local file)
- dotkc can decrypt

## Links

- dotkc manual: [dotkc.hczhang.com](https://dotkc.hczhang.com/)
- OpenClaw plugin docs: [docs.openclaw.ai/tools/plugin](https://docs.openclaw.ai/tools/plugin)
- OpenClaw agent tools guide: [docs.openclaw.ai/plugins/agent-tools](https://docs.openclaw.ai/plugins/agent-tools)

## Roadmap

- Stronger leakage detection: fail closed if plaintext-looking env lines appear
- Safe execution tool: run only via spec allowlist + command allowlist (return only exit code + stderr summary)
- Tests (golden JSON parsing + failure modes)
- Optional: publish to npm
