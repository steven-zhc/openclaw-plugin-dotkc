# dotkc OpenClaw plugin (L2)

This plugin exposes **typed OpenClaw tools** for dotkc so agents can interact with dotkc via a constrained interface.

Docs: https://dotkc-openclaw.hczhang.com/

dotkc manual: https://dotkc.hczhang.com/

## Tools

- `dotkc_status` (required)
- `dotkc_doctor` (optional)
- `dotkc_inspect` (optional, redacted by default)

## Install

```bash
# from npm (recommended)
openclaw plugins install dotkc-openclaw@0.1.2
openclaw gateway restart

# or local dev link
openclaw plugins install -l /path/to/dotkc-openclaw
openclaw gateway restart
```

Note: this plugin bundles `dotkc` as a dependency, so you do not need to install dotkc globally.

## Configure (~/.openclaw/openclaw.json)

```json5
{
  plugins: {
    entries: {
      "dotkc-openclaw-plugin": {
        enabled: true,
        config: {
          // dotkcBin: "dotkc", // optional override (default uses bundled dotkc)
          dotkcBin: "",
          specFile: "./dotkc.spec",
          // vaultPath: "/path/to/dotkc.vault",
          // keyPath: "~/.dotkc/key",
          allowUnsafe: false
        }
      }
    }
  },

  // Allow optional plugin tools (choose a profile and then opt-in)
  tools: {
    // profile: "coding",
    allow: ["dotkc"]
  }
}
```

## Security stance

Required on OpenClaw hosts: set `DOTKC_NO_LEAK=1` (enforces no-leak mode: blocks `dotkc get` and `--unsafe-values`).

- This plugin is designed to **avoid secrets entering model context**.
- `dotkc_inspect` uses `dotkc run --openclaw` and is expected to be **redacted**.
- Do not enable `allowUnsafe` unless you fully understand the leakage risk.

## Notes

- Plugins run in-process with the OpenClaw Gateway. Treat this as trusted code.
- This repo is an MVP skeleton; we should add tests + stricter output filtering.
