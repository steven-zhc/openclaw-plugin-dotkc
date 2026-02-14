# dotkc OpenClaw plugin (L2)

This plugin exposes **typed OpenClaw tools** for dotkc so agents can interact with dotkc via a constrained interface.

Docs (GitHub Pages): https://steven-zhc.github.io/openclaw-plugin-dotkc/

## Tools

- `dotkc_status` (required)
- `dotkc_doctor` (optional)
- `dotkc_inspect` (optional, redacted by default)

## Install (dev / local path)

```bash
# from the OpenClaw host
openclaw plugins install -l /path/to/openclaw-plugin-dotkc
openclaw gateway restart
```

## Configure (~/.openclaw/openclaw.json)

```json5
{
  plugins: {
    entries: {
      "dotkc-openclaw-plugin": {
        enabled: true,
        config: {
          dotkcBin: "dotkc",
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

- This plugin is designed to **avoid secrets entering model context**.
- `dotkc_inspect` uses `dotkc run --openclaw` and is expected to be **redacted**.
- Do not enable `allowUnsafe` unless you fully understand the leakage risk.

## Notes

- Plugins run in-process with the OpenClaw Gateway. Treat this as trusted code.
- This repo is an MVP skeleton; we should add tests + stricter output filtering.
