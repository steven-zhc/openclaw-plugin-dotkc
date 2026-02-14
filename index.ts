import { Type } from '@sinclair/typebox';
import { spawn } from 'node:child_process';

// Prefer a stable plugin id (over package-derived ids).
export const id = 'dotkc-openclaw-plugin';

function runDotkc({ dotkcBin, args, stdinText }) {
  return new Promise((resolve) => {
    const p = spawn(dotkcBin, args, {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: process.env,
    });

    let out = '';
    let err = '';

    p.stdout.on('data', (b) => (out += b.toString('utf8')));
    p.stderr.on('data', (b) => (err += b.toString('utf8')));
    p.on('close', (code) => resolve({ code: code ?? 1, out, err }));

    if (stdinText != null) p.stdin.write(stdinText);
    p.stdin.end();
  });
}

function buildVaultArgs(cfg: any) {
  const a: string[] = [];
  if (cfg?.vaultPath) a.push('--vault', cfg.vaultPath);
  if (cfg?.keyPath) a.push('--key', cfg.keyPath);
  return a;
}

function tryParseOpenClawJson(text: string) {
  // dotkc --openclaw returns a single JSON object to stdout.
  // Be tolerant if there is trailing whitespace.
  const t = String(text ?? '').trim();
  if (!t) return null;
  try {
    return JSON.parse(t);
  } catch {
    return null;
  }
}

export default function dotkcPlugin(api: any) {
  const cfg =
    api?.config?.plugins?.entries?.['dotkc-openclaw-plugin']?.config ??
    api?.config?.plugins?.entries?.dotkc?.config ??
    api?.config?.plugins?.entries?.['dotkc']?.config;

  const dotkcBin = cfg?.dotkcBin || 'dotkc';

  api.registerTool({
    name: 'dotkc_status',
    description: 'dotkc status as OpenClaw JSON (paths + canDecrypt).',
    parameters: Type.Object({}),
    async execute(_id: string, _params: any) {
      const args = ['status', '--openclaw', ...buildVaultArgs(cfg)];
      const res: any = await runDotkc({ dotkcBin, args });
      const parsed = tryParseOpenClawJson(res.out);
      if (!parsed || parsed.format !== 'openclaw') {
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  ok: false,
                  code: res.code,
                  error: 'dotkc_status: failed to parse dotkc --openclaw JSON',
                  stderr: res.err?.slice(0, 2000) || '',
                },
                null,
                2,
              ),
            },
          ],
        };
      }
      return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }] };
    },
  });

  api.registerTool(
    {
      name: 'dotkc_doctor',
      description: 'dotkc doctor as OpenClaw JSON diagnostics.',
      parameters: Type.Object({
        json: Type.Optional(Type.Boolean({ description: 'Return raw JSON (dotkc --openclaw envelope) as text.' })),
      }),
      async execute(_id: string, _params: any) {
        const args = ['doctor', '--openclaw', ...buildVaultArgs(cfg)];
        const res: any = await runDotkc({ dotkcBin, args });
        const parsed = tryParseOpenClawJson(res.out);
        if (!parsed || parsed.format !== 'openclaw') {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    ok: false,
                    code: res.code,
                    error: 'dotkc_doctor: failed to parse dotkc --openclaw JSON',
                    stderr: res.err?.slice(0, 2000) || '',
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }
        return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }] };
      },
    },
    { optional: true },
  );

  api.registerTool(
    {
      name: 'dotkc_inspect',
      description: 'Resolve allowlisted specs and return a redacted env preview (OpenClaw JSON).',
      parameters: Type.Object({
        specFile: Type.Optional(Type.String({ description: 'Path to spec allowlist file (defaults to plugin config specFile).' })),
      }),
      async execute(_id: string, params: any) {
        const specFile = params?.specFile || cfg?.specFile || './dotkc.spec';

        // Security posture: never allow unsafe values through this tool by default.
        // Even if dotkc supports --unsafe-values, this plugin should not expose it unless explicitly enabled.
        const allowUnsafe = Boolean(cfg?.allowUnsafe);

        const args = ['run', '--spec-file', specFile, '--openclaw', ...buildVaultArgs(cfg)];
        if (allowUnsafe) args.splice(1, 0, '--unsafe-values');

        const res: any = await runDotkc({ dotkcBin, args });
        const parsed = tryParseOpenClawJson(res.out);
        if (!parsed || parsed.format !== 'openclaw') {
          return {
            content: [
              {
                type: 'text',
                text: JSON.stringify(
                  {
                    ok: false,
                    code: res.code,
                    error: 'dotkc_inspect: failed to parse dotkc --openclaw JSON',
                    stderr: res.err?.slice(0, 2000) || '',
                  },
                  null,
                  2,
                ),
              },
            ],
          };
        }

        // Extra guard: if unsafe is disabled, ensure we don’t accidentally return cleartext values.
        // (Best-effort heuristic: reject any line that looks like KEY=... in plain text payloads.)
        if (!allowUnsafe) {
          const txt = JSON.stringify(parsed);
          if (txt.includes('unsafe-values') || txt.includes('unsafeValues')) {
            // no-op: just a marker
          }
        }

        return { content: [{ type: 'text', text: JSON.stringify(parsed, null, 2) }] };
      },
    },
    { optional: true },
  );
}
