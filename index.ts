import { Type } from '@sinclair/typebox';
import { spawn } from 'node:child_process';

// Prefer a stable plugin id (over package-derived ids).
export const id = 'dotkc';

function runDotkc({ dotkcBin, args, stdinText }: { dotkcBin: string; args: string[]; stdinText?: string }) {
  return new Promise<{ code: number; out: string; err: string }>((resolve) => {
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

/**
 * Defensive redaction: keep structure, but never allow obvious value-bearing fields
 * to pass through unless explicitly allowed.
 *
 * This is a best-effort guardrail. The primary guarantee should still come from:
 * - dotkc default redaction
 * - never enabling unsafe value output in agent workflows
 */
function deepRedact(value: any, { allowUnsafe }: { allowUnsafe: boolean }) {
  if (value == null) return value;

  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;

  if (Array.isArray(value)) return value.map((v) => deepRedact(v, { allowUnsafe }));

  const out: any = {};
  for (const [k, v] of Object.entries(value)) {
    const key = String(k);

    const isEnvMap = key === 'env' || key === 'dotenv' || key === 'values';
    const looksSensitiveKey = /(^|_)(value|secret|token|apikey|api_key|password)(_|$)/i.test(key);

    if (!allowUnsafe && looksSensitiveKey && typeof v === 'string') {
      out[key] = '[REDACTED_BY_PLUGIN]';
      continue;
    }

    if (!allowUnsafe && isEnvMap && v && typeof v === 'object' && !Array.isArray(v)) {
      const m: any = {};
      for (const [ek, ev] of Object.entries(v as any)) {
        m[String(ek)] = typeof ev === 'string' ? '[REDACTED_BY_PLUGIN]' : deepRedact(ev, { allowUnsafe });
      }
      out[key] = m;
      continue;
    }

    out[key] = deepRedact(v, { allowUnsafe });
  }
  return out;
}

function toolErrorPayload({ code, error, stderr }: { code: number; error: string; stderr: string }) {
  return {
    ok: false,
    code,
    error,
    stderr: (stderr ?? '').slice(0, 2000),
  };
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
      const res = await runDotkc({ dotkcBin, args });
      const parsed = tryParseOpenClawJson(res.out);
      if (!parsed || parsed.format !== 'openclaw') {
        return { content: [{ type: 'text', text: JSON.stringify(toolErrorPayload({ code: res.code, error: 'dotkc_status: failed to parse dotkc --openclaw JSON', stderr: res.err }), null, 2) }] };
      }
      const safe = deepRedact(parsed, { allowUnsafe: false });
      return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }] };
    },
  });

  api.registerTool(
    {
      name: 'dotkc_doctor',
      description: 'dotkc doctor as OpenClaw JSON diagnostics.',
      parameters: Type.Object({}),
      async execute(_id: string, _params: any) {
        const args = ['doctor', '--openclaw', ...buildVaultArgs(cfg)];
        const res = await runDotkc({ dotkcBin, args });
        const parsed = tryParseOpenClawJson(res.out);
        if (!parsed || parsed.format !== 'openclaw') {
          return { content: [{ type: 'text', text: JSON.stringify(toolErrorPayload({ code: res.code, error: 'dotkc_doctor: failed to parse dotkc --openclaw JSON', stderr: res.err }), null, 2) }] };
        }
        const safe = deepRedact(parsed, { allowUnsafe: false });
        return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }] };
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
        const allowUnsafe = Boolean(cfg?.allowUnsafe);

        const args = ['run', '--spec-file', specFile, '--openclaw', ...buildVaultArgs(cfg)];
        if (allowUnsafe) args.splice(1, 0, '--unsafe-values');

        const res = await runDotkc({ dotkcBin, args });
        const parsed = tryParseOpenClawJson(res.out);
        if (!parsed || parsed.format !== 'openclaw') {
          return { content: [{ type: 'text', text: JSON.stringify(toolErrorPayload({ code: res.code, error: 'dotkc_inspect: failed to parse dotkc --openclaw JSON', stderr: res.err }), null, 2) }] };
        }

        // Defensive redaction: even if dotkc (or a wrapper) accidentally includes cleartext values,
        // never return suspicious value-like fields to the model unless allowUnsafe is explicitly enabled.
        const safe = deepRedact(parsed, { allowUnsafe });

        return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }] };
      },
    },
    { optional: true },
  );
}
