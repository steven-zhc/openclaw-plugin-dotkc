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

function* walkStrings(v: any): Generator<string> {
  if (v == null) return;
  if (typeof v === 'string') {
    yield v;
    return;
  }
  if (typeof v === 'number' || typeof v === 'boolean') return;
  if (Array.isArray(v)) {
    for (const x of v) yield* walkStrings(x);
    return;
  }
  if (typeof v === 'object') {
    for (const x of Object.values(v)) yield* walkStrings(x);
  }
}

function shannonEntropy(s: string) {
  const str = String(s);
  const n = str.length;
  if (n === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of str) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let ent = 0;
  for (const c of freq.values()) {
    const p = c / n;
    ent -= p * Math.log2(p);
  }
  return ent;
}

function detectLeak(input: { stdout: string; stderr: string; parsed: any }) {
  const reasons: string[] = [];

  const out = `${input.stdout ?? ''}\n${input.stderr ?? ''}`;

  // 1) KEY=VALUE (common accidental dotenv leak)
  // Require an uppercase-ish key, and at least one non-space char in value.
  const kv = /(^|\n)([A-Z_][A-Z0-9_]{2,})=([^\n\r]+)(\r?\n|$)/g;
  let m: RegExpExecArray | null;
  while ((m = kv.exec(out))) {
    const key = m[2];
    const val = (m[3] ?? '').trim();
    if (!val) continue;
    // Ignore obvious redactions.
    if (/\[REDACTED_BY_PLUGIN\]/.test(val) || /\*\*\* \(len=\d+\)/.test(val)) continue;
    reasons.push(`Detected dotenv-like output: ${key}=…`);
    break;
  }

  // 2) Common token prefixes
  const tokenPrefixes = ['sk-', 'ghp_', 'github_pat_', 'xoxb-', 'xoxp-', 'AKIA', 'ASIA'];
  for (const p of tokenPrefixes) {
    if (out.includes(p)) {
      reasons.push(`Detected token-like prefix: ${p}`);
      break;
    }
  }

  // 3) High-entropy long strings anywhere in parsed JSON
  // Heuristic: long-ish strings with high entropy often indicate secrets.
  for (const s of walkStrings(input.parsed)) {
    if (s.length < 32) continue;
    // Skip URLs/paths (low risk, high entropy sometimes)
    if (/^https?:\/\//.test(s)) continue;
    if (s.includes('/') && s.length < 180) continue;

    const ent = shannonEntropy(s);
    if (ent >= 4.0) {
      reasons.push(`Detected high-entropy string (len=${s.length}, H=${ent.toFixed(2)})`);
      break;
    }
  }

  return reasons;
}

function leakBlockedResponse(reasons: string[]) {
  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify(
          {
            ok: false,
            code: 2,
            error: 'LEAK_BLOCKED: refusing to return suspected secret material to the model',
            reasons,
            hint: 'Inspect on the host manually (never via agent tool output). Ensure DOTKC_NO_LEAK=1 on OpenClaw hosts.',
          },
          null,
          2,
        ),
      },
    ],
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
      const reasons = detectLeak({ stdout: res.out, stderr: res.err, parsed });
      if (reasons.length) return leakBlockedResponse(reasons);

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
        const reasons = detectLeak({ stdout: res.out, stderr: res.err, parsed });
        if (reasons.length) return leakBlockedResponse(reasons);

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

        const reasons = detectLeak({ stdout: res.out, stderr: res.err, parsed });
        if (reasons.length) return leakBlockedResponse(reasons);

        // Defensive redaction: even if dotkc (or a wrapper) accidentally includes cleartext values,
        // never return suspicious value-like fields to the model unless allowUnsafe is explicitly enabled.
        const safe = deepRedact(parsed, { allowUnsafe });

        return { content: [{ type: 'text', text: JSON.stringify(safe, null, 2) }] };
      },
    },
    { optional: true },
  );
}
