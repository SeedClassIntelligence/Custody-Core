import { spawnSync } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Starts, stops or inspects the local Supabase stack used for login (Supabase Auth) tests.
 * Needs Docker. Only the services login needs are started; the rest are excluded to save time and memory.
 *   npm run auth-stack:start | auth-stack:stop | auth-stack:status
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const cli = path.join(root, 'node_modules', 'supabase', 'dist', 'supabase.js');
const EXCLUDE = 'studio,imgproxy,edge-runtime,logflare,vector,supavisor,realtime,storage-api,mailpit,postgres-meta,postgrest';

export interface AuthStackConfig {
  apiUrl: string;
  anonKey: string;
  /** Secret of the throwaway local stack, used only by tests that mint tokens. */
  jwtSecret: string;
  /** Direct database URL of the local stack, used only by tests that adjust its auth data. */
  dbUrl: string;
}

function run(args: string[]) {
  return spawnSync(process.execPath, [cli, ...args], {
    cwd: root,
    encoding: 'utf8',
    env: { ...process.env, DO_NOT_TRACK: '1', SUPABASE_TELEMETRY_DISABLED: '1' }
  });
}

/** Returns the running stack's public settings, or null if it is not running. */
export function readAuthStack(): AuthStackConfig | null {
  const res = run(['status', '-o', 'env']);
  if (res.status !== 0) return null;
  const env = Object.fromEntries(
    res.stdout
      .split('\n')
      .filter((l) => l.includes('='))
      .map((l) => {
        const i = l.indexOf('=');
        return [l.slice(0, i), l.slice(i + 1).replace(/^"|"$/g, '')];
      })
  );
  const anonKey = env.ANON_KEY || env.PUBLISHABLE_KEY;
  if (!env.API_URL || !anonKey) return null;
  return { apiUrl: env.API_URL, anonKey, jwtSecret: env.JWT_SECRET ?? '', dbUrl: env.DB_URL ?? '' };
}

/** Starts the stack if needed (takes a few minutes the first time, while images download). */
export function ensureAuthStack(): AuthStackConfig {
  const existing = readAuthStack();
  if (existing) return existing;

  const docker = spawnSync('docker', ['info'], { encoding: 'utf8' });
  if (docker.status !== 0) {
    throw new Error(
      'Login tests need Docker, and the Docker daemon is not running. Start Docker, then run `npm run auth-stack:start`.'
    );
  }
  const start = run(['start', '-x', EXCLUDE]);
  if (start.status !== 0) {
    throw new Error(`The local Supabase stack failed to start:\n${(start.stderr || start.stdout).slice(-1500)}`);
  }
  const started = readAuthStack();
  if (!started) throw new Error('The local Supabase stack started but its settings could not be read.');
  return started;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const command = process.argv[2];
  if (command === 'start') {
    const cfg = ensureAuthStack();
    console.log(`Local Supabase Auth is running at ${cfg.apiUrl}`);
  } else if (command === 'stop') {
    const res = run(['stop', '--no-backup']);
    console.log((res.stdout || res.stderr).trim());
  } else if (command === 'status') {
    const cfg = readAuthStack();
    console.log(cfg ? `running at ${cfg.apiUrl}` : 'not running');
  } else {
    console.error('usage: auth-stack.ts start|stop|status');
    process.exit(2);
  }
}
