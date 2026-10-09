import fs from 'node:fs';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * Finds the secret scanner (gitleaks). Order: GITLEAKS_PATH, then .tools/gitleaks in this project
 * (`npm run tools:gitleaks` puts it there), then `gitleaks` on PATH. Without it the gateway refuses every push:
 * it never lets code through unscanned.
 */
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

export interface Scanner {
  path: string;
  version: string;
}

let cached: { at: number; scanner: Scanner | null } | null = null;

function probe(candidate: string): Scanner | null {
  const r = spawnSync(candidate, ['version'], { encoding: 'utf8', timeout: 10000 });
  if (r.status !== 0) return null;
  const version = r.stdout.trim();
  return version ? { path: candidate, version } : null;
}

export function findScanner(): Scanner | null {
  // Looked up again at most once a minute, so installing it does not need a restart.
  if (cached && Date.now() - cached.at < 60_000) return cached.scanner;
  const candidates = [process.env.GITLEAKS_PATH, path.join(root, '.tools', 'gitleaks'), 'gitleaks'].filter(Boolean) as string[];
  let scanner: Scanner | null = null;
  for (const c of candidates) {
    if (c.includes(path.sep) && !fs.existsSync(c)) continue;
    scanner = probe(c);
    if (scanner) break;
  }
  cached = { at: Date.now(), scanner };
  return scanner;
}
