import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

/**
 * Downloads the secret scanner the git gateway uses (gitleaks), a pinned version checked against its published
 * SHA-256, into .tools/gitleaks. `npm run tools:gitleaks`. The Dockerfile runs it too.
 */
export const GITLEAKS_VERSION = '8.28.0';
const SHA256: Record<string, string> = {
  linux_x64: 'a65b5253807a68ac0cafa4414031fd740aeb55f54fb7e55f386acb52e6a840eb',
  linux_arm64: 'eff65261156100e5d94a6b3dec313d532fddfe19ae1590bf7a2b4f2699128356',
  darwin_x64: 'edf5a507008b0d2ef4959575772772770586409c1f6f74dabf19cbe7ec341ced',
  darwin_arm64: 'd942f3ad147250c9edbaab3fed9e482f98d3b59ba10ae97b8d75647e3ade492c'
};

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
export const GITLEAKS_TARGET = path.join(root, '.tools', 'gitleaks');

function installedVersion(): string | null {
  try {
    return execFileSync(GITLEAKS_TARGET, ['version'], { encoding: 'utf8' }).trim();
  } catch {
    return null;
  }
}

export async function installGitleaks(): Promise<string> {
  if (installedVersion() === GITLEAKS_VERSION) return GITLEAKS_TARGET;
  const platform = { linux: 'linux', darwin: 'darwin' }[process.platform as string];
  const arch = { x64: 'x64', arm64: 'arm64' }[process.arch as string];
  const key = `${platform}_${arch}`;
  if (!platform || !arch || !SHA256[key]) throw new Error(`No pinned gitleaks build for ${process.platform}/${process.arch}.`);

  const name = `gitleaks_${GITLEAKS_VERSION}_${key}.tar.gz`;
  const url = `https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${name}`;
  const res = await fetch(url, { signal: AbortSignal.timeout(120_000) });
  if (!res.ok) throw new Error(`Downloading ${url} failed: ${res.status}`);
  const data = Buffer.from(await res.arrayBuffer());
  const digest = crypto.createHash('sha256').update(data).digest('hex');
  if (digest !== SHA256[key]) throw new Error(`gitleaks download does not match its published SHA-256 (got ${digest}). Not installed.`);

  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'gitleaks-'));
  try {
    fs.writeFileSync(path.join(tmp, name), data);
    execFileSync('tar', ['-xzf', path.join(tmp, name), '-C', tmp, 'gitleaks']);
    fs.mkdirSync(path.dirname(GITLEAKS_TARGET), { recursive: true });
    fs.copyFileSync(path.join(tmp, 'gitleaks'), `${GITLEAKS_TARGET}.new`);
    fs.chmodSync(`${GITLEAKS_TARGET}.new`, 0o755);
    fs.renameSync(`${GITLEAKS_TARGET}.new`, GITLEAKS_TARGET);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
  const v = installedVersion();
  if (v !== GITLEAKS_VERSION) throw new Error(`gitleaks installed but reports version ${v}.`);
  return GITLEAKS_TARGET;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  installGitleaks()
    .then((p) => console.log(`gitleaks ${GITLEAKS_VERSION} ready at ${path.relative(process.cwd(), p) || p}`))
    .catch((err) => {
      console.error(err.message);
      process.exit(1);
    });
}
