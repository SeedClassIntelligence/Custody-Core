// Custody Core gateway: the pre-receive hook of a door's mirror.
//
// git runs this while the pushed objects are still in quarantine (not yet part of the mirror). Any non-zero exit
// refuses the whole push, and nothing reaches GitHub. In order:
//   1. every pushed ref must be a branch under refs/heads/door/<door id>/ (no tags, no other branches);
//   2. the new commits are scanned for secrets with gitleaks; any finding refuses the push;
//   3. the push is forwarded to GitHub atomically, each ref leased to the value the mirror had, so a change on
//      GitHub since the last refresh is never overwritten. If GitHub refuses, the developer's push fails too.
// The outcome is written to CUSTODY_RESULT_FILE for the server to record in the project's event log.
//
// Plain JavaScript on purpose: it runs as a separate process for every push, with no build step.
// It receives only the settings below (never the server's own environment).

import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const ZERO = '0000000000000000000000000000000000000000';
const env = process.env;
const resultFile = env.CUSTODY_RESULT_FILE;
const updates = [];

function finish(accepted, details) {
  if (resultFile) {
    try {
      fs.writeFileSync(resultFile, JSON.stringify({ accepted, updates, ...details }));
    } catch {
      // the server records "no result" instead
    }
  }
  process.exit(accepted ? 0 : 1);
}

function refuse(reason, lines, extra = {}) {
  for (const line of ['', 'Custody Core refused this push.', ...lines, '']) process.stderr.write(`${line}\n`);
  finish(false, { reason, ...extra });
}

const input = fs.readFileSync(0, 'utf8');
for (const line of input.split('\n')) {
  const m = /^([0-9a-f]{40}) ([0-9a-f]{40}) (\S+)$/.exec(line.trim());
  if (m) updates.push({ old: m[1], new: m[2], ref: m[3] });
}

const doorId = env.CUSTODY_DOOR_ID;
const upstream = env.CUSTODY_UPSTREAM_URL;
const auth = env.CUSTODY_UPSTREAM_AUTH;
if (!doorId || !upstream || !auth || !resultFile) {
  refuse('gateway_misconfigured', ['The gateway is not configured correctly. Nothing was changed.']);
}
if (updates.length === 0) refuse('no_updates', ['Nothing to push.']);

// 1. Branch policy.
const prefix = `refs/heads/door/${doorId}/`;
const outside = updates.filter((u) => !u.ref.startsWith(prefix) || u.ref.length === prefix.length);
if (outside.length > 0) {
  refuse('ref_not_allowed', [
    `This door can only push branches under door/${doorId}/.`,
    ...outside.map((u) => `  not allowed: ${u.ref.replace(/^refs\/heads\//, '')}`),
    `For example: git push origin HEAD:door/${doorId}/my-change`
  ], { refs: outside.map((u) => u.ref) });
}

// 2. Secret scan of every commit the push adds (reachable from the new tips, not from anything already here).
const tips = updates.filter((u) => u.new !== ZERO).map((u) => u.new);
let scanner = 'none';
if (tips.length > 0) {
  const gitleaks = env.CUSTODY_GITLEAKS;
  if (!gitleaks) {
    refuse('scanner_unavailable', ['The secret scanner is not installed on the gateway, so no push can be accepted.']);
  }
  scanner = env.CUSTODY_GITLEAKS_VERSION ? `gitleaks ${env.CUSTODY_GITLEAKS_VERSION}` : 'gitleaks';
  const report = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'custody-scan-')), 'report.json');
  const scan = spawnSync(
    gitleaks,
    ['git', '--no-banner', '--redact', '--log-level', 'error', '--exit-code', '42', '--report-format', 'json', '--report-path', report,
      '--log-opts', `${tips.join(' ')} --not --all`, '.'],
    { encoding: 'utf8', timeout: 5 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 }
  );
  let findings = [];
  try {
    findings = JSON.parse(fs.readFileSync(report, 'utf8'));
  } catch {
    findings = [];
  }
  fs.rmSync(path.dirname(report), { recursive: true, force: true });
  if (scan.status === 42) {
    // Only where and what kind: the secret itself is never shown, logged or recorded.
    const safe = findings.slice(0, 50).map((f) => ({
      rule: String(f.RuleID ?? ''),
      description: String(f.Description ?? ''),
      file: String(f.File ?? ''),
      line: Number(f.StartLine ?? 0),
      commit: String(f.Commit ?? '')
    }));
    refuse('secret_found', [
      `The secret scanner found ${findings.length} possible secret${findings.length === 1 ? '' : 's'}:`,
      ...safe.map((f) => `  ${f.file}:${f.line}  ${f.rule}  (commit ${f.commit.slice(0, 12)})`),
      'Remove it from these commits (not just from the latest one), then push again.',
      'If it was a real key, treat it as leaked and replace it.'
    ], { findings: safe, finding_count: findings.length, scanner });
  }
  if (scan.status !== 0) {
    process.stderr.write(`${(scan.stderr || '').slice(-2000)}\n`);
    refuse('scanner_failed', ['The secret scanner could not check this push, so it was not accepted. Try again.'], { scanner });
  }
}

// 3. Forward to GitHub: all refs or none, each only if GitHub still has what the mirror had.
const args = ['-c', `http.extraHeader=${auth}`, '-c', 'credential.helper=', 'push', '--porcelain', '--atomic', '--no-verify'];
for (const u of updates) args.push(`--force-with-lease=${u.ref}:${u.old === ZERO ? '' : u.old}`);
args.push(upstream);
for (const u of updates) args.push(u.new === ZERO ? `:${u.ref}` : `${u.new}:${u.ref}`);
const push = spawnSync('git', args, { encoding: 'utf8', timeout: 10 * 60 * 1000, maxBuffer: 16 * 1024 * 1024 });
if (push.status !== 0) {
  const detail = `${push.stdout || ''}\n${push.stderr || ''}`
    .split('\n')
    .map((l) => l.trim())
    .filter((l) => l && !/authorization/i.test(l))
    .slice(-8);
  refuse('upstream_refused', [
    'GitHub did not accept the push, so nothing was changed:',
    ...detail.map((l) => `  ${l}`),
    'If someone else changed this branch, fetch and try again.'
  ], { scanner, upstream_detail: detail });
}

process.stderr.write(`Custody Core: scanned (${scanner}) and saved to the creator's repository.\n`);
finish(true, { scanner });
