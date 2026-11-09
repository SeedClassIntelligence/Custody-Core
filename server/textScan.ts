import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { findScanner, type Scanner } from './gateway/scanner';

const run = promisify(execFile);

/**
 * Scans text for secrets with the same scanner the git gateway uses (gitleaks), before the text is written into a
 * permanent record. Whatever goes into the project's tamper-evident record cannot be taken out again, so a key
 * pasted into a request must be stopped before it is recorded, not noticed afterwards.
 *
 * Fails closed, like the gateway: with no scanner, or a scanner that could not run, the answer is "do not record".
 * Never returns, logs or stores the secret itself, only which rules matched and how many times.
 */
export type TextScan =
  | { status: 'clean' }
  | { status: 'found'; rules: string[]; count: number }
  | { status: 'unavailable' }
  | { status: 'failed' };

export async function scanTextForSecrets(text: string, scanner: Scanner | null = findScanner()): Promise<TextScan> {
  if (!scanner) return { status: 'unavailable' };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'custody-textscan-'));
  try {
    fs.writeFileSync(path.join(dir, 'request.json'), text, { mode: 0o600 });
    const report = path.join(dir, 'report.json');
    let exit = 0;
    try {
      await run(scanner.path, ['dir', '--no-banner', '--redact', '--log-level', 'error', '--exit-code', '42', '--report-format', 'json', '--report-path', report, path.join(dir, 'request.json')], {
        timeout: 30_000,
        maxBuffer: 4 * 1024 * 1024
      });
    } catch (err: any) {
      exit = typeof err?.code === 'number' ? err.code : -1;
    }
    if (exit === 42) {
      let findings: any[] = [];
      try {
        findings = JSON.parse(fs.readFileSync(report, 'utf8'));
      } catch {
        findings = [];
      }
      const rules = [...new Set(findings.map((f) => String(f?.RuleID ?? '')).filter(Boolean))].sort();
      return { status: 'found', rules, count: Math.max(findings.length, 1) };
    }
    return exit === 0 ? { status: 'clean' } : { status: 'failed' };
  } catch {
    return { status: 'failed' };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}
