/**
 * Path rules for work sessions (docs/integration/PHASE5_DESIGN.md, 4.2). Pure: no git, no files, no clock.
 *
 * A session's request names three lists of path patterns: where it may read, where it may write, and what is
 * prohibited. This module answers one question about one repository path: may this session read it, may it write it,
 * and if not, why. The filtered view and the push check both ask it; neither interprets a pattern itself.
 *
 * DIALECT (nothing clever: no character classes, no braces, no negation)
 *   *   any run of characters except "/"            (inside a segment; "**" mixed into a longer segment counts as "*")
 *   **  as a whole segment: zero or more whole segments; but a FINAL "**" needs at least one ("a/**" is everything UNDER a,
 *       not a file that happens to be called a)
 *   ?   exactly one character except "/"
 *   everything else is literal.
 *
 * ANCHORING: patterns are anchored at the repository root. The one exception: a PROHIBITED pattern with no "/" (for
 * example ".env*") matches that name at any depth, as .gitignore does: whoever writes ".env*" means every .env.
 *
 * STRICT WHERE IT GRANTS, CONSERVATIVE WHERE IT DENIES: allow patterns match exactly (case-sensitive, no normalization);
 * prohibited patterns match case-insensitively, after Unicode compatibility normalization, and also with trailing dots and
 * spaces removed from each segment (how Windows reads names), so "server/MIGRATIONS/x" is refused when "server/migrations/**"
 * is prohibited. Prohibited always wins over allowed.
 *
 * ALWAYS REFUSED (whatever the lists say): invalid paths; any component that is ".git" or ".gitmodules" in any of the
 * spellings git itself treats as the same; and, for writing, the sensitive CI files below unless a write pattern names them.
 */

export type DenyReason =
  | 'invalid_path' //          not a path that can be safely used at all
  | 'always_refused' //        .git or .gitmodules in some spelling
  | 'prohibited' //            matches a prohibited pattern
  | 'not_readable' //          writing needs the path to be readable too (no blind writes)
  | 'not_writable' //          no allowed write pattern matches
  | 'sensitive_not_named'; //  a CI or pipeline file, and no write pattern names it

export type Decision = { allowed: true } | { allowed: false; reason: DenyReason; detail: string };

export class PatternError extends Error {
  constructor(
    readonly list: string,
    readonly pattern: string,
    message: string
  ) {
    super(`${list}: ${message} (${JSON.stringify(pattern)})`);
  }
}

export const MAX_PATTERN_LENGTH = 200;
export const MAX_PATH_LENGTH = 4096;
export const MAX_SEGMENT_BYTES = 255;

// ---- characters we refuse in any path --------------------------------------------------------------------------------
// Control (Cc), format (Cf: zero-width, bidirectional overrides, BOM), unpaired surrogates (Cs), and line and paragraph
// separators. Format characters can make one name look like another; the rest are never part of an honest file name.
const FORBIDDEN_CHARS = /[\p{Cc}\p{Cf}\p{Cs}\p{Zl}\p{Zp}]/u;

/** Why a repository path cannot be used at all, or null. */
export function repoPathProblem(path: string): string | null {
  if (typeof path !== 'string' || path.length === 0) return 'the path is empty';
  if (path.length > MAX_PATH_LENGTH) return `the path is longer than ${MAX_PATH_LENGTH} characters`;
  if (path.startsWith('/')) return 'the path is not relative to the repository root';
  if (path.includes('\\')) return 'the path contains a backslash';
  if (FORBIDDEN_CHARS.test(path)) return 'the path contains a control, invisible or separator character';
  for (const segment of path.split('/')) {
    if (segment === '') return 'the path has an empty segment';
    if (segment === '.' || segment === '..') return `the path contains "${segment}"`;
    if (Buffer.byteLength(segment, 'utf8') > MAX_SEGMENT_BYTES) return `a path segment is longer than ${MAX_SEGMENT_BYTES} bytes`;
  }
  return null;
}

/** Why a PATTERN is not acceptable, or null. */
export function patternProblem(pattern: string): string | null {
  if (typeof pattern !== 'string' || pattern.length === 0) return 'the pattern is empty';
  if (pattern.length > MAX_PATTERN_LENGTH) return `the pattern is longer than ${MAX_PATTERN_LENGTH} characters`;
  if (pattern.startsWith('/') || pattern.startsWith('~')) return 'patterns are relative to the repository root and cannot start with / or ~';
  if (pattern.includes('\\')) return 'the pattern contains a backslash';
  if (FORBIDDEN_CHARS.test(pattern)) return 'the pattern contains a control, invisible or separator character';
  for (const segment of pattern.split('/')) {
    if (segment === '') return 'the pattern has an empty segment';
    if (segment === '.' || segment === '..') return `the pattern contains "${segment}"`;
  }
  return null;
}

// ---- folding (for denying) -------------------------------------------------------------------------------------------

/** An approximation of case folding that errs toward treating names as equal: compatibility-normalize, then up and down. */
export function fold(s: string): string {
  return s.normalize('NFKC').toUpperCase().toLowerCase();
}

/** How Windows reads a name: trailing dots and spaces do not count. */
function windowsRead(segment: string): string {
  return segment.replace(/[. ]+$/u, '');
}

/** The spellings of one path that a prohibited pattern is tested against. */
function denyVariants(segments: string[]): string[][] {
  const folded = segments.map(fold);
  const win = folded.map((s) => (windowsRead(s) === '' ? s : windowsRead(s)));
  const same = win.every((s, i) => s === folded[i]);
  return same ? [folded] : [folded, win];
}

// ---- matching one segment ---------------------------------------------------------------------------------------------

/**
 * Glob match of one segment (no "/") by the classic two-pointer method with backtracking to the last "*": at worst
 * quadratic in the segment and pattern lengths, never exponential, so a hostile pattern cannot stall the server.
 * Works on code points, so "?" is one character, not one UTF-16 unit.
 */
function matchSegment(pattern: string[], text: string[]): boolean {
  let p = 0;
  let t = 0;
  let star = -1;
  let mark = 0;
  while (t < text.length) {
    if (p < pattern.length && (pattern[p] === '?' || (pattern[p] !== '*' && pattern[p] === text[t]))) {
      p++;
      t++;
    } else if (p < pattern.length && pattern[p] === '*') {
      star = p++;
      mark = t;
    } else if (star >= 0) {
      p = star + 1;
      t = ++mark;
    } else {
      return false;
    }
  }
  while (p < pattern.length && pattern[p] === '*') p++;
  return p === pattern.length;
}

interface Compiled {
  readonly source: string;
  /** Pattern segments; "**" stays "**" only when it is the whole segment, otherwise runs of "*" collapse to one. */
  readonly segments: string[][];
  readonly doubleStar: boolean[];
  /** The literal (wildcard-free) segments, folded: what the pattern explicitly NAMES. */
  readonly named: Set<string>;
  readonly noSlash: boolean;
}

function compile(list: string, pattern: string, folded: boolean): Compiled {
  const problem = patternProblem(pattern);
  if (problem) throw new PatternError(list, pattern, problem);
  const parts = pattern.split('/');
  const segments: string[][] = [];
  const doubleStar: boolean[] = [];
  const named = new Set<string>();
  for (const raw of parts) {
    const part = folded ? fold(raw) : raw;
    if (part === '**') {
      segments.push(['*']);
      doubleStar.push(true);
      continue;
    }
    doubleStar.push(false);
    segments.push(Array.from(part.replace(/\*{2,}/g, '*')));
    if (!/[*?]/.test(raw)) named.add(fold(raw));
  }
  return { source: pattern, segments, doubleStar, named, noSlash: parts.length === 1 };
}

/** Does the compiled pattern match these whole path segments? "**" segments are handled by dynamic programming: no blow-up. */
function matchPath(c: Compiled, path: string[][]): boolean {
  const n = c.segments.length;
  const m = path.length;
  // ok[i][j]: pattern segments i.. match path segments j..
  const ok: boolean[][] = Array.from({ length: n + 1 }, () => new Array<boolean>(m + 1).fill(false));
  ok[n][m] = true;
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m; j >= 0; j--) {
      // a final "**" must consume at least one segment: "a/**" is what is under a/, not a itself
      if (c.doubleStar[i] && i === n - 1) ok[i][j] = j < m;
      else if (c.doubleStar[i]) ok[i][j] = ok[i + 1][j] || (j < m && ok[i][j + 1]);
      else ok[i][j] = j < m && matchSegment(c.segments[i], path[j]) && ok[i + 1][j + 1];
    }
  }
  return ok[0][0];
}

const codePoints = (segments: string[]) => segments.map((s) => Array.from(s));

function matchesExact(c: Compiled, path: string): boolean {
  return matchPath(c, codePoints(path.split('/')));
}

/** A prohibited pattern: case-insensitive, normalized, Windows-trailing-dot aware; a slash-less one matches any segment. */
function matchesProhibited(c: Compiled, path: string): boolean {
  for (const variant of denyVariants(path.split('/'))) {
    const cps = codePoints(variant);
    if (c.noSlash && !c.doubleStar[0]) {
      if (cps.some((s) => matchSegment(c.segments[0], s))) return true;
    } else if (matchPath(c, cps)) {
      return true;
    }
  }
  return false;
}

// ---- names that are never allowed -------------------------------------------------------------------------------------

/** True when this one path component is ".git" or ".gitmodules" in any spelling git itself would treat as the same. */
export function isGitSpecialName(component: string): 'git' | 'gitmodules' | null {
  let c = fold(component);
  const colon = c.indexOf(':'); // NTFS alternate data streams: ".git::$INDEX_ALLOCATION"
  if (colon >= 0) c = c.slice(0, colon);
  c = windowsRead(c);
  if (c === '.git' || c === 'git~1') return 'git';
  if (c === '.gitmodules' || c === 'gitmod~1') return 'gitmodules';
  return null;
}

/**
 * Pipeline and CI files: whoever can edit one can run code with the creator's secrets. Matched at any depth, case-
 * insensitively. A write pattern must NAME one (a literal segment, no wildcard) to include it.
 */
export const SENSITIVE_NAMES: readonly string[] = [
  '.github',
  '.gitlab',
  '.gitlab-ci.yml',
  '.circleci',
  '.buildkite',
  '.woodpecker',
  '.woodpecker.yml',
  '.drone.yml',
  '.travis.yml',
  '.gitea',
  '.forgejo',
  'jenkinsfile',
  'azure-pipelines.yml',
  'bitbucket-pipelines.yml',
  'appveyor.yml',
  'cloudbuild.yaml',
  'cloudbuild.yml'
].map(fold);

const MODES_OF_REGULAR_FILES = new Set(['100644', '100755']);

/** Only regular files are ever part of a view or accepted from a session. Symlinks (120000) and submodules (160000) are not. */
export function isRegularFileMode(mode: string): boolean {
  return MODES_OF_REGULAR_FILES.has(mode);
}

// ---- the rule set -----------------------------------------------------------------------------------------------------

export interface PathRuleSet {
  allowedRead: readonly string[];
  allowedWrite: readonly string[];
  prohibited: readonly string[];
}

export class PathRules {
  private readonly read: Compiled[];
  private readonly write: Compiled[];
  private readonly prohibited: Compiled[];

  /** Throws PatternError for a pattern that is not acceptable. */
  constructor(set: PathRuleSet) {
    this.read = set.allowedRead.map((p) => compile('allowed read paths', p, false));
    this.write = set.allowedWrite.map((p) => compile('allowed write paths', p, false));
    this.prohibited = set.prohibited.map((p) => compile('prohibited paths', p, true));
  }

  private isProhibited(path: string): boolean {
    return this.prohibited.some((c) => matchesProhibited(c, path));
  }

  explainRead(path: string): Decision {
    const problem = repoPathProblem(path);
    if (problem) return { allowed: false, reason: 'invalid_path', detail: problem };
    if (this.isProhibited(path)) return { allowed: false, reason: 'prohibited', detail: 'the path matches a prohibited pattern' };
    if (!this.read.some((c) => matchesExact(c, path))) return { allowed: false, reason: 'not_readable', detail: 'no allowed read pattern matches the path' };
    return { allowed: true };
  }

  explainWrite(path: string): Decision {
    const problem = repoPathProblem(path);
    if (problem) return { allowed: false, reason: 'invalid_path', detail: problem };
    const segments = path.split('/');
    const special = segments.map(isGitSpecialName).find(Boolean);
    if (special) return { allowed: false, reason: 'always_refused', detail: special === 'git' ? 'a .git component is never allowed' : '.gitmodules is never allowed' };
    if (this.isProhibited(path)) return { allowed: false, reason: 'prohibited', detail: 'the path matches a prohibited pattern' };
    if (!this.read.some((c) => matchesExact(c, path))) return { allowed: false, reason: 'not_readable', detail: 'a path that cannot be read cannot be written either' };
    if (!this.write.some((c) => matchesExact(c, path))) return { allowed: false, reason: 'not_writable', detail: 'no allowed write pattern matches the path' };
    const folded = segments.map(fold);
    for (const entry of SENSITIVE_NAMES) {
      if (!folded.includes(entry) && !folded.map(windowsRead).includes(entry)) continue;
      const named = this.write.some((c) => matchesExact(c, path) && c.named.has(entry));
      if (!named) return { allowed: false, reason: 'sensitive_not_named', detail: `${entry} is a pipeline file; a write pattern must name it` };
    }
    return { allowed: true };
  }

  canRead(path: string): boolean {
    return this.explainRead(path).allowed;
  }

  canWrite(path: string): boolean {
    return this.explainWrite(path).allowed;
  }
}
