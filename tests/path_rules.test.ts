import { describe, it, expect } from 'vitest';
import {
  PathRules,
  PatternError,
  SENSITIVE_NAMES,
  fold,
  isGitSpecialName,
  isRegularFileMode,
  patternProblem,
  repoPathProblem,
  type DenyReason,
  type PathRuleSet
} from '../server/pathRules';
import { pathProblem as requestPathProblem } from '../server/workSessions';

/**
 * Path rules (Phase 5b, docs/integration/PHASE5_DESIGN.md 4.2): pure, so tested exhaustively before anything uses them.
 * Three layers: examples for every rule of the dialect and every refusal; Unicode and case tricks; and a property test
 * that checks the matcher against a second, independently written one on thousands of random patterns and paths.
 */
const rules = (set: Partial<PathRuleSet>) => new PathRules({ allowedRead: [], allowedWrite: [], prohibited: [], ...set });
const read = (patterns: string[], paths: string[], prohibited: string[] = []) => {
  const r = rules({ allowedRead: patterns, prohibited });
  return paths.map((p) => [p, r.canRead(p)] as const);
};
const reasonOf = (r: PathRules, path: string, mode: 'read' | 'write'): DenyReason | 'allowed' => {
  const d = mode === 'read' ? r.explainRead(path) : r.explainWrite(path);
  return d.allowed ? 'allowed' : d.reason;
};

describe('the pattern dialect', () => {
  it('* matches any run of characters except "/"', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('src/*.ts', 'src/a.ts')).toBe(true);
    expect(t('src/*.ts', 'src/.ts')).toBe(true); // an empty run is a run
    expect(t('src/*.ts', 'src/a/b.ts')).toBe(false); // does not cross "/"
    expect(t('src/*', 'src/a')).toBe(true);
    expect(t('src/*', 'src')).toBe(false);
    expect(t('*', 'a')).toBe(true);
    expect(t('*', 'a/b')).toBe(false);
    expect(t('a*c*e', 'abcde')).toBe(true);
    expect(t('a*c*e', 'ace')).toBe(true);
    expect(t('a*c*e', 'abde')).toBe(false);
    expect(t('*a', 'ba')).toBe(true);
    expect(t('*a', 'bab')).toBe(false);
  });

  it('? matches exactly one character except "/", counting a whole character (not half of an emoji)', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('a?c', 'abc')).toBe(true);
    expect(t('a?c', 'ac')).toBe(false);
    expect(t('a?c', 'abbc')).toBe(false);
    expect(t('a?c', 'a😀c')).toBe(true);
    expect(t('a?c', 'a/c')).toBe(false);
    expect(t('??', 'é1')).toBe(true);
  });

  it('a whole-segment ** matches zero or more whole segments (a final one, at least one)', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('**', 'a')).toBe(true);
    expect(t('**', 'a/b/c')).toBe(true);
    expect(t('a/**', 'a/b')).toBe(true);
    expect(t('a/**', 'a/b/c/d')).toBe(true);
    expect(t('a/**', 'a')).toBe(false); // a file called "a" is not under "a/"
    expect(t('a/**', 'ab/c')).toBe(false);
    expect(t('a/**/b', 'a/b')).toBe(true); // zero segments in the middle
    expect(t('a/**/b', 'a/x/b')).toBe(true);
    expect(t('a/**/b', 'a/x/y/b')).toBe(true);
    expect(t('a/**/b', 'a/x/y/c')).toBe(false);
    expect(t('**/b', 'b')).toBe(true);
    expect(t('**/b', 'x/y/b')).toBe(true);
    expect(t('**/b', 'x/y/bb')).toBe(false);
    expect(t('**/**/b', 'b')).toBe(true);
    expect(t('a/**/**/b', 'a/b')).toBe(true);
  });

  it('** inside a longer segment is just *: it never crosses "/" there', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('server**', 'serverx')).toBe(true);
    expect(t('server**', 'server/x')).toBe(false);
    expect(t('a**b', 'axxb')).toBe(true);
    expect(t('a**b', 'a/b')).toBe(false);
    expect(t('***', 'abc')).toBe(true);
    expect(t('***', 'a/b')).toBe(false);
  });

  it('everything else is literal: dots, brackets, braces, plus, caret, parentheses and the rest', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('a.b', 'a.b')).toBe(true);
    expect(t('a.b', 'axb')).toBe(false); // "." is not "any character"
    expect(t('[ab].ts', '[ab].ts')).toBe(true);
    expect(t('[ab].ts', 'a.ts')).toBe(false); // no character classes
    expect(t('{a,b}.ts', '{a,b}.ts')).toBe(true);
    expect(t('{a,b}.ts', 'a.ts')).toBe(false); // no braces
    expect(t('a+b', 'a+b')).toBe(true);
    expect(t('a+b', 'aab')).toBe(false);
    expect(t('!x', '!x')).toBe(true);
    expect(t('(a|b)', '(a|b)')).toBe(true);
    expect(t('a|b', 'a')).toBe(false);
    expect(t('^a$', '^a$')).toBe(true);
    expect(t('a b', 'a b')).toBe(true);
  });

  it('is anchored at the repository root', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('src/**', 'src/a')).toBe(true);
    expect(t('src/**', 'x/src/a')).toBe(false);
    expect(t('a.ts', 'a.ts')).toBe(true);
    expect(t('a.ts', 'src/a.ts')).toBe(false); // a slash-less ALLOW pattern is root-level only
    expect(t('**/a.ts', 'src/a.ts')).toBe(true); // to mean "anywhere", say so
  });

  it('matching is case-sensitive and exact for what is allowed', () => {
    const t = (p: string, path: string) => read([p], [path])[0][1];
    expect(t('server/**', 'server/a')).toBe(true);
    expect(t('server/**', 'SERVER/a')).toBe(false);
    expect(t('server/**', 'Server/a')).toBe(false);
    expect(t('café/**', 'café/x')).toBe(true);
    expect(t('café/**', 'café/x')).toBe(false); // the decomposed spelling is a different path; nothing is granted by guessing
    expect(t('straße/**', 'STRASSE/x')).toBe(false);
  });

  it('no list means no access: nothing is allowed unless listed', () => {
    const r = rules({});
    expect(r.canRead('a')).toBe(false);
    expect(r.canWrite('a')).toBe(false);
    expect(reasonOf(r, 'a', 'read')).toBe('not_readable');
  });
});

describe('prohibited patterns', () => {
  const allowAll = (prohibited: string[]) => rules({ allowedRead: ['**'], allowedWrite: ['**'], prohibited });

  it('always win over what is allowed', () => {
    const r = allowAll(['server/migrations/**']);
    expect(r.canRead('server/app.ts')).toBe(true);
    expect(r.canRead('server/migrations/001.sql')).toBe(false);
    expect(r.canWrite('server/migrations/001.sql')).toBe(false);
    expect(reasonOf(r, 'server/migrations/001.sql', 'read')).toBe('prohibited');
    expect(reasonOf(r, 'server/migrations/001.sql', 'write')).toBe('prohibited');
  });

  it('a prohibited pattern WITHOUT a "/" matches that name at any depth, files and directories', () => {
    const r = allowAll(['.env*', 'secrets']);
    for (const p of ['.env', '.env.local', 'a/.env', 'a/b/.env.production', 'a/.environment', 'secrets/key', 'x/secrets/key', 'x/y/secrets']) {
      expect(r.canRead(p), p).toBe(false);
    }
    for (const p of ['env', 'a/env.txt', 'my.env', 'secret', 'secretsx/a', 'xsecrets/a']) expect(r.canRead(p), p).toBe(true);
  });

  it('a prohibited pattern WITH a "/" is anchored, like any other: say **/ to mean anywhere', () => {
    const anchored = allowAll(['migrations/**']);
    expect(anchored.canRead('migrations/a')).toBe(false);
    expect(anchored.canRead('server/migrations/a')).toBe(true);
    const anywhere = allowAll(['**/migrations/**']);
    expect(anywhere.canRead('migrations/a')).toBe(false);
    expect(anywhere.canRead('server/migrations/a')).toBe(false);
    expect(anywhere.canRead('server/migrationsx/a')).toBe(true);
  });

  it('a lone ** prohibits everything', () => {
    const r = allowAll(['**']);
    expect(r.canRead('a')).toBe(false);
    expect(r.canRead('a/b')).toBe(false);
  });

  it('match case-insensitively, so a different capital letter is not a way around them', () => {
    const r = allowAll(['server/migrations/**', '.env*']);
    for (const p of ['server/MIGRATIONS/x', 'Server/Migrations/x', 'SERVER/MIGRATIONS/X', 'a/.ENV', '.Env.Local']) expect(r.canRead(p), p).toBe(false);
  });

  it('match across Unicode spellings: compatibility forms, decomposed accents, special case folds', () => {
    const r = allowAll(['server/migrations/**', 'café/**', 'strasse/**']);
    expect(r.canRead('ｓｅｒｖｅｒ/ｍｉｇｒａｔｉｏｎｓ/x')).toBe(false); // full-width letters
    expect(r.canRead('server/migrations/é.sql')).toBe(false);
    expect(r.canRead('café/x')).toBe(false); // decomposed é against a composed pattern
    expect(r.canRead('CAFÉ/x')).toBe(false);
    expect(r.canRead('straße/x')).toBe(false); // ß folds to ss
    expect(r.canRead('STRASSE/x')).toBe(false);
    expect(allowAll(['café/**']).canRead('café/x')).toBe(false); // and the other way round
  });

  it('match the way Windows reads names: trailing dots and spaces do not count', () => {
    const r = allowAll(['server/migrations/**', '.env']);
    expect(r.canRead('server/migrations./x')).toBe(false);
    expect(r.canRead('server/migrations /x')).toBe(false);
    expect(r.canRead('server/migrations. ./x')).toBe(false);
    expect(r.canRead('a/.env.')).toBe(false);
    expect(r.canRead('a/.env ')).toBe(false);
  });

  it('do not over-reach: names that merely resemble a prohibited one stay allowed', () => {
    const r = allowAll(['server/migrations/**']);
    expect(r.canRead('server/migrationsx/a')).toBe(true);
    expect(r.canRead('server/migration/a')).toBe(true);
    expect(r.canRead('xserver/migrations/a')).toBe(true);
    expect(r.canRead('server/migrations')).toBe(true); // a FILE with that name is not under the directory
  });
});

describe('writing', () => {
  const r = rules({ allowedRead: ['server/**', 'shared/**', 'docs/**'], allowedWrite: ['server/gateway/**', 'shared/*.ts', 'docs/**', 'src/**'], prohibited: ['server/gateway/secret*', '.env*'] });

  it('needs an allowed write pattern, an allowed read pattern, and no prohibition', () => {
    expect(r.canWrite('server/gateway/router.ts')).toBe(true);
    expect(r.canWrite('shared/util.ts')).toBe(true);
    expect(r.canWrite('docs/a/b.md')).toBe(true);
    expect(reasonOf(r, 'server/app.ts', 'write')).toBe('not_writable'); // readable, not writable
    expect(reasonOf(r, 'shared/sub/x.ts', 'write')).toBe('not_writable');
    expect(reasonOf(r, 'server/gateway/secret.txt', 'write')).toBe('prohibited');
  });

  it('a path that cannot be read cannot be written (no blind writes)', () => {
    // src/** is allowed for writing, but src is not readable: refused, because writing there could overwrite a file the session never saw
    expect(reasonOf(r, 'src/new.ts', 'write')).toBe('not_readable');
  });

  it('can read without writing, but never write without reading', () => {
    for (const p of ['server/app.ts', 'shared/sub/x.ts', 'src/a', 'docs/a', 'nothing/here']) {
      if (r.canWrite(p)) expect(r.canRead(p), p).toBe(true);
    }
    expect(r.canRead('server/app.ts')).toBe(true);
    expect(r.canWrite('server/app.ts')).toBe(false);
  });
});

describe('paths that can never be used', () => {
  const all = rules({ allowedRead: ['**'], allowedWrite: ['**'] });
  const invalid: Array<[string, string]> = [
    ['', 'empty'],
    ['/etc/passwd', 'absolute'],
    ['a//b', 'empty segment'],
    ['a/./b', 'dot segment'],
    ['a/../b', 'parent segment'],
    ['..', 'parent'],
    ['a\\b', 'backslash'],
    ['a\u0000b', 'NUL'],
    ['a\nb', 'newline'],
    ['a\tb', 'tab'],
    ['a\u007fb', 'DEL'],
    ['a​b', 'zero-width space'],
    ['a‮b', 'right-to-left override'],
    ['﻿a', 'byte order mark'],
    ['a b', 'line separator'],
    ['a b', 'paragraph separator'],
    ['a\ud800b', 'lone surrogate'],
    ['x'.repeat(4097), 'too long'],
    [`a/${'y'.repeat(256)}`, 'segment too long'],
    ['trailing/', 'trailing slash']
  ];
  for (const [path, label] of invalid) {
    it(`refuses ${label}`, () => {
      expect(repoPathProblem(path), label).toEqual(expect.any(String));
      expect(reasonOf(all, path, 'read')).toBe('invalid_path');
      expect(reasonOf(all, path, 'write')).toBe('invalid_path');
    });
  }

  it('accepts ordinary paths, including spaces, unicode, dots and a segment of exactly 255 bytes', () => {
    for (const p of ['a', 'a/b.c', 'my file.txt', 'dir with space/x y.md', 'héllo/日本語/😀.txt', '.hidden/.also', 'a-b_c/d~1', `${'y'.repeat(255)}`]) {
      expect(repoPathProblem(p), p).toBeNull();
    }
    expect(repoPathProblem(`${'é'.repeat(128)}`)).toMatch(/255 bytes/); // 256 bytes
  });
});

describe('.git and .gitmodules are never allowed, in any spelling git treats the same', () => {
  const all = rules({ allowedRead: ['**'], allowedWrite: ['**'] });
  const spellings = ['.git', '.GIT', '.Git', '.git.', '.git ', '.git. .', 'git~1', 'GIT~1', '.git:stream', '.git::$INDEX_ALLOCATION', '.ｇｉｔ'];
  for (const s of spellings) {
    it(`refuses a component spelled ${JSON.stringify(s)}`, () => {
      expect(isGitSpecialName(s), s).toBe('git');
      expect(reasonOf(all, `${s}/config`, 'write')).toBe('always_refused');
      expect(reasonOf(all, `sub/dir/${s}/hooks/x`, 'write')).toBe('always_refused');
      expect(reasonOf(all, `sub/${s}`, 'write')).toBe('always_refused');
    });
  }
  for (const s of ['.gitmodules', '.GITMODULES', '.gitmodules.', '.gitmodules ', 'gitmod~1', '.gitmodules:x']) {
    it(`refuses ${JSON.stringify(s)} (any depth)`, () => {
      expect(isGitSpecialName(s)).toBe('gitmodules');
      expect(reasonOf(all, s, 'write')).toBe('always_refused');
      expect(reasonOf(all, `a/b/${s}`, 'write')).toBe('always_refused');
    });
  }
  it('does not refuse names that only begin with the same letters', () => {
    for (const s of ['.gitignore', '.gitattributes', '.github', '.gitkeep', 'git', 'gitmodules', 'a.git', '.gitx', 'xgit~1', '.git-hooks']) {
      expect(isGitSpecialName(s), s).toBeNull();
    }
    expect(all.canWrite('.gitignore')).toBe(true);
    expect(all.canWrite('docs/.gitkeep')).toBe(true);
  });
  it('is not the lists\' decision: no pattern, however broad or specific, can allow it', () => {
    const named = rules({ allowedRead: ['.git/**', '**'], allowedWrite: ['.git/**', '.gitmodules', '**'] });
    expect(named.canWrite('.git/config')).toBe(false);
    expect(named.canWrite('.gitmodules')).toBe(false);
  });
  it('reading is not blocked by name (such paths cannot exist in a tree); only writing is', () => {
    expect(isGitSpecialName('.gitmodules')).toBe('gitmodules');
    expect(all.canRead('.gitmodules')).toBe(true); // a normal file at the root, readable when the lists say so
  });
});

describe('pipeline and CI files need to be named', () => {
  const broad = rules({ allowedRead: ['**'], allowedWrite: ['**'] });

  it('are refused for writing under a broad pattern, at any depth and in any capitalization', () => {
    const paths = [
      '.github/workflows/ci.yml', 'a/b/.github/workflows/x.yml', '.GitHub/x', '.gitlab-ci.yml', 'svc/.gitlab-ci.yml', '.gitlab/ci/x.yml', '.circleci/config.yml', '.buildkite/pipeline.yml',
      'Jenkinsfile', 'services/api/Jenkinsfile', 'JENKINSFILE', 'azure-pipelines.yml', 'bitbucket-pipelines.yml', '.travis.yml', 'appveyor.yml', 'cloudbuild.yaml', '.drone.yml',
      '.woodpecker/x.yml', '.gitea/workflows/x.yml', '.forgejo/workflows/x.yml', '.github./workflows/x.yml'
    ];
    for (const p of paths) expect(reasonOf(broad, p, 'write'), p).toBe('sensitive_not_named');
  });

  it('can still be READ under a broad pattern', () => {
    expect(broad.canRead('.github/workflows/ci.yml')).toBe(true);
    expect(broad.canRead('Jenkinsfile')).toBe(true);
  });

  it('every listed name is covered', () => {
    for (const name of SENSITIVE_NAMES) expect(reasonOf(broad, `${name}`, 'write'), name).toBe('sensitive_not_named');
  });

  it('a pattern that NAMES the file includes it; a wildcard never names anything', () => {
    const named = (w: string) => rules({ allowedRead: ['**'], allowedWrite: [w] });
    expect(named('.github/workflows/ci.yml').canWrite('.github/workflows/ci.yml')).toBe(true);
    expect(named('.github/**').canWrite('.github/workflows/ci.yml')).toBe(true);
    expect(named('.github/workflows/*.yml').canWrite('.github/workflows/ci.yml')).toBe(true);
    expect(named('Jenkinsfile').canWrite('Jenkinsfile')).toBe(true);
    expect(named('**/Jenkinsfile').canWrite('services/api/Jenkinsfile')).toBe(true);
    expect(named('services/api/Jenkinsfile').canWrite('services/api/Jenkinsfile')).toBe(true);
    // wildcards do not name
    expect(reasonOf(named('.git*/**'), '.github/x.yml', 'write')).toBe('sensitive_not_named');
    expect(reasonOf(named('.github*/x.yml'), '.github/x.yml', 'write')).toBe('sensitive_not_named');
    expect(reasonOf(named('*/workflows/*.yml'), '.github/workflows/ci.yml', 'write')).toBe('sensitive_not_named');
    expect(reasonOf(named('J*'), 'Jenkinsfile', 'write')).toBe('sensitive_not_named');
    expect(reasonOf(named('**'), 'Jenkinsfile', 'write')).toBe('sensitive_not_named');
    expect(reasonOf(named('?github/x'), '.github/x', 'write')).toBe('sensitive_not_named');
  });

  it('naming one does not name the others, and does not widen what else the pattern may write', () => {
    const r = rules({ allowedRead: ['**'], allowedWrite: ['.github/workflows/ci.yml', 'src/**'] });
    expect(r.canWrite('.github/workflows/ci.yml')).toBe(true);
    expect(r.canWrite('.github/workflows/release.yml')).toBe(false); // not matched by the pattern at all
    expect(reasonOf(r, 'src/.github/x.yml', 'write')).toBe('sensitive_not_named'); // src/** does not name .github
    expect(reasonOf(r, 'src/Jenkinsfile', 'write')).toBe('sensitive_not_named');
    expect(r.canWrite('src/a.ts')).toBe(true);
  });

  it('prohibited still wins over a naming pattern', () => {
    const r = rules({ allowedRead: ['**'], allowedWrite: ['.github/**'], prohibited: ['.github/workflows/release.yml'] });
    expect(r.canWrite('.github/workflows/ci.yml')).toBe(true);
    expect(reasonOf(r, '.github/workflows/release.yml', 'write')).toBe('prohibited');
  });

  it('names with different capitals are the same sensitive file; a lookalike is not', () => {
    expect(reasonOf(broad, 'jenkinsfile', 'write')).toBe('sensitive_not_named');
    expect(broad.canWrite('Jenkinsfiles')).toBe(true);
    expect(broad.canWrite('xJenkinsfile')).toBe(true);
    expect(broad.canWrite('github/workflows/x')).toBe(true);
    expect(broad.canWrite('docs/github.md')).toBe(true);
  });
});

describe('what is a valid pattern', () => {
  const bad: Array<[string, RegExp]> = [
    ['', /empty/],
    ['/abs', /cannot start/],
    ['~/x', /cannot start/],
    ['a\\b', /backslash/],
    ['a//b', /empty segment/],
    ['a/', /empty segment/],
    ['a/./b', /"\."/],
    ['a/../b', /"\.\."/],
    ['..', /"\.\."/],
    ['a\u0000b', /control/],
    ['a​b', /control, invisible/],
    ['x'.repeat(201), /longer than 200/]
  ];
  for (const [p, why] of bad) {
    it(`refuses ${JSON.stringify(p.length > 30 ? `${p.slice(0, 12)}...` : p)}`, () => {
      expect(patternProblem(p)).toMatch(why);
      for (const list of ['allowedRead', 'allowedWrite', 'prohibited'] as const) {
        expect(() => rules({ [list]: [p] }), list).toThrow(PatternError);
      }
    });
  }
  it('says which list the bad pattern was in', () => {
    expect(() => rules({ prohibited: ['a//b'] })).toThrow(/prohibited paths: the pattern has an empty segment/);
    expect(() => rules({ allowedWrite: ['..'] })).toThrow(/allowed write paths/);
    expect(() => rules({ allowedRead: ['ok', '/bad'] })).toThrow(/allowed read paths/);
  });
  it('accepts the whole dialect, including a pattern of exactly 200 characters', () => {
    for (const p of ['**', '*', '?', 'a/**/b', '.env*', 'dir with space/*.md', 'héllo/**', '😀*', 'a'.repeat(200)]) expect(patternProblem(p), p).toBeNull();
  });
  it('the request check of Phase 3 and this one agree, including invisible and separator characters', () => {
    const corpus = ['src/**', '', '/a', '~a', 'a/../b', 'a//b', 'a\\b', 'a\u0000b', 'a/./b', 'x'.repeat(201), 'ok/**', '.env*', 'a b', 'é/**', '**/x'];
    for (const p of corpus) expect(patternProblem(p) === null, JSON.stringify(p)).toBe(requestPathProblem(p) === null);
    // the one known difference of Phase 5b is closed: the request check now also refuses what the rules refuse (Phase 5c)
    for (const p of ['a\u200bb', 'a\u202eb', 'a\u2028b', 'a\ufeffb']) {
      expect(patternProblem(p), JSON.stringify(p)).not.toBeNull();
      expect(requestPathProblem(p), JSON.stringify(p)).not.toBeNull();
    }
  });
});

describe('small helpers', () => {
  it('only regular files have a mode that is accepted', () => {
    expect(isRegularFileMode('100644')).toBe(true);
    expect(isRegularFileMode('100755')).toBe(true);
    for (const m of ['120000', '160000', '040000', '100664', '100666', '', '0']) expect(isRegularFileMode(m), m).toBe(false);
  });
  it('fold treats compatibility forms, capitals and special folds as equal', () => {
    expect(fold('ＡＢＣ')).toBe('abc');
    expect(fold('Straße')).toBe('strasse');
    expect(fold('é')).toBe(fold('é'));
  });
});

// ---------------------------------------------------------------------------------------------------------------------------
describe('hostile patterns cannot stall the server', () => {
  const time = (f: () => void) => {
    const t = Date.now();
    f();
    return Date.now() - t;
  };
  it('a pattern built to make a backtracking matcher explode runs in milliseconds', () => {
    const evil = `${'*a'.repeat(40)}*b`.slice(0, 190);
    const r = rules({ allowedRead: [evil, 'x/**/**/**/**/**/**/**/**/y'], prohibited: [evil] });
    const victim = `${'a'.repeat(190)}`;
    expect(time(() => r.canRead(victim))).toBeLessThan(500);
    expect(time(() => r.canRead(`${'x/'.repeat(300)}z`))).toBeLessThan(500);
  });
  it('a path with thousands of segments against many ** is also fast', () => {
    const r = rules({ allowedRead: ['**/a/**/b/**/c/**/d/**'], prohibited: ['**/z/**/y/**'] });
    const deep = Array.from({ length: 1500 }, (_, i) => ['a', 'b', 'c', 'd', 'q'][i % 5]).join('/');
    expect(time(() => r.canRead(deep))).toBeLessThan(2000);
  });
});

// ---------------------------------------------------------------------------------------------------------------------------
/**
 * The property test. A second matcher, written differently (recursion and regular expressions on tiny inputs, where the
 * exponential cases cannot occur), is the oracle. Seeded, so a failure repeats exactly.
 */
function mulberry32(seed: number) {
  return () => {
    seed |= 0;
    seed = (seed + 0x6d2b79f5) | 0;
    let t = Math.imul(seed ^ (seed >>> 15), 1 | seed);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function oracleSegment(pattern: string, text: string): boolean {
  const body = pattern
    .replace(/\*{2,}/g, '*')
    .split('')
    .map((c) => (c === '*' ? '.*' : c === '?' ? '.' : c.replace(/[.+^${}()|[\]\\]/g, '\\$&')))
    .join('');
  return new RegExp(`^${body}$`, 'su').test(text);
}
function oracle(pattern: string, path: string): boolean {
  const go = (ps: string[], xs: string[]): boolean => {
    if (ps.length === 0) return xs.length === 0;
    if (ps.length === 1 && ps[0] === '**') return xs.length > 0; // a final ** needs at least one segment
    if (ps[0] === '**') return go(ps.slice(1), xs) || (xs.length > 0 && go(ps, xs.slice(1)));
    return xs.length > 0 && oracleSegment(ps[0], xs[0]) && go(ps.slice(1), xs.slice(1));
  };
  return go(pattern.split('/'), path.split('/'));
}
/** The oracle for a prohibited pattern: slash-less ones match any one segment. */
function oracleProhibited(pattern: string, path: string): boolean {
  if (!pattern.includes('/') && pattern !== '**') return path.split('/').some((s) => oracleSegment(pattern, s));
  return oracle(pattern, path);
}

describe('property: the matcher agrees with an independently written one', () => {
  const rand = mulberry32(20261109);
  const pick = <T>(xs: T[]): T => xs[Math.floor(rand() * xs.length)];
  const letters = ['a', 'b', 'c', 'ab', 'ba', 'x-y', 'é', '😀'];
  const genPath = () => Array.from({ length: 1 + Math.floor(rand() * 4) }, () => pick(letters)).join('/');
  const genSegment = () => {
    if (rand() < 0.15) return '**';
    let s = '';
    for (let i = 0; i < 1 + Math.floor(rand() * 3); i++) s += pick(['a', 'b', 'c', 'é', '*', '?', 'ab', '*', '😀']);
    return s;
  };
  const genPattern = () => Array.from({ length: 1 + Math.floor(rand() * 4) }, genSegment).join('/');

  it('allow patterns: 6000 random pattern and path pairs', () => {
    let matched = 0;
    for (let i = 0; i < 6000; i++) {
      const pattern = genPattern();
      const path = genPath();
      const expected = oracle(pattern, path);
      if (expected) matched++;
      expect(read([pattern], [path])[0][1], `${pattern}  vs  ${path}`).toBe(expected);
    }
    expect(matched).toBeGreaterThan(300); // the test really exercised matches, not only misses
  });

  it('prohibited patterns: 6000 random pairs (lower-case alphabet, so folding changes nothing)', () => {
    let matched = 0;
    for (let i = 0; i < 6000; i++) {
      const pattern = genPattern();
      const path = genPath();
      const expected = oracleProhibited(pattern, path);
      if (expected) matched++;
      const r = rules({ allowedRead: ['**'], prohibited: [pattern] });
      expect(r.canRead(path), `prohibit ${pattern}  vs  ${path}`).toBe(!expected);
    }
    expect(matched).toBeGreaterThan(300);
  });

  it('invariants over random rule sets: write implies read; prohibited beats allowed; the decision is stable', () => {
    for (let i = 0; i < 3000; i++) {
      const set: PathRuleSet = {
        allowedRead: Array.from({ length: 1 + Math.floor(rand() * 3) }, genPattern),
        allowedWrite: Array.from({ length: Math.floor(rand() * 3) }, genPattern),
        prohibited: Array.from({ length: Math.floor(rand() * 3) }, genPattern)
      };
      const r = new PathRules(set);
      const path = genPath();
      if (r.canWrite(path)) expect(r.canRead(path), `${JSON.stringify(set)} ${path}`).toBe(true);
      if (set.prohibited.some((p) => oracleProhibited(p, path))) {
        expect(r.canRead(path)).toBe(false);
        expect(r.canWrite(path)).toBe(false);
      }
      if (r.canRead(path)) expect(set.allowedRead.some((p) => oracle(p, path))).toBe(true);
      if (r.canWrite(path)) expect(set.allowedWrite.some((p) => oracle(p, path))).toBe(true);
      expect(r.explainWrite(path)).toEqual(r.explainWrite(path));
    }
  });

  it('whatever the lists say, no path with a .git component is ever writable (3000 random lists, hostile spellings)', () => {
    const hostile = ['.git', '.GIT', '.git.', '.git ', 'GIT~1', '.git:x', '.gitmodules', '.GitModules'];
    for (let i = 0; i < 3000; i++) {
      const set: PathRuleSet = { allowedRead: ['**', genPattern()], allowedWrite: ['**', genPattern(), pick(hostile)], prohibited: [] };
      const path = [genPath(), pick(hostile), genPath()].join('/');
      expect(new PathRules(set).canWrite(path), path).toBe(false);
    }
  });
});
