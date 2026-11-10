import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { app } from '../server';
import { openApiDocument } from '../server/openapi';
import { startApp, RunningApp } from './support/api';
import { allOperations, validate } from './support/openapiCheck';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const doc: any = openApiDocument;

/** Every route the server registers, as "METHOD /path/{}" (path parameters all written {}), found by walking the real application. */
function serverRoutes(): string[] {
  const out: string[] = [];
  const mountOf = (layer: any): string => {
    // express keeps a mount path only as a regular expression; the static parts are what we need, and its parameters are in layer.keys
    let src: string = layer.regexp.source;
    if (layer.regexp.fast_slash) return '';
    src = src.replace(/^\^/, '').replace(/\\\/\?\(\?=\\\/\|\$\)$/, '').replace(/\(\?:\\\/\(\[\^\/\]\+\?\)\)/g, '/{}');
    return src.replace(/\\\//g, '/');
  };
  const walk = (stack: any[], prefix: string) => {
    for (const l of stack) {
      if (l.route) {
        for (const m of Object.keys(l.route.methods)) out.push(`${m.toUpperCase()} ${prefix}${String(l.route.path).replace(/:[A-Za-z]+/g, '{}')}`.replace(/\/$/, '') || '/');
      } else if (l.name === 'router' && l.handle?.stack) {
        walk(l.handle.stack, prefix + mountOf(l));
      }
    }
  };
  walk((app as any)._router.stack, '');
  return out;
}
const specRoutes = (filter: (p: string) => boolean) =>
  allOperations.filter((o) => filter(o.template)).map((o) => `${o.method} ${o.template.replace(/\{[^}]+\}/g, '{}')}`);

describe('OpenAPI description (CL-17)', () => {
  let running: RunningApp;
  beforeAll(async () => {
    running = await startApp();
  });
  afterAll(async () => {
    await running?.stop();
  });

  it('describes every /api/v2 route the server has, and nothing it does not have', () => {
    const real = serverRoutes().filter((r) => r.split(' ')[1].startsWith('/api/v2')).sort();
    const described = specRoutes((p) => p.startsWith('/api/v2')).sort();
    expect(real.length).toBeGreaterThanOrEqual(14);
    expect(described).toEqual(real);
  });

  it('describes the owner routes it lists as they exist, and every owner route in those families is listed', () => {
    const real = new Set(serverRoutes());
    const described = specRoutes((p) => p.startsWith('/api/v1'));
    for (const r of described) expect(real.has(r), `described but not served: ${r}`).toBe(true);
    const families = [/\/work-sessions/, /\/promotions/, /\/attestation-authorities/, /\/webhook-endpoints/];
    const family = [...real].filter((r) => r.split(' ')[1].startsWith('/api/v1') && families.some((f) => f.test(r)));
    expect(family.length).toBeGreaterThanOrEqual(20);
    for (const r of family) expect(described.includes(r), `served but not described: ${r}`).toBe(true);
  });

  it('is a structurally valid OpenAPI 3.1 document', () => {
    expect(doc.openapi).toBe('3.1.0');
    expect(doc.info.title).toBeTruthy();
    const ids = new Set<string>();
    const refs: string[] = [];
    const collect = (x: any) => {
      if (Array.isArray(x)) return x.forEach(collect);
      if (x && typeof x === 'object') {
        if (typeof x.$ref === 'string') refs.push(x.$ref);
        Object.values(x).forEach(collect);
      }
    };
    collect(doc);
    for (const r of refs) {
      const target = r.replace(/^#\//, '').split('/').reduce((a: any, p) => a?.[p], doc);
      expect(target, `unresolved ${r}`).toBeTruthy();
    }
    const schemes = Object.keys(doc.components.securitySchemes);
    const tags = new Set(doc.tags.map((t: any) => t.name));
    const methods = ['get', 'post', 'put', 'patch', 'delete'];
    for (const [template, item] of Object.entries<any>(doc.paths)) {
      expect(template.startsWith('/')).toBe(true);
      const inTemplate = [...template.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      for (const m of Object.keys(item)) {
        expect(methods, `${template}: ${m}`).toContain(m);
        const op = item[m];
        const where = `${m.toUpperCase()} ${template}`;
        expect(op.operationId, where).toMatch(/^[a-z][A-Za-z0-9]*$/);
        expect(ids.has(op.operationId), `duplicate operationId ${op.operationId}`).toBe(false);
        ids.add(op.operationId);
        expect(op.summary, where).toBeTruthy();
        for (const t of op.tags) expect(tags.has(t), `${where}: tag ${t}`).toBe(true);
        for (const sec of op.security) for (const name of Object.keys(sec)) expect(schemes, where).toContain(name);
        const declared = (op.parameters ?? []).filter((p: any) => p.in === 'path').map((p: any) => p.name).sort();
        expect(declared, `${where}: path parameters`).toEqual([...inTemplate].sort());
        for (const p of op.parameters ?? []) expect(p.schema, `${where}: parameter ${p.name}`).toBeTruthy();
        const codes = Object.keys(op.responses);
        expect(codes.some((c) => /^2\d\d$/.test(c)), `${where}: needs a success response`).toBe(true);
        for (const c of codes) expect(c).toMatch(/^[1-5]\d\d$/);
        if (['post', 'put', 'patch'].includes(m) && op.requestBody) expect(op.requestBody.content['application/json'].schema, where).toBeTruthy();
      }
    }
    // every machine operation names its credentials; the two that need none say so
    for (const o of allOperations.filter((x) => x.template.startsWith('/api/v2'))) {
      if (o.operationId === 'getOpenApiDocument') expect(o.op.security).toEqual([]);
      else expect(o.op.security).toEqual([{ principalAssertion: [] }]);
    }
    for (const o of allOperations.filter((x) => x.template.startsWith('/api/v1'))) expect(o.op.security).toEqual([{ ownerSession: [] }]);
    // schemas: every "required" names a property that exists
    const check = (s: any, at: string) => {
      if (!s || typeof s !== 'object') return;
      if (Array.isArray(s)) return s.forEach((x, i) => check(x, `${at}[${i}]`));
      if (s.required && s.properties) for (const r of s.required) expect(Object.keys(s.properties), `${at}: required "${r}"`).toContain(r);
      if (s.enum) expect(s.enum.length, `${at}: empty enum`).toBeGreaterThan(0);
      Object.entries(s).forEach(([k, v]) => check(v, `${at}.${k}`));
    };
    check(doc.components.schemas, 'schemas');
    expect(doc.webhooks['custody-event'].post.requestBody.content['application/json'].schema.$ref).toBe('#/components/schemas/WebhookEvent');
  });

  it('docs/openapi.json is exactly what server/openapi.ts produces (run `npm run build:openapi`)', () => {
    const file = fs.readFileSync(path.join(root, 'docs', 'openapi.json'), 'utf8');
    expect(file).toBe(`${JSON.stringify(openApiDocument, null, 2)}\n`);
  });

  it('is served without credentials at GET /api/v2/openapi.json, while every other /api/v2 route still needs them', async () => {
    const r = await fetch(`${running.base}/api/v2/openapi.json`);
    expect(r.status).toBe(200);
    expect(await r.json()).toEqual(JSON.parse(JSON.stringify(openApiDocument)));
    for (const [method, p] of [['GET', '/whoami'], ['GET', '/work-sessions'], ['POST', '/work-sessions'], ['GET', `/work-sessions/${'0'.repeat(8)}-0000-0000-0000-${'0'.repeat(12)}/evidence`]] as const) {
      const res = await fetch(`${running.base}/api/v2${p}`, { method, headers: { 'Content-Type': 'application/json' }, body: method === 'POST' ? '{}' : undefined });
      expect(res.status, `${method} ${p}`).toBe(401);
    }
  });

  it('the schema checker itself catches what it should (so the conformance tests mean something)', () => {
    const schema = doc.components.schemas.EvidenceEvaluation;
    expect(validate(schema, { commit: null, ready: true, requirements: [] })).toEqual([]);
    expect(validate(schema, { commit: null, ready: 'yes', requirements: [] }).join()).toMatch(/expected boolean/);
    expect(validate(schema, { commit: 'abc', ready: true, requirements: [] }).join()).toMatch(/alternatives/);
    expect(validate(schema, { ready: true, requirements: [] }).join()).toMatch(/missing "commit"/);
    expect(validate(schema, { commit: null, ready: true, requirements: [], extra: 1 }).join()).toMatch(/unexpected "extra"/);
    expect(validate(doc.components.schemas.Uuid, 'nope').join()).toMatch(/not a uuid/);
  });
});
