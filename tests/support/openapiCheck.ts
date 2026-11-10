import { openApiDocument } from '../../server/openapi';

/**
 * A small JSON Schema checker for the subset the OpenAPI document uses (type, enum, const, pattern, format uuid and date-time, min/max, properties,
 * required, additionalProperties, items, oneOf, allOf, $ref), and a way to find the operation a request belongs to. It exists so tests can check
 * real requests and responses against the document: a description that is wrong in either direction fails.
 */
type J = Record<string, any>;
const doc: J = openApiDocument;

function resolve(schema: J): J {
  let s = schema;
  for (let i = 0; i < 20 && s && s.$ref; i++) {
    const parts = String(s.$ref).replace(/^#\//, '').split('/');
    s = parts.reduce((acc: any, p) => acc?.[p], doc);
    if (!s) throw new Error(`unresolved reference ${schema.$ref}`);
  }
  return s;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export function validate(schema: J, value: unknown, at = '$'): string[] {
  const s = resolve(schema);
  const errs: string[] = [];
  if (s.oneOf) {
    const ok = s.oneOf.filter((alt: J) => validate(alt, value, at).length === 0).length;
    return ok === 1 ? [] : [`${at}: matches ${ok} of the ${s.oneOf.length} alternatives`];
  }
  if (s.allOf) for (const part of s.allOf) errs.push(...validate(part, value, at));
  if ('const' in s && value !== s.const) errs.push(`${at}: must be ${JSON.stringify(s.const)}`);
  if (s.enum && !s.enum.includes(value)) errs.push(`${at}: ${JSON.stringify(value)} is not one of ${s.enum.join(', ')}`);
  const type = s.type;
  if (type) {
    const actual = value === null ? 'null' : Array.isArray(value) ? 'array' : Number.isInteger(value) && typeof value === 'number' ? 'integer' : typeof value;
    const okType = type === actual || (type === 'number' && (actual === 'integer' || typeof value === 'number')) || (type === 'integer' && actual === 'integer');
    if (!okType) return [...errs, `${at}: expected ${type}, got ${actual}`];
  }
  if (typeof value === 'string') {
    if (s.pattern && !new RegExp(s.pattern).test(value)) errs.push(`${at}: does not match ${s.pattern}`);
    if (s.format === 'uuid' && !UUID.test(value)) errs.push(`${at}: not a uuid`);
    if (s.format === 'date-time' && (Number.isNaN(Date.parse(value)) || !/^\d{4}-\d\d-\d\dT/.test(value))) errs.push(`${at}: not a date-time`);
    if (s.format === 'uri') { try { new URL(value); } catch { errs.push(`${at}: not a uri`); } }
    if (s.minLength !== undefined && value.length < s.minLength) errs.push(`${at}: too short`);
    if (s.maxLength !== undefined && value.length > s.maxLength) errs.push(`${at}: too long`);
  }
  if (typeof value === 'number') {
    if (s.minimum !== undefined && value < s.minimum) errs.push(`${at}: below ${s.minimum}`);
    if (s.maximum !== undefined && value > s.maximum) errs.push(`${at}: above ${s.maximum}`);
  }
  if (Array.isArray(value)) {
    if (s.minItems !== undefined && value.length < s.minItems) errs.push(`${at}: too few items`);
    if (s.maxItems !== undefined && value.length > s.maxItems) errs.push(`${at}: too many items`);
    if (s.items) value.forEach((v, i) => errs.push(...validate(s.items, v, `${at}[${i}]`)));
  }
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    const o = value as J;
    for (const r of s.required ?? []) if (!(r in o)) errs.push(`${at}: missing "${r}"`);
    for (const [k, v] of Object.entries(o)) {
      if (s.properties?.[k]) errs.push(...validate(s.properties[k], v, `${at}.${k}`));
      else if (s.additionalProperties === false) errs.push(`${at}: unexpected "${k}"`);
    }
  }
  return errs;
}

export interface Operation { method: string; template: string; operationId: string; op: J }

const toMatcher = (template: string) => new RegExp('^' + template.replace(/[.*+?^$()|[\]\\]/g, '\\$&').replace(/\{[^}]+\}/g, '[^/]+') + '$');
const operations: Operation[] = [];
for (const [template, item] of Object.entries<J>(doc.paths)) {
  for (const [method, op] of Object.entries<J>(item)) operations.push({ method: method.toUpperCase(), template, operationId: op.operationId, op });
}

export function findOperation(method: string, pathname: string): Operation | null {
  return operations.find((o) => o.method === method.toUpperCase() && toMatcher(o.template).test(pathname)) ?? null;
}

/** Problems with a request body or a response against the document ([] when it conforms). */
export function checkRequest(o: Operation, body: unknown): string[] {
  const rb = o.op.requestBody;
  if (body === undefined || body === null) return rb?.required ? [`${o.operationId}: the document says a body is required`] : [];
  if (!rb) return [`${o.operationId}: the document describes no request body`];
  return validate(rb.content['application/json'].schema, body).map((e) => `${o.operationId} request ${e}`);
}

export function checkResponse(o: Operation, status: number, body: unknown): string[] {
  let r = o.op.responses?.[String(status)];
  if (!r) return [`${o.operationId}: status ${status} is not described`];
  r = resolve(r);
  const content = r.content?.['application/json'];
  if (!content) return [];
  return validate(content.schema, body).map((e) => `${o.operationId} ${status} ${e}`);
}

export const allOperations = operations;
