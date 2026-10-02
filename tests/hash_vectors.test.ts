import { describe, it, expect } from 'vitest';
import { computeEventHash, verifyHashChain, GENESIS_PREV_HASH, canonicalJson, canonicalJsonV2 } from '../shared/crypto';

/**
 * Known-answer tests. The expected hashes below are fixed literals. The version 1 value was produced
 * by the ORIGINAL pre-migration code (shared/crypto.ts at commit f105eb0), so a change to the v1
 * format cannot slip through by being applied consistently to both sides of a test.
 */
const PROJECT = '11111111-1111-1111-1111-111111111111';
const PREV = 'ab'.repeat(32);

describe('Known-answer hashes', () => {
  it('version 1 (written before the database built the chain) still hashes to the value the original code produced', async () => {
    const hash = await computeEventHash({
      seq: 2, project_id: PROJECT, actor_type: 'creator', actor_id: 'actor-1', action: 'project.claimed',
      subject_type: 'project', subject_id: PROJECT,
      // includes an astral-plane key and a U+FF5E key: UTF-16 order puts the emoji first
      payload: JSON.parse('{"name":"Zoë","b":[1,2.5],"\\uD83D\\uDE00":1,"\\uFF5E":2,"q":"a\\"b\\\\c"}'),
      prev_hash: PREV, timestamp: '2026-09-30T10:00:00.000Z'
    });
    expect(hash).toBe('35932187032d2386aa852363210222daa8c025d9796eeee3340d622f18eb2e8f');
  });

  it('version 1 orders keys by UTF-16 unit, version 2 by code point (they must not be swapped)', () => {
    const payload = JSON.parse('{"\\uD83D\\uDE00":1,"\\uFF5E":2}');
    expect(canonicalJson(payload)).toBe('{"\u{1F600}":1,"～":2}');
    expect(canonicalJsonV2(payload)).toBe('{"～":2,"\u{1F600}":1}');
  });

  it('version 2 hashes the exact documented byte string', async () => {
    // The literal envelope is written out here so the format is visible, then hashed independently.
    const envelope =
      '{"action":"project.claimed","actor_id":"actor-1","actor_type":"creator","payload":{"a":1,"b":"Zoë"},' +
      `"prev_hash":"${PREV}","project_id":"${PROJECT}","seq":2,"subject_id":"${PROJECT}","subject_type":"project",` +
      '"timestamp":"2026-09-30T10:00:00.000Z"}';
    expect(envelope).not.toContain(' ');
    const hash = await computeEventHash({
      seq: 2, project_id: PROJECT, actor_type: 'creator', actor_id: 'actor-1', action: 'project.claimed',
      subject_type: 'project', subject_id: PROJECT, payload: { a: 1, b: 'Zoë' }, prev_hash: PREV,
      timestamp: '2026-09-30T10:00:00.000Z', hash_version: 2, canonical_payload: '{"a":1,"b":"Zoë"}'
    });
    expect(hash).toBe('53837265316dd893139a689ec12665a8654ea137769900ea0f1290df6908ce75');
  });
});

describe('verifyHashChain on version 2 events', () => {
  async function chain() {
    const base = {
      seq: 1, project_id: PROJECT, actor_type: 'system', actor_id: 'a', action: 'x', subject_type: 'project',
      subject_id: PROJECT, payload: { n: 1 }, prev_hash: GENESIS_PREV_HASH, timestamp: '2026-09-30T10:00:00.000Z',
      hash_version: 2, canonical_payload: '{"n":1}'
    };
    return [{ ...base, hash: await computeEventHash(base) }];
  }

  it('accepts a consistent event', async () => {
    expect((await verifyHashChain(await chain())).isValid).toBe(true);
  });

  it('rejects an event whose payload column disagrees with the hashed canonical_payload', async () => {
    const [event] = await chain();
    const result = await verifyHashChain([{ ...event, payload: { n: 2 } }]);
    expect(result.isValid).toBe(false);
    expect(result.brokenAtSeq).toBe(1);
    expect(result.reason).toMatch(/does not match the payload that was hashed/);
  });

  it('rejects an event whose canonical_payload is not valid JSON, or is missing', async () => {
    const [event] = await chain();
    expect((await verifyHashChain([{ ...event, canonical_payload: '{not json' }])).isValid).toBe(false);
    await expect(verifyHashChain([{ ...event, canonical_payload: null }])).rejects.toThrow(/needs its canonical_payload/);
  });

  it('rejects a changed canonical_payload even when the payload column is changed to match', async () => {
    const [event] = await chain();
    const result = await verifyHashChain([{ ...event, payload: { n: 2 }, canonical_payload: '{"n":2}' }]);
    expect(result.isValid).toBe(false);
    expect(result.reason).toMatch(/Hash integrity mismatch/);
  });
});
