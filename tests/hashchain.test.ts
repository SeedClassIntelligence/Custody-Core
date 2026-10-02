import { describe, it, expect } from 'vitest';
import {
  canonicalJson,
  computeEventHash,
  verifyHashChain,
  GENESIS_PREV_HASH,
  EventHashInput
} from '../shared/crypto';

describe('Cryptographic Append-Only Event Hash Chain', () => {
  it('canonicalJson produces identical deterministically-sorted output regardless of key order', () => {
    const objA = { z: 1, a: { b: 2, a: 1 }, m: 'test' };
    const objB = { m: 'test', a: { a: 1, b: 2 }, z: 1 };
    expect(canonicalJson(objA)).toBe(canonicalJson(objB));
  });

  it('computes initial hash from 64 zeros genesis prev_hash', async () => {
    const event1: EventHashInput = {
      seq: 1,
      project_id: 'proj_123',
      actor_type: 'creator',
      actor_id: 'creator_abc',
      action: 'project.claimed',
      subject_type: 'project',
      subject_id: 'proj_123',
      payload: { name: 'My Secure Core', purpose: 'Protected DSP' },
      prev_hash: GENESIS_PREV_HASH,
      timestamp: '2026-09-30T10:00:00.000Z'
    };

    const hash1 = await computeEventHash(event1);
    expect(hash1).toBeDefined();
    expect(hash1).toHaveLength(64);
    expect(/^[a-f0-9]{64}$/.test(hash1)).toBe(true);

    const verification = await verifyHashChain([{ ...event1, hash: hash1 }]);
    expect(verification.isValid).toBe(true);
    expect(verification.totalEvents).toBe(1);
  });

  it('validates a multi-event hash chain correctly', async () => {
    const event1: EventHashInput = {
      seq: 1,
      project_id: 'proj_123',
      actor_type: 'creator',
      actor_id: 'creator_abc',
      action: 'project.claimed',
      subject_type: 'project',
      subject_id: 'proj_123',
      payload: { name: 'Aether Engine' },
      prev_hash: GENESIS_PREV_HASH,
      timestamp: '2026-09-30T10:00:00.000Z'
    };
    const hash1 = await computeEventHash(event1);

    const event2: EventHashInput = {
      seq: 2,
      project_id: 'proj_123',
      actor_type: 'system',
      actor_id: 'sys_app_lock',
      action: 'repository.locked',
      subject_type: 'repository',
      subject_id: 'repo_core_01',
      payload: { repo: 'aether-core', is_core: true },
      prev_hash: hash1,
      timestamp: '2026-09-30T10:01:00.000Z'
    };
    const hash2 = await computeEventHash(event2);

    const event3: EventHashInput = {
      seq: 3,
      project_id: 'proj_123',
      actor_type: 'creator',
      actor_id: 'creator_abc',
      action: 'door.created',
      subject_type: 'door',
      subject_id: 'door_789',
      payload: { developer: 'alex@dev.net', duration_days: 7 },
      prev_hash: hash2,
      timestamp: '2026-09-30T10:02:00.000Z'
    };
    const hash3 = await computeEventHash(event3);

    const chain = [
      { ...event1, hash: hash1 },
      { ...event2, hash: hash2 },
      { ...event3, hash: hash3 }
    ];

    const result = await verifyHashChain(chain);
    expect(result.isValid).toBe(true);
    expect(result.totalEvents).toBe(3);
  });

  it('CRITICAL FIX: Altering actor_id, actor_type, project_id, subject_id, or subject_type MUST break the hash chain', async () => {
    const originalEvent: EventHashInput = {
      seq: 1,
      project_id: 'proj_alpha',
      actor_type: 'creator',
      actor_id: 'creator_real_owner',
      action: 'project.claimed',
      subject_type: 'project',
      subject_id: 'proj_alpha',
      payload: { proprietary: true },
      prev_hash: GENESIS_PREV_HASH,
      timestamp: '2026-09-30T10:00:00.000Z'
    };
    const originalHash = await computeEventHash(originalEvent);

    // 1. Alter actor_id: someone tries to attribute the event to someone else
    const forgedActor = { ...originalEvent, actor_id: 'impostor_user_id', hash: originalHash };
    const res1 = await verifyHashChain([forgedActor]);
    expect(res1.isValid).toBe(false);
    expect(res1.brokenAtSeq).toBe(1);

    // 2. Alter actor_type
    const forgedActorType = { ...originalEvent, actor_type: 'system', hash: originalHash };
    const res2 = await verifyHashChain([forgedActorType]);
    expect(res2.isValid).toBe(false);

    // 3. Alter project_id
    const forgedProject = { ...originalEvent, project_id: 'proj_stolen', hash: originalHash };
    const res3 = await verifyHashChain([forgedProject]);
    expect(res3.isValid).toBe(false);

    // 4. Alter subject_id
    const forgedSubject = { ...originalEvent, subject_id: 'subject_tampered', hash: originalHash };
    const res4 = await verifyHashChain([forgedSubject]);
    expect(res4.isValid).toBe(false);

    // 5. Alter subject_type
    const forgedSubjectType = { ...originalEvent, subject_type: 'repository', hash: originalHash };
    const res5 = await verifyHashChain([forgedSubjectType]);
    expect(res5.isValid).toBe(false);
  });

  it('detects broken linkage when previous hash does not match prior event hash', async () => {
    const event1: EventHashInput = {
      seq: 1,
      project_id: 'proj_1',
      actor_type: 'creator',
      actor_id: 'cr_1',
      action: 'project.claimed',
      subject_type: 'project',
      subject_id: 'proj_1',
      payload: { name: 'Test' },
      prev_hash: GENESIS_PREV_HASH,
      timestamp: '2026-09-30T10:00:00.000Z'
    };
    const hash1 = await computeEventHash(event1);

    // Maliciously forged prev_hash on event 2
    const event2: EventHashInput = {
      seq: 2,
      project_id: 'proj_1',
      actor_type: 'creator',
      actor_id: 'cr_1',
      action: 'door.created',
      subject_type: 'door',
      subject_id: 'door_1',
      payload: {},
      prev_hash: 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff',
      timestamp: '2026-09-30T10:01:00.000Z'
    };
    const hash2 = await computeEventHash(event2);

    const res = await verifyHashChain([
      { ...event1, hash: hash1 },
      { ...event2, hash: hash2 }
    ]);

    expect(res.isValid).toBe(false);
    expect(res.brokenAtSeq).toBe(2);
    expect(res.reason).toContain('Previous hash linkage broken');
  });
});
