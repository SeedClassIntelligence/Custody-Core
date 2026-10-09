/**
 * The developer's signing key, made and kept in this browser. The private half is created non-extractable: the
 * browser can sign with it but never hand it out, so it never leaves this device. Only the public half is sent to
 * the server. Kept in IndexedDB; clearing site data or using another device means registering a new key (the old
 * one is retired and both stay on record).
 */
const DB = 'custody-core-signing';
const STORE = 'keys';
const ID = 'agreement-key';

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function load(): Promise<CryptoKeyPair | null> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE).objectStore(STORE).get(ID);
    req.onsuccess = () => resolve((req.result as CryptoKeyPair) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function save(pair: CryptoKeyPair): Promise<void> {
  const db = await openDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, 'readwrite');
    tx.objectStore(STORE).put(pair, ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

const toB64 = (buf: ArrayBuffer) => btoa(String.fromCharCode(...new Uint8Array(buf)));

export interface DeviceKey {
  publicKeySpki: string;
  fingerprint: string;
  sign(message: string): Promise<string>;
}

async function wrap(pair: CryptoKeyPair): Promise<DeviceKey> {
  const spki = await crypto.subtle.exportKey('spki', pair.publicKey);
  const fp = await crypto.subtle.digest('SHA-256', spki);
  return {
    publicKeySpki: toB64(spki),
    fingerprint: Array.from(new Uint8Array(fp), (b) => b.toString(16).padStart(2, '0')).join(''),
    sign: async (message) =>
      toB64(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new TextEncoder().encode(message)))
  };
}

/** This device's key, or null if none was made here yet. */
export async function existingDeviceKey(): Promise<DeviceKey | null> {
  const pair = await load().catch(() => null);
  return pair ? wrap(pair) : null;
}

/** This device's key, made now if needed. */
export async function deviceKey(): Promise<DeviceKey> {
  let pair = await load().catch(() => null);
  if (!pair) {
    pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])) as CryptoKeyPair;
    await save(pair);
  }
  return wrap(pair);
}
