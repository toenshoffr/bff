import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import session from 'express-session';

const VERSION = 'v1';
const IV_BYTES = 12;
const TAG_BYTES = 16;

type Callback<T = void> = (err?: unknown, result?: T) => void;

export function deriveKey(secret: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secret, '', 'bff-session-encryption-v1', 32));
}

/** AES-256-GCM; the session id is bound as AAD so a blob can't be replayed under another sid. */
export function encryptSession(key: Buffer, sid: string, data: unknown): string {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  cipher.setAAD(Buffer.from(sid));
  const ct = Buffer.concat([cipher.update(JSON.stringify(data), 'utf8'), cipher.final()]);
  return `${VERSION}.${Buffer.concat([iv, cipher.getAuthTag(), ct]).toString('base64url')}`;
}

/** Returns null if the blob is malformed, tampered with, or encrypted under a different key/sid. */
export function decryptSession(key: Buffer, sid: string, blob: string): session.SessionData | null {
  try {
    const [version, payload] = blob.split('.');
    if (version !== VERSION || !payload) return null;
    const raw = Buffer.from(payload, 'base64url');
    const iv = raw.subarray(0, IV_BYTES);
    const tag = raw.subarray(IV_BYTES, IV_BYTES + TAG_BYTES);
    const ct = raw.subarray(IV_BYTES + TAG_BYTES);
    const decipher = createDecipheriv('aes-256-gcm', key, iv);
    decipher.setAAD(Buffer.from(sid));
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8'));
  } catch {
    return null;
  }
}

/**
 * Wraps any express-session store and encrypts the session payload before it is
 * persisted. Only an opaque envelope `{ cookie, enc }` reaches the inner store: the
 * cookie block stays readable because stores (e.g. connect-redis) need `cookie.expires`
 * for TTLs and it contains no secrets.
 *
 * Sessions that fail to decrypt (rotated key, tampering, plaintext left over from before
 * encryption was enabled) are treated as nonexistent, i.e. the user must log in again.
 */
export class EncryptedSessionStore extends session.Store {
  constructor(
    private readonly inner: session.Store,
    private readonly key: Buffer,
  ) {
    super();
  }

  get(sid: string, cb: Callback<session.SessionData | null>): void {
    this.inner.get(sid, (err, stored) => {
      if (err || !stored) return cb(err, null);
      const enc = (stored as unknown as { enc?: unknown }).enc;
      if (typeof enc !== 'string') {
        console.warn('Discarding unencrypted session found in store');
        return cb(null, null);
      }
      const data = decryptSession(this.key, sid, enc);
      if (!data) {
        console.warn('Discarding session that failed to decrypt (key rotated or data tampered)');
        return cb(null, null);
      }
      cb(null, data);
    });
  }

  set(sid: string, data: session.SessionData, cb?: Callback): void {
    let envelope: unknown;
    try {
      envelope = { cookie: data.cookie, enc: encryptSession(this.key, sid, data) };
    } catch (err) {
      return cb?.(err);
    }
    this.inner.set(sid, envelope as session.SessionData, cb);
  }

  destroy(sid: string, cb?: Callback): void {
    this.inner.destroy(sid, cb);
  }

  touch(sid: string, data: session.SessionData, cb?: Callback): void {
    // Only the cookie (expiry) matters for touch; nothing sensitive is forwarded.
    if (typeof this.inner.touch === 'function') {
      this.inner.touch(sid, { cookie: data.cookie } as session.SessionData, cb);
    } else {
      cb?.();
    }
  }
}
