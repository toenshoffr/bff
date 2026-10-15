import RedisStore from 'connect-redis';
import session from 'express-session';
import { createClient } from 'redis';
import { config } from '../config.js';
import { deriveKey, EncryptedSessionStore } from './encrypted-store.js';
import { InProcessLock, RedisRefreshLock, type RefreshLock } from './refresh-lock.js';

const redisClient = config.session.store === 'redis' ? createClient({ url: config.session.redisUrl }) : undefined;
redisClient?.on('error', (err) => console.error('Redis error:', err.message));

function createInnerStore(): session.Store {
  if (!redisClient) {
    if (config.isProduction) {
      console.warn('SESSION_STORE=memory in production — sessions are lost on restart and not shared across instances.');
    }
    return new session.MemoryStore();
  }
  return new RedisStore({ client: redisClient, prefix: config.session.redisKeyPrefix });
}

function createStore(): session.Store {
  const inner = createInnerStore();
  if (!config.session.encryptionEnabled) {
    if (config.isProduction) {
      console.warn('SESSION_ENCRYPTION_ENABLED=false — tokens are stored unencrypted in the session store.');
    }
    return inner;
  }
  return new EncryptedSessionStore(inner, deriveKey(config.session.encryptionKey));
}

export const sessionStore = createStore();

/** Serializes token refreshes per session (across instances when using Redis). */
export const refreshLock: RefreshLock = redisClient
  ? new RedisRefreshLock(redisClient as never, {
      keyPrefix: `${config.session.redisKeyPrefix}refresh-lock:`,
      // Lock must outlive a refresh round-trip; waiters give up slightly later.
      ttlMs: config.api.timeoutMs + 5_000,
      waitTimeoutMs: config.api.timeoutMs * 2 + 5_000,
    })
  : new InProcessLock();

export async function connectSessionBackend(): Promise<void> {
  await redisClient?.connect();
}

export async function closeSessionBackend(): Promise<void> {
  await redisClient?.quit().catch(() => undefined);
}
