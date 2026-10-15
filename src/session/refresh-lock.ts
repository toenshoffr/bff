import { randomUUID } from 'node:crypto';

export interface RefreshLock {
  /** Runs `fn` while holding an exclusive lock for `key`; concurrent callers queue up. */
  run<T>(key: string, fn: () => Promise<T>): Promise<T>;
}

/** Serializes callers within one Node process. */
export class InProcessLock implements RefreshLock {
  private tails = new Map<string, Promise<unknown>>();

  async run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    const prev = this.tails.get(key) ?? Promise.resolve();
    const result = prev.then(fn, fn);
    const tail = result.catch(() => undefined);
    this.tails.set(key, tail);
    try {
      return await result;
    } finally {
      if (this.tails.get(key) === tail) this.tails.delete(key);
    }
  }
}

/** Minimal subset of the node-redis client used for the distributed lock. */
export interface LockRedisClient {
  set(key: string, value: string, opts: { NX: true; PX: number }): Promise<string | null>;
  eval(script: string, opts: { keys: string[]; arguments: string[] }): Promise<unknown>;
}

const RELEASE_SCRIPT = `if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end`;

/**
 * Cross-instance lock (SET NX PX + compare-and-delete release). Layered on top of the
 * in-process lock so waiters on the same instance queue in memory instead of polling Redis.
 * The TTL bounds how long a crashed holder can block others.
 */
export class RedisRefreshLock implements RefreshLock {
  private local = new InProcessLock();

  constructor(
    private readonly client: LockRedisClient,
    private readonly opts: { keyPrefix: string; ttlMs: number; waitTimeoutMs: number; pollMs?: number },
  ) {}

  run<T>(key: string, fn: () => Promise<T>): Promise<T> {
    return this.local.run(key, async () => {
      const redisKey = `${this.opts.keyPrefix}${key}`;
      const token = randomUUID();
      const deadline = Date.now() + this.opts.waitTimeoutMs;
      while ((await this.client.set(redisKey, token, { NX: true, PX: this.opts.ttlMs })) !== 'OK') {
        if (Date.now() >= deadline) throw new Error('Timed out waiting for token refresh lock');
        await new Promise((r) => setTimeout(r, this.opts.pollMs ?? 50));
      }
      try {
        return await fn();
      } finally {
        await this.client.eval(RELEASE_SCRIPT, { keys: [redisKey], arguments: [token] }).catch(() => undefined);
      }
    });
  }
}
