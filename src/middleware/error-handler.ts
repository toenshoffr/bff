import axios from 'axios';
import type { ErrorRequestHandler } from 'express';

/**
 * Reduces an error to a safe-to-log projection. Axios errors in particular carry the
 * full outgoing request config on `.config` (including the JSON body — e.g. a
 * username/password login payload or an OAuth client_secret) and must never be
 * logged verbatim.
 */
function describeError(err: unknown): unknown {
  if (axios.isAxiosError(err)) {
    return {
      name: 'AxiosError',
      message: err.message,
      code: err.code,
      method: err.config?.method,
      url: err.config?.url,
      status: err.response?.status,
    };
  }
  if (err instanceof Error) {
    return { name: err.name, message: err.message, stack: err.stack };
  }
  return err;
}

export const errorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }
  console.error(describeError(err));
  res.status(500).json({ error: 'internal_server_error' });
};
