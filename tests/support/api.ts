import type { Server } from 'node:http';
import { app } from '../../server';
import type { AuthSession } from './authStack';

export interface RunningApp {
  base: string;
  stop: () => Promise<void>;
}

/** Starts the real Express app on an ephemeral port. */
export async function startApp(): Promise<RunningApp> {
  const server: Server = app.listen(0);
  await new Promise<void>((resolve) => server.on('listening', resolve));
  const addr = server.address();
  const port = typeof addr === 'object' && addr ? addr.port : 0;
  return {
    base: `http://127.0.0.1:${port}`,
    stop: () => new Promise<void>((resolve, reject) => server.close((err) => (err ? reject(err) : resolve())))
  };
}

/** Calls the API. Pass a session to send its access token, or null to send no credentials at all. */
export async function api(
  base: string,
  session: AuthSession | { accessToken: string } | null,
  path: string,
  init: { method?: string; body?: unknown; headers?: Record<string, string> } = {}
) {
  const headers: Record<string, string> = { ...(init.headers ?? {}) };
  if (init.body !== undefined) headers['Content-Type'] = 'application/json';
  if (session) headers.Authorization = `Bearer ${session.accessToken}`;
  const res = await fetch(`${base}/api/v1${path}`, {
    method: init.method ?? 'GET',
    headers,
    body: init.body === undefined ? undefined : JSON.stringify(init.body)
  });
  const body: any = await res.json().catch(() => ({}));
  return { status: res.status, body };
}
