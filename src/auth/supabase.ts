import { createClient } from '@supabase/supabase-js';

/**
 * Browser login client. It uses only the project URL and the PUBLIC (anon) key. The service-role key is
 * a server secret and must never be given to the browser; this app does not use it anywhere.
 */
const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

export const supabase = url && anonKey ? createClient(url, anonKey, { auth: { persistSession: true, autoRefreshToken: true } }) : null;

/** fetch() that sends the signed-in user's session token. Identity is never sent any other way. */
export async function authFetch(input: string, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  const session = supabase ? (await supabase.auth.getSession()).data.session : null;
  if (session?.access_token) headers.set('Authorization', `Bearer ${session.access_token}`);
  return fetch(input, { ...init, headers });
}
