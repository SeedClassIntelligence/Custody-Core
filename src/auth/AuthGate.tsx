import React, { useCallback, useEffect, useRef, useState } from 'react';
import { Shield, Loader2, AlertCircle, KeyRound, LogIn } from 'lucide-react';
import { supabase } from './supabase';

export interface AuthInfo {
  email: string;
  signOut: () => Promise<void>;
}

type Phase =
  | { kind: 'loading' }
  | { kind: 'not_configured' }
  | { kind: 'signed_out'; notice?: string }
  | { kind: 'enroll'; factorId: string; qrCode: string; secret: string }
  | { kind: 'challenge'; factorId: string }
  | { kind: 'ready'; email: string }
  | { kind: 'error'; message: string };

const card = 'bg-zinc-900 border border-zinc-700/80 rounded-2xl max-w-md w-full shadow-2xl overflow-hidden';
const input =
  'w-full bg-zinc-950 border border-zinc-800 rounded-lg px-3 py-2 text-sm text-zinc-100 focus:outline-none focus:border-indigo-500';
const button =
  'w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-50 text-white font-medium px-4 py-2.5 rounded-lg text-sm flex items-center justify-center gap-2 transition-colors';

function Shell({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center p-4 font-sans">
      <div className={card}>
        <div className="px-6 py-5 border-b border-zinc-800 bg-zinc-950 flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-indigo-600/20 border border-indigo-500/30 flex items-center justify-center text-indigo-400">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <h1 className="text-lg font-semibold">{title}</h1>
            <p className="text-xs text-zinc-400">{subtitle}</p>
          </div>
        </div>
        <div className="p-6 space-y-4 text-sm text-zinc-300">{children}</div>
      </div>
    </div>
  );
}

function ErrorLine({ message }: { message: string | null }) {
  if (!message) return null;
  return (
    <div role="alert" className="bg-rose-950/50 border border-rose-800 p-3 rounded-lg text-xs text-rose-200 flex items-start gap-2">
      <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
      <span>{message}</span>
    </div>
  );
}

/**
 * Nothing behind this gate is shown until the person has signed in AND verified a code from an
 * authenticator app (aal2). The server enforces the same rule on every request; this is the way in.
 */
export function AuthGate({ children }: { children: (auth: AuthInfo) => React.ReactNode }) {
  const [phase, setPhase] = useState<Phase>({ kind: 'loading' });
  const resolving = useRef(false);

  const signOut = useCallback(async () => {
    await supabase?.auth.signOut();
  }, []);

  const resolve = useCallback(async () => {
    if (!supabase || resolving.current) return;
    resolving.current = true;
    try {
      const { data: sessionData } = await supabase.auth.getSession();
      const session = sessionData.session;
      if (!session) return setPhase({ kind: 'signed_out' });

      const { data: aal, error: aalError } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
      if (aalError) return setPhase({ kind: 'error', message: aalError.message });
      if (aal.currentLevel === 'aal2') return setPhase({ kind: 'ready', email: session.user.email ?? '' });

      const { data: factors, error: factorsError } = await supabase.auth.mfa.listFactors();
      if (factorsError) return setPhase({ kind: 'error', message: factorsError.message });
      const verified = factors.totp[0];
      if (verified) return setPhase({ kind: 'challenge', factorId: verified.id });

      // No verified authenticator yet: drop any half-finished enrollment, then start a fresh one.
      // Whoever holds the password at this moment becomes the owner of the authenticator, which is why
      // the project must require confirmed email addresses (docs/LOGIN_SETUP.md).
      for (const f of factors.all.filter((x) => x.factor_type === 'totp' && x.status === 'unverified')) {
        await supabase.auth.mfa.unenroll({ factorId: f.id });
      }
      const { data: enrolled, error: enrollError } = await supabase.auth.mfa.enroll({ factorType: 'totp' });
      if (enrollError) return setPhase({ kind: 'error', message: enrollError.message });
      setPhase({ kind: 'enroll', factorId: enrolled.id, qrCode: enrolled.totp.qr_code, secret: enrolled.totp.secret });
    } finally {
      resolving.current = false;
    }
  }, []);

  useEffect(() => {
    if (!supabase) return setPhase({ kind: 'not_configured' });
    void resolve();
    const { data } = supabase.auth.onAuthStateChange((event) => {
      if (event === 'SIGNED_OUT') return setPhase({ kind: 'signed_out' });
      if (event === 'TOKEN_REFRESHED') return;
      void resolve();
    });
    return () => data.subscription.unsubscribe();
  }, [resolve]);

  if (phase.kind === 'loading') {
    return (
      <div className="min-h-screen bg-zinc-950 flex items-center justify-center text-zinc-400 font-mono text-xs">Loading...</div>
    );
  }

  if (phase.kind === 'not_configured') {
    return (
      <Shell title="Login is not set up" subtitle="Not connected yet">
        <p>This app was built without a Supabase project, so nobody can sign in.</p>
        <p className="text-xs text-zinc-400">
          Set <code className="text-zinc-200">VITE_SUPABASE_URL</code> and <code className="text-zinc-200">VITE_SUPABASE_ANON_KEY</code> (the
          public key) and rebuild.
        </p>
      </Shell>
    );
  }

  if (phase.kind === 'error') {
    return (
      <Shell title="Something went wrong" subtitle="Sign-in could not continue">
        <ErrorLine message={phase.message} />
        <button className={button} onClick={() => void resolve()}>
          Try again
        </button>
      </Shell>
    );
  }

  if (phase.kind === 'signed_out') return <SignInForm notice={phase.notice} onDone={() => void resolve()} />;
  if (phase.kind === 'enroll') {
    return <CodeForm mode="enroll" factorId={phase.factorId} qrCode={phase.qrCode} secret={phase.secret} onVerified={() => void resolve()} onSignOut={signOut} />;
  }
  if (phase.kind === 'challenge') {
    return <CodeForm mode="challenge" factorId={phase.factorId} onVerified={() => void resolve()} onSignOut={signOut} />;
  }
  return <>{children({ email: phase.email, signOut })}</>;
}

function SignInForm({ notice, onDone }: { notice?: string; onDone: () => void }) {
  const [mode, setMode] = useState<'sign_in' | 'sign_up'>('sign_in');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(notice ?? null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!supabase) return;
    setBusy(true);
    setError(null);
    setInfo(null);
    try {
      if (mode === 'sign_up') {
        const { data, error: err } = await supabase.auth.signUp({ email, password });
        if (err) return setError(err.message);
        if (!data.session) return setInfo('Account created. Check your email to confirm it, then sign in.');
      } else {
        const { error: err } = await supabase.auth.signInWithPassword({ email, password });
        if (err) return setError(err.message);
      }
      onDone();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Shell
      title={mode === 'sign_in' ? 'Sign in' : 'Create your account'}
      subtitle="You will also need a code from an authenticator app."
    >
      <form onSubmit={submit} className="space-y-4">
        <label className="block text-xs font-medium text-zinc-300">
          Email
          <input className={`${input} mt-1`} type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} />
        </label>
        <label className="block text-xs font-medium text-zinc-300">
          Password
          <input
            className={`${input} mt-1`}
            type="password"
            autoComplete={mode === 'sign_in' ? 'current-password' : 'new-password'}
            required
            minLength={8}
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </label>
        <ErrorLine message={error} />
        {info && <div className="bg-indigo-950/40 border border-indigo-800 p-3 rounded-lg text-xs text-indigo-200">{info}</div>}
        <button className={button} disabled={busy} type="submit">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
          {mode === 'sign_in' ? 'Sign in' : 'Create account'}
        </button>
      </form>
      <button
        type="button"
        className="text-xs text-indigo-400 hover:text-indigo-300"
        onClick={() => {
          setMode(mode === 'sign_in' ? 'sign_up' : 'sign_in');
          setError(null);
        }}
      >
        {mode === 'sign_in' ? 'New here? Create an account' : 'Already have an account? Sign in'}
      </button>
    </Shell>
  );
}

function CodeForm(props: {
  mode: 'enroll' | 'challenge';
  factorId: string;
  qrCode?: string;
  secret?: string;
  onVerified: () => void;
  onSignOut: () => Promise<void>;
}) {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!supabase) return;
    setBusy(true);
    setError(null);
    try {
      const { error: err } = await supabase.auth.mfa.challengeAndVerify({ factorId: props.factorId, code: code.trim() });
      if (err) {
        setCode('');
        return setError(err.message);
      }
      props.onVerified();
    } finally {
      setBusy(false);
    }
  };

  return (
    <Shell
      title={props.mode === 'enroll' ? 'Set up your authenticator app' : 'Enter your authenticator code'}
      subtitle={props.mode === 'enroll' ? 'Required before you can see any project.' : 'Open your authenticator app and type the 6-digit code.'}
    >
      {props.mode === 'enroll' && (
        <div className="space-y-3">
          <p className="text-xs text-zinc-400">
            Scan this with an authenticator app (such as Google Authenticator, 1Password or Authy), then type the code it shows.
          </p>
          {props.qrCode && <img src={props.qrCode} alt="Authenticator setup QR code" className="mx-auto w-44 h-44 bg-white rounded-lg p-2" />}
          <div className="text-xs">
            <span className="text-zinc-400">Can't scan? Enter this key by hand:</span>
            <code data-testid="totp-secret" className="block mt-1 break-all bg-zinc-950 border border-zinc-800 rounded-lg p-2 text-zinc-200 select-all">
              {props.secret}
            </code>
          </div>
        </div>
      )}
      <form onSubmit={submit} className="space-y-4">
        <label className="block text-xs font-medium text-zinc-300">
          6-digit code
          <input
            className={`${input} mt-1 tracking-widest text-center font-mono`}
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
          />
        </label>
        <ErrorLine message={error} />
        <button className={button} disabled={busy || code.length !== 6} type="submit">
          {busy ? <Loader2 className="w-4 h-4 animate-spin" /> : <KeyRound className="w-4 h-4" />}
          {props.mode === 'enroll' ? 'Confirm and continue' : 'Verify'}
        </button>
      </form>
      <button type="button" className="text-xs text-zinc-400 hover:text-zinc-200" onClick={() => void props.onSignOut()}>
        Sign out
      </button>
    </Shell>
  );
}
