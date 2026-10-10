# Putting Custody Core live on Render (free plan)

About 10 minutes. You need your Render account (sign in with GitHub) and your Supabase project.

## 1. Collect three values from Supabase

Supabase dashboard > your project:

1. **Project Settings > Database > Connection string** > choose **Session pooler**. Copy it and put your database
   password in place of `[YOUR-PASSWORD]`. It looks like
   `postgresql://postgres.abcdefgh:PASSWORD@aws-0-us-east-1.pooler.supabase.com:5432/postgres`.
   (Not the "Direct connection": Render cannot reach it.)
2. **Project Settings > API**: the **Project URL** (`https://abcdefgh.supabase.co`) and the **anon / public** key
   (newer dashboards: the publishable key `sb_publishable_...`). Both are public by design.

## 2. Create the service from the Blueprint

1. render.com > **New** > **Blueprint**. Connect GitHub if asked, pick **SeedClassIntelligence/Custody-Core**,
   branch `main`.
2. Render reads `render.yaml` and asks for five values:
   - `DATABASE_URL`: the Session pooler string from step 1.1
   - `SUPABASE_URL` and `VITE_SUPABASE_URL`: the Project URL (the same value twice)
   - `SUPABASE_ANON_KEY` and `VITE_SUPABASE_ANON_KEY`: the anon key (the same value twice)
3. **Apply**. Render generates `APP_DB_PASSWORD` and `MFA_ENCRYPTION_KEY` itself, builds the Docker image (a few
   minutes the first time) and starts it. Your address is shown at the top: `https://custody-core-xxxx.onrender.com`.
4. Copy `MFA_ENCRYPTION_KEY` from the service's **Environment** tab and keep it with your other passwords.

## 3. Tell Supabase where the app lives

Supabase > **Authentication > URL Configuration**:

- **Site URL**: your Render address (`https://custody-core-xxxx.onrender.com`)
- **Redirect URLs**: add the same address

Without this, the "confirm your email" link points to `localhost` and sign-up cannot finish.

Also, once: **Authentication > Sign In / Providers > Email > Confirm email: ON**, and **Authentication >
Multi-Factor > TOTP: disabled** (`docs/LOGIN_SETUP.md` explains why).

## 4. Check it

- Open `https://<your address>/api/v1/health`: `"database": {"status": "connected"}` and `"scheduler": {..., "ok": true}`.
- Open the address, sign up, confirm the email, set up the authenticator, claim a project.

GitHub (Connect GitHub, doors, the gateway) needs the GitHub App: `docs/GITHUB_APP_SETUP.md`. Add its
`GITHUB_APP_*` values in the service's **Environment** tab later; the rest works without them.

## What the free plan means

- The service sleeps after about 15 minutes without visitors; the next visit wakes it in about a minute. While it
  sleeps nothing runs, and when it wakes, the scheduler first closes any door whose end date passed meanwhile.
- No persistent disk: backup snapshots of closed doors are lost when the service restarts or redeploys. For real use,
  move to a paid plan with a disk mounted at `/data` (the Dockerfile keeps snapshots in `/data/backups`).
