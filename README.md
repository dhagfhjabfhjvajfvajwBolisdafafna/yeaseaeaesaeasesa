# Focuss Tweaks — License Backend

Single Python process (`bot.py`) running the Discord bot + FastAPI license API together via asyncio.

## Local setup
1. `pip install -r requirements.txt`
2. Copy `.env.example` to `.env`, fill in values.
3. Run `schema.sql` in the Supabase SQL editor against your project.
4. `python bot.py`

## Railway setup
1. Create a new Railway project from this `backend/` folder (or repo subdirectory).
2. Add all variables from `.env.example` under Project → Variables (real values, never commit `.env`).
3. Start command: `python bot.py` (already set via `Procfile` / `railway.json`).
4. Once deployed, connect a public domain (Settings → Networking → Generate Domain).
5. Set `PUBLIC_BASE_URL` to that domain (e.g. `https://focuss-backend.up.railway.app`).
6. Set `DISCORD_REDIRECT_URI` to `${PUBLIC_BASE_URL}/oauth/discord/callback` and add the exact same
   redirect URI in the Discord Developer Portal → OAuth2 → Redirects.
7. Test: `GET https://<your-domain>/health` → `{"status":"online"}`.
8. View logs from the Railway dashboard (Deployments → View Logs). No secrets are ever logged.

## Discord application setup
- Create an application at https://discord.com/developers/applications
- Bot tab: create bot, copy token → `DISCORD_BOT_TOKEN`. Enable "Server Members Intent".
- OAuth2 tab: copy Client ID/Secret → `DISCORD_CLIENT_ID` / `DISCORD_CLIENT_SECRET`.
- Add redirect URI matching `DISCORD_REDIRECT_URI`.
- Invite the bot to your server with `applications.commands` + `bot` scopes and Manage Roles permission
  (its role must sit above the Basic/Premium roles it assigns).

## What this service does
- Discord slash commands for staff to manage licenses (`/genkey`, `/ban`, `/extend`, etc.)
- Public REST API the Electron app calls (`/api/licence/start`, `/api/session/validate`, …)
- Discord OAuth2 identify flow to permanently bind a license to one Discord account
- HWID binding (double-hashed, never stored in reversible form)
- Session issuance/validation/revocation
- Feature/plan gating via `TWEAK_DEFINITIONS` in `bot.py` — this is the single source of truth
  the backend enforces; the Electron `feature-manager.js` mirrors it only for UI locking, never
  for actual enforcement.
