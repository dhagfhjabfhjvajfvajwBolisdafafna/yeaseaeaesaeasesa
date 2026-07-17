"""
FOCUSS TWEAKS — License, Session & Discord OAuth Backend
=========================================================================
Single-file service: runs the Discord bot (slash commands for license
management) and the public FastAPI license/session API side by side in
one asyncio event loop. This is what Railway runs (`python bot.py`).

Security model:
  - The Electron app NEVER talks to Supabase directly. It only calls this
    API's public endpoints over HTTPS.
  - Supabase is accessed only here, with the service-role key, which is
    never shipped to the client.
  - License keys are stored only as HMAC-SHA256 hashes (LICENCE_HMAC_SECRET).
    The full key is shown to staff exactly once, in the ephemeral /genkey
    response, and is never persisted or logged anywhere.
  - HWIDs arrive from Electron already SHA-256 hashed on the client. This
    backend applies a second HMAC-SHA256 (HWID_HMAC_SECRET) before storing
    or comparing them, so even a Supabase data leak does not reveal a
    reversible device fingerprint.
  - Session tokens are opaque random strings. Only their HMAC-SHA256 hash
    (SESSION_SECRET) is stored. The raw token is handed to the client
    exactly once and never persisted server-side.
=========================================================================
"""

import os
import io
import time
import hmac
import hashlib
import logging
import secrets
import asyncio
from datetime import datetime, timedelta, timezone
from typing import Optional, Literal
from urllib.parse import urlencode

import discord
from discord import app_commands
from discord.ext import commands
from dotenv import load_dotenv
from supabase import create_client, Client

import aiohttp
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field
import uvicorn


# ═════════════════════════════════════════════════════════════════════════
# CONFIG
# ═════════════════════════════════════════════════════════════════════════
load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_ids(name: str) -> set:
    return {int(x) for x in _env(name).replace(" ", "").split(",") if x.isdigit()}


DISCORD_BOT_TOKEN = _env("DISCORD_BOT_TOKEN")
DISCORD_CLIENT_ID = _env("DISCORD_CLIENT_ID")
DISCORD_CLIENT_SECRET = _env("DISCORD_CLIENT_SECRET")
DISCORD_REDIRECT_URI = _env("DISCORD_REDIRECT_URI")
_GUILD_ID_RAW = _env("DISCORD_GUILD_ID")
GUILD_ID = int(_GUILD_ID_RAW) if _GUILD_ID_RAW.isdigit() else None

ADMIN_IDS = _env_ids("DISCORD_ADMIN_IDS")
STAFF_ROLE_IDS = _env_ids("DISCORD_STAFF_ROLE_IDS")

BASIC_ROLE_ID = _env("DISCORD_BASIC_ROLE_ID")
PREMIUM_ROLE_ID = _env("DISCORD_PREMIUM_ROLE_ID")

ACTIVATION_LOG_CHANNEL_ID = _env("DISCORD_ACTIVATION_LOG_CHANNEL_ID")
LOGIN_LOG_CHANNEL_ID = _env("DISCORD_LOGIN_LOG_CHANNEL_ID")
SECURITY_LOG_CHANNEL_ID = _env("DISCORD_SECURITY_LOG_CHANNEL_ID")
ADMIN_LOG_CHANNEL_ID = _env("DISCORD_ADMIN_LOG_CHANNEL_ID")

SUPABASE_URL = _env("SUPABASE_URL")
SUPABASE_SERVICE_KEY = _env("SUPABASE_SERVICE_ROLE_KEY")

PUBLIC_BASE_URL = _env("PUBLIC_BASE_URL").rstrip("/")

LICENCE_HMAC_SECRET = _env("LICENCE_HMAC_SECRET")
HWID_HMAC_SECRET = _env("HWID_HMAC_SECRET")
SESSION_SECRET = _env("SESSION_SECRET")
IP_HMAC_SECRET = _env("IP_HMAC_SECRET")
APP_SECRET = _env("APP_SECRET")

SESSION_LIFETIME_SECONDS = int(_env("SESSION_LIFETIME_SECONDS") or 3600)
ACTIVATION_LIFETIME_SECONDS = int(_env("ACTIVATION_LIFETIME_SECONDS") or 600)
LOGIN_LOG_COOLDOWN_SECONDS = int(_env("LOGIN_LOG_COOLDOWN_SECONDS") or 300)
SESSION_VALIDATION_INTERVAL_SECONDS = int(_env("SESSION_VALIDATION_INTERVAL_SECONDS") or 30)

PORT = int(_env("PORT") or 8080)

DURATION_DAYS = {"1d": 1, "3d": 3, "7d": 7, "30d": 30, "lifetime": None}

FOCUSS_DISCORD_INVITE = "https://discord.gg/v9DmvTKAzS"


# ═════════════════════════════════════════════════════════════════════════
# LOGGING
# ═════════════════════════════════════════════════════════════════════════
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler("bot.log", encoding="utf-8")],
)
log = logging.getLogger("focuss-backend")


# ═════════════════════════════════════════════════════════════════════════
# SUPABASE
# ═════════════════════════════════════════════════════════════════════════
supabase: Optional[Client] = None
if SUPABASE_URL and SUPABASE_SERVICE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_KEY)
else:
    log.critical("SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY missing — set them in .env")


async def db(fn):
    """Run a blocking supabase-py call in a worker thread."""
    return await asyncio.to_thread(fn)


def require_supabase():
    if supabase is None:
        raise RuntimeError("Supabase is not configured.")


# ═════════════════════════════════════════════════════════════════════════
# CRYPTO / KEY HELPERS
# ═════════════════════════════════════════════════════════════════════════
KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no 0/O/1/I


def generate_key() -> str:
    groups = ["".join(secrets.choice(KEY_ALPHABET) for _ in range(4)) for _ in range(4)]
    return "FOCUSS-" + "-".join(groups)


def normalize_key(key: str) -> str:
    return key.strip().upper().replace(" ", "")


def mask_key(key: str) -> str:
    parts = key.split("-")
    if len(parts) != 5:
        return key
    return f"{parts[0]}-{parts[1]}-****-****-{parts[4]}"


def hmac_hex(secret: str, value: str) -> str:
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()


def key_hash(full_key: str) -> str:
    return hmac_hex(LICENCE_HMAC_SECRET, normalize_key(full_key))


def hwid_store_hash(client_hwid_sha256: str) -> str:
    """Client already SHA-256'd the raw HWID components. We apply a second
    HMAC layer with a server-only secret before it ever touches storage."""
    return hmac_hex(HWID_HMAC_SECRET, client_hwid_sha256.strip().lower())


def new_opaque_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(raw_token: str) -> str:
    return hmac_hex(SESSION_SECRET, raw_token)


def ip_hash(ip: str) -> str:
    return hmac_hex(IP_HMAC_SECRET, ip or "unknown")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: Optional[datetime]) -> Optional[str]:
    return dt.isoformat() if dt else None


def parse_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fmt_dt(value: Optional[str]) -> str:
    dt = parse_dt(value)
    return f"<t:{int(dt.timestamp())}:f>" if dt else "Lifetime"


def const_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a or "", b or "")


# ═════════════════════════════════════════════════════════════════════════
# FEATURE / TWEAK REGISTRY  (shared source of truth — mirrored in
# feature-manager.js on the Electron side for UI display only; THIS
# dict is the actual authority checked by /api/feature/validate)
# ═════════════════════════════════════════════════════════════════════════
TWEAK_DEFINITIONS: dict[str, dict] = {
    # cleaners — safe, everyday maintenance -> basic
    "junk-cleaner": {"requiredPlan": "basic"},
    "discord-cache-cleaner": {"requiredPlan": "basic"},
    "discord-session-cleaner": {"requiredPlan": "basic"},
    "steam-cleaner": {"requiredPlan": "basic"},
    "log-crash-cleaner": {"requiredPlan": "basic"},
    "recent-documents-cleaner": {"requiredPlan": "basic"},
    "browser-cache-cleaner": {"requiredPlan": "basic"},
    "thumbnail-icon-cache-cleaner": {"requiredPlan": "basic"},
    # deep/system-level cleaning -> premium
    "deep-temp-prefetch-cleaner": {"requiredPlan": "premium"},
    "windows-update-cache-cleaner": {"requiredPlan": "basic"},
    "font-cache-cleaner": {"requiredPlan": "basic"},

    # network — quick/simple -> basic, advanced tuning -> premium
    "flush-dns-cache": {"requiredPlan": "basic"},
    "dns-profile": {"requiredPlan": "premium"},
    "optimize-network-performance": {"requiredPlan": "premium"},
    "disable-tcp-heuristics": {"requiredPlan": "premium"},
    "disable-delivery-optimization-p2p": {"requiredPlan": "premium"},
    "disable-usb-selective-suspend": {"requiredPlan": "premium"},
    "disable-pcie-link-state-ac": {"requiredPlan": "premium"},

    # performance / power — deep system tuning -> premium
    "drive-fixer": {"requiredPlan": "premium"},
    "drive-optimizer": {"requiredPlan": "premium"},
    "system-fixer": {"requiredPlan": "premium"},
    "timer-resolution": {"requiredPlan": "premium"},
    "disable-power-throttling": {"requiredPlan": "premium"},
    "low-latency-ac-power": {"requiredPlan": "premium"},
    "enable-maximum-performance-power-mode": {"requiredPlan": "premium"},
    "disable-hibernation": {"requiredPlan": "premium"},
    "disable-superfetch-sysmain": {"requiredPlan": "premium"},
    "search-indexing-on-demand": {"requiredPlan": "premium"},

    # boot — advanced -> premium
    "show-pc-boot-information": {"requiredPlan": "premium"},
    "restore-legacy-boot-menu": {"requiredPlan": "premium"},
    "reduce-boot-menu-timeout": {"requiredPlan": "premium"},
    "disable-boot-menu-timeout": {"requiredPlan": "premium"},
    "disable-boot-logo": {"requiredPlan": "premium"},
    "bypass-windows-11-checks": {"requiredPlan": "premium"},

    # visual / UI — everyday cosmetic toggles -> basic
    "set-visual-effects-performance": {"requiredPlan": "basic"},
    "increase-taskbar-transparency": {"requiredPlan": "basic"},
    "disable-transparency": {"requiredPlan": "basic"},
    "optimize-jpeg-wallpaper-quality": {"requiredPlan": "basic"},
    "show-all-taskbar-tray-icons": {"requiredPlan": "basic"},
    "disable-windows-focus-assist": {"requiredPlan": "basic"},
    "disable-sticky-keys": {"requiredPlan": "basic"},
    "disable-storage-sense": {"requiredPlan": "basic"},
    "disable-live-tiles": {"requiredPlan": "basic"},
    "disable-notifications": {"requiredPlan": "basic"},
    "disable-action-center": {"requiredPlan": "basic"},
    "taskbar-cleanup": {"requiredPlan": "basic"},
    "explorer-cleanup-profile": {"requiredPlan": "basic"},
    "instant-menu-response": {"requiredPlan": "basic"},
    "taskbar-productivity": {"requiredPlan": "basic"},
    "simplify-explorer-sidebar": {"requiredPlan": "basic"},
    "classic-context-menu": {"requiredPlan": "basic"},
    "enable-dark-mode": {"requiredPlan": "basic"},
    "optimize-mouse": {"requiredPlan": "basic"},
    "enable-long-paths": {"requiredPlan": "basic"},
    "disable-autoplay": {"requiredPlan": "basic"},
    # deeper UI/security policy changes -> premium
    "disable-lock-screen": {"requiredPlan": "premium"},
    "disable-lock-screen-blur": {"requiredPlan": "premium"},
    "start-menu-cleanup": {"requiredPlan": "premium"},
    "disable-app-archiving": {"requiredPlan": "premium"},
    "disable-windows-web-search": {"requiredPlan": "premium"},

    # privacy / telemetry / AI — advanced policy tweaks -> premium
    "disable-dynamic-lighting": {"requiredPlan": "basic"},
    "disable-nearby-sharing": {"requiredPlan": "basic"},
    "disable-mobile-integration": {"requiredPlan": "premium"},
    "disable-windows-insider": {"requiredPlan": "premium"},
    "disable-windows-gamebar": {"requiredPlan": "premium"},
    "disable-background-store-apps": {"requiredPlan": "premium"},
    "disable-xbox": {"requiredPlan": "premium"},
    "disable-windows-services": {"requiredPlan": "premium"},
    "disable-maps-broker": {"requiredPlan": "premium"},
    "disable-print-spooler-no-printers": {"requiredPlan": "premium"},
    "disable-bluetooth-no-device": {"requiredPlan": "premium"},
    "disable-camera-no-device": {"requiredPlan": "premium"},
    "disable-vbs-hyperv": {"requiredPlan": "premium"},
    "disable-onedrive": {"requiredPlan": "premium"},
    "disable-windows-automatic-updates": {"requiredPlan": "premium"},
    "disable-consumer-content": {"requiredPlan": "premium"},
    "disable-activity-history": {"requiredPlan": "premium"},
    "disable-advertising-personalization": {"requiredPlan": "premium"},
    "disable-settings-sync": {"requiredPlan": "premium"},
    "disable-online-speech": {"requiredPlan": "premium"},
    "disable-location-services": {"requiredPlan": "premium"},
    "disable-remote-access": {"requiredPlan": "premium"},
    "block-wpbt": {"requiredPlan": "premium"},
    "disable-windows-ai": {"requiredPlan": "premium"},
    "minimize-diagnostic-data": {"requiredPlan": "premium"},
    "remove-optional-microsoft-apps": {"requiredPlan": "premium"},

    # nvidia
    "nvidia-driver-installer": {"requiredPlan": "basic"},
    "nvidia-privacy": {"requiredPlan": "premium"},

    # misc protected action
    "defender-exclusions": {"requiredPlan": "premium"},

    # free / unlocked for everyone — not gated, but listed for completeness
    "open-discord": {"requiredPlan": "free"},
}


def plan_satisfies(user_plan: str, required_plan: str) -> bool:
    if required_plan == "free":
        return True
    if user_plan == "premium":
        return True
    return user_plan == "basic" and required_plan == "basic"


# ═════════════════════════════════════════════════════════════════════════
# IN-MEMORY RATE LIMITING & LOG COOLDOWNS (single Railway instance)
# ═════════════════════════════════════════════════════════════════════════
_rate_buckets: dict[str, list] = {}
_login_log_cooldown: dict[str, float] = {}
_security_log_cooldown: dict[str, float] = {}


def rate_limited(key: str, max_calls: int, window_seconds: int) -> bool:
    now = time.time()
    bucket = _rate_buckets.setdefault(key, [])
    bucket[:] = [t for t in bucket if now - t < window_seconds]
    if len(bucket) >= max_calls:
        return True
    bucket.append(now)
    return False


def cooldown_ok(store: dict, key: str, seconds: int) -> bool:
    now = time.time()
    last = store.get(key, 0)
    if now - last < seconds:
        return False
    store[key] = now
    return True


# ═════════════════════════════════════════════════════════════════════════
# DISCORD BOT
# ═════════════════════════════════════════════════════════════════════════
intents = discord.Intents.default()
intents.members = True
bot = commands.Bot(command_prefix="!", intents=intents)

PLAN_COLORS = {"basic": discord.Color.light_grey(), "premium": discord.Color.gold()}


def admin_only():
    async def predicate(interaction: discord.Interaction) -> bool:
        member = interaction.user
        if member.id in ADMIN_IDS:
            return True
        role_ids = {r.id for r in getattr(member, "roles", [])}
        if role_ids & STAFF_ROLE_IDS:
            return True
        raise app_commands.CheckFailure("not_staff")
    return app_commands.check(predicate)


async def get_channel(channel_id: str):
    if not channel_id or not channel_id.isdigit():
        return None
    ch = bot.get_channel(int(channel_id))
    if ch is None:
        try:
            ch = await bot.fetch_channel(int(channel_id))
        except Exception:
            return None
    return ch


async def send_log(channel_id: str, embed: discord.Embed):
    ch = await get_channel(channel_id)
    if ch is None:
        return
    try:
        await ch.send(embed=embed)
    except Exception:
        log.exception("Failed to deliver log embed to channel %s", channel_id)


async def audit_log(action: str, admin_discord_id: Optional[str], licence_id: Optional[str],
                     discord_user_id: Optional[str], details: str):
    if supabase:
        try:
            await db(lambda: supabase.table("audit_logs").insert({
                "action": action, "admin_discord_id": admin_discord_id, "licence_id": licence_id,
                "discord_user_id": discord_user_id, "details": details,
            }).execute())
        except Exception:
            log.exception("audit_log insert failed")
    embed = discord.Embed(title=f"🛡️ Staff action: {action}", color=discord.Color.orange(), timestamp=now_utc())
    if admin_discord_id:
        embed.add_field(name="Staff", value=f"<@{admin_discord_id}>", inline=True)
    if discord_user_id:
        embed.add_field(name="Target user", value=f"<@{discord_user_id}>", inline=True)
    embed.add_field(name="Details", value=details[:1000], inline=False)
    await send_log(ADMIN_LOG_CHANNEL_ID, embed)


async def assign_plan_role(discord_user_id: str, plan: Optional[str]):
    """plan=None removes both roles (unlink/ban/delete)."""
    if not GUILD_ID or not discord_user_id.isdigit():
        return
    guild = bot.get_guild(GUILD_ID)
    if guild is None:
        return
    try:
        member = guild.get_member(int(discord_user_id)) or await guild.fetch_member(int(discord_user_id))
    except Exception:
        return
    basic_role = guild.get_role(int(BASIC_ROLE_ID)) if BASIC_ROLE_ID.isdigit() else None
    premium_role = guild.get_role(int(PREMIUM_ROLE_ID)) if PREMIUM_ROLE_ID.isdigit() else None
    try:
        if basic_role and basic_role in member.roles and plan != "basic":
            await member.remove_roles(basic_role, reason="Focuss licence role sync")
        if premium_role and premium_role in member.roles and plan != "premium":
            await member.remove_roles(premium_role, reason="Focuss licence role sync")
        if plan == "basic" and basic_role and basic_role not in member.roles:
            await member.add_roles(basic_role, reason="Focuss licence activated")
        if plan == "premium" and premium_role and premium_role not in member.roles:
            await member.add_roles(premium_role, reason="Focuss licence activated")
    except discord.Forbidden:
        log.warning("Missing permission to modify roles for %s", discord_user_id)
    except Exception:
        log.exception("Role sync failed for %s", discord_user_id)


# ─── shared license lookups ────────────────────────────────────────────
async def find_licence_by_key(full_key: str) -> Optional[dict]:
    kh = key_hash(full_key)
    res = await db(lambda: supabase.table("licences").select("*").eq("key_hash", kh).limit(1).execute())
    return res.data[0] if res.data else None


async def find_licence_by_masked(masked_or_partial: str) -> Optional[dict]:
    res = await db(lambda: supabase.table("licences").select("*")
                    .ilike("masked_key", f"%{masked_or_partial.strip().upper()}%").limit(1).execute())
    return res.data[0] if res.data else None


async def is_banned(ban_type: str, target: str) -> Optional[dict]:
    res = await db(lambda: supabase.table("bans").select("*").eq("ban_type", ban_type)
                    .eq("target_hash_or_id", target).eq("active", True).limit(1).execute())
    return res.data[0] if res.data else None


async def revoke_licence_sessions(licence_id: str, reason: str):
    await db(lambda: supabase.table("sessions").update({
        "revoked": True, "revoked_at": iso(now_utc()), "revocation_reason": reason,
    }).eq("licence_id", licence_id).eq("revoked", False).execute())


def duration_expiry(duration_type: str, base: datetime) -> Optional[datetime]:
    days = DURATION_DAYS[duration_type]
    return None if days is None else base + timedelta(days=days)


# ═════════════════════════════════════════════════════════════════════════
# SLASH COMMANDS
# ═════════════════════════════════════════════════════════════════════════
DurationLiteral = Literal["1d", "3d", "7d", "30d", "lifetime"]


@bot.tree.command(name="genkey", description="Generate one or more Focuss Tweaks license keys")
@app_commands.describe(plan="License plan", duration="License duration", amount="How many keys (max 25)", note="Optional staff note")
@admin_only()
async def genkey(interaction: discord.Interaction, plan: Literal["basic", "premium"],
                  duration: DurationLiteral, amount: app_commands.Range[int, 1, 25] = 1,
                  note: Optional[str] = None):
    require_supabase()
    await interaction.response.defer(ephemeral=True, thinking=True)

    keys = [generate_key() for _ in range(amount)]
    rows = []
    for k in keys:
        parts = k.split("-")
        rows.append({
            "key_hash": key_hash(k), "key_prefix": parts[0], "key_last_four": parts[-1],
            "masked_key": mask_key(k), "plan": plan, "duration_type": duration,
            "duration_days": DURATION_DAYS[duration], "status": "unused",
            "created_by_discord_id": str(interaction.user.id), "staff_note": note,
        })

    try:
        await db(lambda: supabase.table("licences").insert(rows).execute())
    except Exception as e:
        log.exception("genkey insert failed")
        await interaction.followup.send(f"❌ Failed to create key(s): `{e}`", ephemeral=True)
        return

    await audit_log("genkey", str(interaction.user.id), None, None,
                     f"{amount}x {plan} / {duration}" + (f" — {note}" if note else ""))

    embed = discord.Embed(title=f"✅ Generated {amount}x {plan.upper()} key{'s' if amount != 1 else ''}", color=PLAN_COLORS[plan])
    embed.add_field(name="Duration", value=duration, inline=True)
    embed.add_field(name="Generated by", value=interaction.user.mention, inline=True)
    embed.add_field(name="Created", value=fmt_dt(iso(now_utc())), inline=True)
    if note:
        embed.add_field(name="Note", value=note, inline=False)
    keys_block = "\n".join(keys)
    if len(keys_block) > 900:
        file = discord.File(fp=io.BytesIO(keys_block.encode("utf-8")), filename="focuss_keys.txt")
        await interaction.followup.send(embed=embed, file=file, ephemeral=True)
    else:
        embed.add_field(name="Key(s) — shown once, save them now", value=f"```\n{keys_block}\n```", inline=False)
        await interaction.followup.send(embed=embed, ephemeral=True)


STATUS_FILTERS = Literal["all", "unused", "active", "expired", "banned", "basic", "premium"]


@bot.tree.command(name="list", description="List license keys")
@app_commands.describe(filter="Filter keys", page="Page number (10 per page)")
@admin_only()
async def list_keys(interaction: discord.Interaction, filter: STATUS_FILTERS = "all", page: app_commands.Range[int, 1, 999] = 1):
    require_supabase()
    await interaction.response.defer(ephemeral=True)

    def query():
        q = supabase.table("licences").select(
            "masked_key,plan,status,discord_user_id,activated_at,expires_at,last_login_at,hwid_hash"
        ).order("created_at", desc=True)
        if filter in ("basic", "premium"):
            q = q.eq("plan", filter)
        elif filter in ("unused", "active", "expired", "banned"):
            q = q.eq("status", filter)
        start = (page - 1) * 10
        return q.range(start, start + 9).execute()

    res = await db(query)
    rows = res.data or []
    if not rows:
        await interaction.followup.send("No keys found for that filter/page.", ephemeral=True)
        return

    embed = discord.Embed(title=f"📋 License Keys — {filter} — page {page}", color=discord.Color.blurple())
    for r in rows:
        linked = f"<@{r['discord_user_id']}>" if r["discord_user_id"] else "unclaimed"
        embed.add_field(
            name=r["masked_key"],
            value=(f"Plan: **{r['plan']}** · {r['status'].upper()}\n"
                   f"Linked: {linked} · Device linked: {'yes' if r['hwid_hash'] else 'no'}\n"
                   f"Expires: {fmt_dt(r['expires_at'])} · Last login: {fmt_dt(r['last_login_at']) if r['last_login_at'] else '—'}"),
            inline=False,
        )
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="lookup", description="Show full details for a license key or Discord user")
@app_commands.describe(query="License key, masked key, or Discord ID")
@admin_only()
async def lookup(interaction: discord.Interaction, query: str):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    q = query.strip()

    row = None
    if q.isdigit():
        res = await db(lambda: supabase.table("licences").select("*").eq("discord_user_id", q)
                        .order("created_at", desc=True).limit(1).execute())
        row = res.data[0] if res.data else None
    elif q.upper().startswith("FOCUSS-") and q.count("-") == 4 and "*" not in q:
        row = await find_licence_by_key(q)
    else:
        row = await find_licence_by_masked(q)

    if not row:
        await interaction.followup.send("❌ No matching license found.", ephemeral=True)
        return

    embed = discord.Embed(title=f"🔎 {row['masked_key']}", color=PLAN_COLORS.get(row["plan"], discord.Color.default()))
    embed.add_field(name="Plan", value=row["plan"], inline=True)
    embed.add_field(name="Status", value=row["status"], inline=True)
    embed.add_field(name="Duration", value=row["duration_type"], inline=True)
    embed.add_field(name="Created", value=fmt_dt(row["created_at"]), inline=True)
    embed.add_field(name="Activated", value=fmt_dt(row["activated_at"]) if row["activated_at"] else "Not yet activated", inline=True)
    embed.add_field(name="Expires", value=fmt_dt(row["expires_at"]), inline=True)
    embed.add_field(name="Discord", value=(f"<@{row['discord_user_id']}>" if row["discord_user_id"] else "—"), inline=True)
    embed.add_field(name="Device linked", value=("Yes" if row["hwid_hash"] else "No"), inline=True)
    embed.add_field(name="Last login", value=fmt_dt(row["last_login_at"]) if row["last_login_at"] else "—", inline=True)
    embed.add_field(name="Created by", value=f"<@{row['created_by_discord_id']}>", inline=True)
    if row["staff_note"]:
        embed.add_field(name="Note", value=row["staff_note"], inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="ban", description="Ban a license, Discord user, or device")
@app_commands.describe(target_type="What to ban", key="License key (if banning a licence)",
                        user="Discord user (if banning a discord user)", reason="Reason for the ban")
@admin_only()
async def ban_cmd(interaction: discord.Interaction, target_type: Literal["licence", "discord_user"],
                   reason: str, key: Optional[str] = None, user: Optional[discord.User] = None):
    require_supabase()
    await interaction.response.defer(ephemeral=True)

    licence_row = None
    discord_id = None

    if target_type == "licence":
        if not key:
            await interaction.followup.send("❌ Provide `key` when banning a licence.", ephemeral=True)
            return
        licence_row = await find_licence_by_key(normalize_key(key))
        if not licence_row:
            await interaction.followup.send("❌ No license found with that key.", ephemeral=True)
            return
        await db(lambda: supabase.table("licences").update({"status": "banned"}).eq("id", licence_row["id"]).execute())
        await db(lambda: supabase.table("bans").insert({
            "ban_type": "licence", "target_hash_or_id": licence_row["key_hash"], "reason": reason,
            "created_by_discord_id": str(interaction.user.id),
        }).execute())
        await revoke_licence_sessions(licence_row["id"], "licence_banned")
        discord_id = licence_row.get("discord_user_id")
    else:
        if not user:
            await interaction.followup.send("❌ Provide `user` when banning a Discord user.", ephemeral=True)
            return
        discord_id = str(user.id)
        await db(lambda: supabase.table("discord_users").upsert({
            "discord_user_id": discord_id, "banned": True, "ban_reason": reason, "banned_at": iso(now_utc()),
            "updated_at": iso(now_utc()),
        }).execute())
        await db(lambda: supabase.table("bans").insert({
            "ban_type": "discord_user", "target_hash_or_id": discord_id, "reason": reason,
            "created_by_discord_id": str(interaction.user.id),
        }).execute())
        linked = await db(lambda: supabase.table("licences").select("id").eq("discord_user_id", discord_id).execute())
        for row in (linked.data or []):
            await revoke_licence_sessions(row["id"], "discord_banned")

    if discord_id:
        await assign_plan_role(discord_id, None)

    await audit_log("ban", str(interaction.user.id), licence_row["id"] if licence_row else None, discord_id, reason)
    embed = discord.Embed(title="🔨 Ban applied", color=discord.Color.red())
    embed.add_field(name="Type", value=target_type, inline=True)
    embed.add_field(name="Reason", value=reason, inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="unban", description="Remove an active ban")
@app_commands.describe(target_type="What to unban", key="License key", user="Discord user")
@admin_only()
async def unban_cmd(interaction: discord.Interaction, target_type: Literal["licence", "discord_user"],
                     key: Optional[str] = None, user: Optional[discord.User] = None):
    require_supabase()
    await interaction.response.defer(ephemeral=True)

    if target_type == "licence":
        if not key:
            await interaction.followup.send("❌ Provide `key`.", ephemeral=True)
            return
        row = await find_licence_by_key(normalize_key(key))
        if not row:
            await interaction.followup.send("❌ No license found.", ephemeral=True)
            return
        await db(lambda: supabase.table("licences").update({"status": "active" if row["activated_at"] else "unused"})
                  .eq("id", row["id"]).execute())
        await db(lambda: supabase.table("bans").update({"active": False, "removed_at": iso(now_utc()),
                  "removed_by_discord_id": str(interaction.user.id)}).eq("target_hash_or_id", row["key_hash"])
                  .eq("ban_type", "licence").eq("active", True).execute())
        target_id = row["id"]
    else:
        if not user:
            await interaction.followup.send("❌ Provide `user`.", ephemeral=True)
            return
        did = str(user.id)
        await db(lambda: supabase.table("discord_users").update({"banned": False, "ban_reason": None,
                  "updated_at": iso(now_utc())}).eq("discord_user_id", did).execute())
        await db(lambda: supabase.table("bans").update({"active": False, "removed_at": iso(now_utc()),
                  "removed_by_discord_id": str(interaction.user.id)}).eq("target_hash_or_id", did)
                  .eq("ban_type", "discord_user").eq("active", True).execute())
        target_id = did

    await audit_log("unban", str(interaction.user.id), None, None, f"{target_type}: {target_id}")
    await interaction.followup.send(f"✅ Ban removed for {target_type}.", ephemeral=True)


@bot.tree.command(name="deletekey", description="Soft-delete a license key (audit trail preserved)")
@app_commands.describe(key="The license key to delete", confirm="Type 'confirm' to proceed")
@admin_only()
async def deletekey(interaction: discord.Interaction, key: str, confirm: str):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    if confirm.strip().lower() != "confirm":
        await interaction.followup.send("❌ Deletion cancelled — pass `confirm: confirm` to proceed.", ephemeral=True)
        return

    row = await find_licence_by_key(normalize_key(key))
    if not row:
        await interaction.followup.send("❌ No license found with that key.", ephemeral=True)
        return

    await db(lambda: supabase.table("licences").update({
        "status": "deleted", "deleted_at": iso(now_utc()),
    }).eq("id", row["id"]).execute())
    await revoke_licence_sessions(row["id"], "licence_deleted")
    if row.get("discord_user_id"):
        await assign_plan_role(row["discord_user_id"], None)

    await audit_log("deletekey", str(interaction.user.id), row["id"], row.get("discord_user_id"), row["masked_key"])
    await interaction.followup.send(f"🗑️ `{row['masked_key']}` soft-deleted and all sessions revoked.", ephemeral=True)


@bot.tree.command(name="extend", description="Extend or change a license's duration")
@app_commands.describe(key="The license key", duration="New duration to extend by / set")
@admin_only()
async def extend(interaction: discord.Interaction, key: str, duration: DurationLiteral):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    row = await find_licence_by_key(normalize_key(key))
    if not row:
        await interaction.followup.send("❌ No license found with that key.", ephemeral=True)
        return

    if duration == "lifetime":
        await db(lambda: supabase.table("licences").update({
            "duration_type": "lifetime", "duration_days": None, "expires_at": None,
        }).eq("id", row["id"]).execute())
        new_expiry_txt = "Lifetime"
    elif not row["activated_at"]:
        # unused key: just change its future duration
        await db(lambda: supabase.table("licences").update({
            "duration_type": duration, "duration_days": DURATION_DAYS[duration],
        }).eq("id", row["id"]).execute())
        new_expiry_txt = f"Will expire {DURATION_DAYS[duration]} days after activation"
    else:
        current_expiry = parse_dt(row["expires_at"]) or now_utc()
        base = max(current_expiry, now_utc())
        new_expiry = base + timedelta(days=DURATION_DAYS[duration])
        await db(lambda: supabase.table("licences").update({
            "expires_at": iso(new_expiry), "duration_type": duration,
        }).eq("id", row["id"]).execute())
        new_expiry_txt = fmt_dt(iso(new_expiry))

    await audit_log("extend", str(interaction.user.id), row["id"], row.get("discord_user_id"), f"+{duration}")
    embed = discord.Embed(title="⏳ Key extended", color=discord.Color.green())
    embed.add_field(name="Key", value=row["masked_key"], inline=False)
    embed.add_field(name="New expiry", value=new_expiry_txt, inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="resetkey", description="Staff-only: reset the device (and optionally Discord) link on a key")
@app_commands.describe(key="The license key", also_unlink_discord="Also remove the Discord link")
@admin_only()
async def resetkey(interaction: discord.Interaction, key: str, also_unlink_discord: bool = False):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    row = await find_licence_by_key(normalize_key(key))
    if not row:
        await interaction.followup.send("❌ No license found with that key.", ephemeral=True)
        return

    updates = {"hwid_hash": None}
    if also_unlink_discord:
        updates["discord_user_id"] = None
    await db(lambda: supabase.table("licences").update(updates).eq("id", row["id"]).execute())
    await revoke_licence_sessions(row["id"], "resetkey")
    if also_unlink_discord and row.get("discord_user_id"):
        await assign_plan_role(row["discord_user_id"], None)

    await audit_log("resetkey", str(interaction.user.id), row["id"], row.get("discord_user_id"),
                     f"unlink_discord={also_unlink_discord}")
    await interaction.followup.send(
        f"✅ Device lock reset for `{row['masked_key']}`" +
        (" (Discord link also removed)." if also_unlink_discord else ". Discord link kept."), ephemeral=True,
    )


@bot.tree.command(name="unlinkdiscord", description="Remove the Discord link from a license")
@app_commands.describe(key="The license key")
@admin_only()
async def unlinkdiscord(interaction: discord.Interaction, key: str):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    row = await find_licence_by_key(normalize_key(key))
    if not row:
        await interaction.followup.send("❌ No license found with that key.", ephemeral=True)
        return

    old_discord = row.get("discord_user_id")
    await db(lambda: supabase.table("licences").update({"discord_user_id": None}).eq("id", row["id"]).execute())
    await revoke_licence_sessions(row["id"], "unlinked")
    if old_discord:
        await assign_plan_role(old_discord, None)

    await audit_log("unlinkdiscord", str(interaction.user.id), row["id"], old_discord, row["masked_key"])
    await interaction.followup.send(f"✅ Discord link removed from `{row['masked_key']}`.", ephemeral=True)


@bot.tree.command(name="stats", description="Show license statistics")
@admin_only()
async def stats(interaction: discord.Interaction):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    now_iso = iso(now_utc())
    today_start = iso(now_utc().replace(hour=0, minute=0, second=0, microsecond=0))

    async def count(builder):
        res = await db(builder)
        return res.count or 0

    total = await count(lambda: supabase.table("licences").select("id", count="exact").execute())
    unused = await count(lambda: supabase.table("licences").select("id", count="exact").eq("status", "unused").execute())
    active = await count(lambda: supabase.table("licences").select("id", count="exact").eq("status", "active").execute())
    expired = await count(lambda: supabase.table("licences").select("id", count="exact").eq("status", "expired").execute())
    banned = await count(lambda: supabase.table("licences").select("id", count="exact").eq("status", "banned").execute())
    basic = await count(lambda: supabase.table("licences").select("id", count="exact").eq("plan", "basic").execute())
    premium = await count(lambda: supabase.table("licences").select("id", count="exact").eq("plan", "premium").execute())
    activations_today = await count(lambda: supabase.table("licences").select("id", count="exact").gte("activated_at", today_start).execute())
    logins_ok_today = await count(lambda: supabase.table("login_events").select("id", count="exact").eq("status", "success").gte("created_at", today_start).execute())
    logins_fail_today = await count(lambda: supabase.table("login_events").select("id", count="exact").eq("status", "failure").gte("created_at", today_start).execute())
    active_sessions = await count(lambda: supabase.table("sessions").select("id", count="exact").eq("revoked", False).gte("expires_at", now_iso).execute())

    embed = discord.Embed(title="📊 Focuss Tweaks — Statistics", color=discord.Color.blurple(), timestamp=now_utc())
    embed.add_field(name="Total", value=str(total), inline=True)
    embed.add_field(name="Unused", value=str(unused), inline=True)
    embed.add_field(name="Active", value=str(active), inline=True)
    embed.add_field(name="Expired", value=str(expired), inline=True)
    embed.add_field(name="Banned", value=str(banned), inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.add_field(name="Basic", value=str(basic), inline=True)
    embed.add_field(name="Premium", value=str(premium), inline=True)
    embed.add_field(name="\u200b", value="\u200b", inline=True)
    embed.add_field(name="Activations today", value=str(activations_today), inline=True)
    embed.add_field(name="Logins ok today", value=str(logins_ok_today), inline=True)
    embed.add_field(name="Logins failed today", value=str(logins_fail_today), inline=True)
    embed.add_field(name="Active sessions", value=str(active_sessions), inline=True)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="userinfo", description="Show license info for a Discord member")
@app_commands.describe(user="The Discord member")
@admin_only()
async def userinfo(interaction: discord.Interaction, user: discord.User):
    require_supabase()
    await interaction.response.defer(ephemeral=True)
    res = await db(lambda: supabase.table("licences").select("*").eq("discord_user_id", str(user.id))
                    .order("created_at", desc=True).execute())
    rows = res.data or []
    if not rows:
        await interaction.followup.send(f"No licenses linked to {user.mention}.", ephemeral=True)
        return
    embed = discord.Embed(title=f"👤 {user}", color=discord.Color.blurple())
    for r in rows[:10]:
        embed.add_field(name=r["masked_key"],
                         value=f"{r['plan']} · {r['status']} · expires {fmt_dt(r['expires_at'])}", inline=False)
    await interaction.followup.send(embed=embed, ephemeral=True)


@bot.tree.command(name="help", description="Show all Focuss Tweaks bot commands")
@admin_only()
async def help_cmd(interaction: discord.Interaction):
    embed = discord.Embed(title="🛠️ Focuss Tweaks — Bot Commands",
                           description="All commands are staff-only and reply privately.", color=discord.Color.blurple())
    cmds = [
        ("/genkey", "plan, duration, amount, note"),
        ("/list", "filter, page"),
        ("/lookup", "query (key / masked key / Discord ID)"),
        ("/ban", "target_type, key/user, reason"),
        ("/unban", "target_type, key/user"),
        ("/deletekey", "key, confirm"),
        ("/extend", "key, duration"),
        ("/resetkey", "key, also_unlink_discord"),
        ("/unlinkdiscord", "key"),
        ("/stats", "—"),
        ("/userinfo", "user"),
        ("/help", "—"),
    ]
    for name, desc in cmds:
        embed.add_field(name=name, value=desc, inline=False)
    await interaction.response.send_message(embed=embed, ephemeral=True)


@bot.tree.error
async def on_app_command_error(interaction: discord.Interaction, error: app_commands.AppCommandError):
    msg = "🚫 You do not have permission to use this command." if isinstance(error, app_commands.CheckFailure) else "⚠️ Something went wrong running that command."
    if not isinstance(error, app_commands.CheckFailure):
        log.exception("Unhandled app command error", exc_info=error)
    try:
        if interaction.response.is_done():
            await interaction.followup.send(msg, ephemeral=True)
        else:
            await interaction.response.send_message(msg, ephemeral=True)
    except Exception:
        pass


@bot.event
async def on_ready():
    log.info("Logged in as %s (%s)", bot.user, bot.user.id if bot.user else "?")
    try:
        if GUILD_ID:
            guild_obj = discord.Object(id=GUILD_ID)
            bot.tree.copy_global_to(guild=guild_obj)
            synced = await bot.tree.sync(guild=guild_obj)
            log.info("Synced %d slash command(s) to guild %d", len(synced), GUILD_ID)
        else:
            synced = await bot.tree.sync()
            log.info("Synced %d slash command(s) globally", len(synced))
    except Exception:
        log.exception("Failed to sync slash commands")


# ═════════════════════════════════════════════════════════════════════════
# FASTAPI APP
# ═════════════════════════════════════════════════════════════════════════
app = FastAPI(title="Focuss Tweaks License API")


def err(code: str, http_status: int = 400):
    return JSONResponse(status_code=http_status, content={"error": code})


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    return (fwd.split(",")[0].strip() if fwd else request.client.host) or "unknown"


@app.get("/health")
async def health():
    return {"status": "online"}


class LicenceStartBody(BaseModel):
    licence_key: str = Field(..., max_length=64)
    hwid_hash: str = Field(..., max_length=128)


@app.post("/api/licence/start")
async def licence_start(body: LicenceStartBody, request: Request):
    require_supabase()
    ip = client_ip(request)
    if rate_limited(f"start:{ip}", 8, 60):
        return err("RATE_LIMITED", 429)

    key = normalize_key(body.licence_key)
    if not key.startswith("FOCUSS-") or key.count("-") != 4:
        return err("INVALID_KEY_FORMAT")

    row = await find_licence_by_key(key)
    if not row:
        await log_security(ip, None, None, "invalid_licence_attempt")
        return err("LICENCE_NOT_FOUND")
    if row["status"] == "deleted":
        return err("LICENCE_NOT_FOUND")
    if row["status"] == "banned" or await is_banned("licence", row["key_hash"]):
        await log_security(ip, row["id"], row.get("discord_user_id"), "banned_licence_attempt")
        return err("LICENCE_BANNED")
    if row["status"] == "active" and row["expires_at"] and parse_dt(row["expires_at"]) < now_utc():
        return err("LICENCE_EXPIRED")

    stored_hwid = hwid_store_hash(body.hwid_hash)
    if await is_banned("hwid", stored_hwid):
        await log_security(ip, row["id"], row.get("discord_user_id"), "banned_hwid_attempt")
        return err("HWID_MISMATCH")

    if row["hwid_hash"] and not const_eq(row["hwid_hash"], stored_hwid):
        await log_security(ip, row["id"], row.get("discord_user_id"), "hwid_mismatch")
        return err("HWID_MISMATCH")

    if row["discord_user_id"]:
        du = await db(lambda: supabase.table("discord_users").select("*").eq("discord_user_id", row["discord_user_id"]).limit(1).execute())
        if du.data and du.data[0]["banned"]:
            return err("DISCORD_BANNED")

    activation_token = new_opaque_token()
    oauth_state = new_opaque_token()
    expires_at = now_utc() + timedelta(seconds=ACTIVATION_LIFETIME_SECONDS)

    await db(lambda: supabase.table("activations").insert({
        "licence_id": row["id"], "activation_token_hash": token_hash(activation_token),
        "oauth_state_hash": token_hash(oauth_state), "hwid_hash": stored_hwid,
        "status": "pending", "expires_at": iso(expires_at),
    }).execute())

    params = urlencode({
        "client_id": DISCORD_CLIENT_ID, "redirect_uri": DISCORD_REDIRECT_URI,
        "response_type": "code", "scope": "identify", "state": oauth_state,
        "prompt": "consent",
    })
    oauth_url = f"https://discord.com/api/oauth2/authorize?{params}"

    return {"activation_id": activation_token, "oauth_url": oauth_url, "expires_in": ACTIVATION_LIFETIME_SECONDS}


async def log_security(ip: str, licence_id: Optional[str], discord_user_id: Optional[str], reason: str):
    await db(lambda: supabase.table("login_events").insert({
        "licence_id": licence_id, "discord_user_id": discord_user_id, "status": "failure",
        "failure_reason": reason, "ip_hash": ip_hash(ip),
    }).execute())
    cd_key = f"{reason}:{licence_id or discord_user_id or ip}"
    if cooldown_ok(_security_log_cooldown, cd_key, 30):
        embed = discord.Embed(title="⚠️ Security event", color=discord.Color.red(), timestamp=now_utc())
        embed.add_field(name="Reason", value=reason, inline=False)
        await send_log(SECURITY_LOG_CHANNEL_ID, embed)


@app.get("/oauth/discord/callback")
async def oauth_callback(code: str = "", state: str = "", error: str = ""):
    require_supabase()
    if error or not code or not state:
        return HTMLResponse(_result_page(False, "Authorization was cancelled or denied."))

    state_h = token_hash(state)
    act_res = await db(lambda: supabase.table("activations").select("*").eq("oauth_state_hash", state_h)
                        .eq("status", "pending").limit(1).execute())
    activation = act_res.data[0] if act_res.data else None
    if not activation:
        return HTMLResponse(_result_page(False, "This authorization link is invalid or was already used."))
    if parse_dt(activation["expires_at"]) < now_utc():
        await db(lambda: supabase.table("activations").update({"status": "expired"}).eq("id", activation["id"]).execute())
        return HTMLResponse(_result_page(False, "This authorization link expired. Please try again in the app."))

    await db(lambda: supabase.table("activations").update({"status": "oauth_started"}).eq("id", activation["id"]).execute())

    async with aiohttp.ClientSession() as session:
        token_resp = await session.post("https://discord.com/api/oauth2/token", data={
            "client_id": DISCORD_CLIENT_ID, "client_secret": DISCORD_CLIENT_SECRET,
            "grant_type": "authorization_code", "code": code, "redirect_uri": DISCORD_REDIRECT_URI,
        }, headers={"Content-Type": "application/x-www-form-urlencoded"})
        if token_resp.status != 200:
            await db(lambda: supabase.table("activations").update({"status": "failed"}).eq("id", activation["id"]).execute())
            return HTMLResponse(_result_page(False, "Discord did not accept the authorization. Please try again."))
        token_data = await token_resp.json()

        user_resp = await session.get("https://discord.com/api/users/@me",
                                        headers={"Authorization": f"Bearer {token_data['access_token']}"})
        if user_resp.status != 200:
            return HTMLResponse(_result_page(False, "Could not read your Discord profile. Please try again."))
        profile = await user_resp.json()

    discord_id = str(profile["id"])
    username = profile.get("username", "")
    display_name = profile.get("global_name") or username
    avatar_hash = profile.get("avatar")
    avatar_url = (f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar_hash}.png"
                  if avatar_hash else None)

    du = await db(lambda: supabase.table("discord_users").select("*").eq("discord_user_id", discord_id).limit(1).execute())
    existing_du = du.data[0] if du.data else None
    if existing_du and existing_du["banned"]:
        await db(lambda: supabase.table("activations").update({"status": "failed"}).eq("id", activation["id"]).execute())
        return HTMLResponse(_result_page(False, "This Discord account is banned from using Focuss Tweaks."))

    await db(lambda: supabase.table("discord_users").upsert({
        "discord_user_id": discord_id, "username": username, "display_name": display_name,
        "avatar_url": avatar_url, "updated_at": iso(now_utc()),
    }).execute())

    lic_res = await db(lambda: supabase.table("licences").select("*").eq("id", activation["licence_id"]).limit(1).execute())
    licence = lic_res.data[0] if lic_res.data else None
    if not licence or licence["status"] == "banned" or licence["status"] == "deleted":
        return HTMLResponse(_result_page(False, "This license is no longer valid."))

    if licence["discord_user_id"] and licence["discord_user_id"] != discord_id:
        await db(lambda: supabase.table("activations").update({"status": "failed"}).eq("id", activation["id"]).execute())
        return HTMLResponse(_result_page(False, "This license is already linked to a different Discord account."))

    if licence["hwid_hash"] and licence["hwid_hash"] != activation["hwid_hash"]:
        await db(lambda: supabase.table("activations").update({"status": "failed"}).eq("id", activation["id"]).execute())
        return HTMLResponse(_result_page(False, "This license is already linked to a different computer."))

    is_first_activation = licence["status"] == "unused"
    updates = {"discord_user_id": discord_id, "hwid_hash": activation["hwid_hash"], "status": "active"}
    if is_first_activation:
        updates["activated_at"] = iso(now_utc())
        updates["expires_at"] = iso(duration_expiry(licence["duration_type"], now_utc()))
    await db(lambda: supabase.table("licences").update(updates).eq("id", licence["id"]).execute())

    session_token = new_opaque_token()
    session_expiry = now_utc() + timedelta(seconds=SESSION_LIFETIME_SECONDS)
    await db(lambda: supabase.table("sessions").insert({
        "licence_id": licence["id"], "discord_user_id": discord_id, "token_hash": token_hash(session_token),
        "hwid_hash": activation["hwid_hash"], "expires_at": iso(session_expiry),
    }).execute())

    await db(lambda: supabase.table("activations").update({
        "status": "completed", "completed_at": iso(now_utc()),
    }).eq("id", activation["id"]).execute())

    await assign_plan_role(discord_id, licence["plan"])
    await db(lambda: supabase.table("login_events").insert({
        "licence_id": licence["id"], "discord_user_id": discord_id, "hwid_hash": activation["hwid_hash"], "status": "success",
    }).execute())

    if is_first_activation:
        embed = discord.Embed(title="✅ License activated", color=discord.Color.green(), timestamp=now_utc())
        embed.add_field(name="Discord", value=f"<@{discord_id}> ({username})", inline=False)
        embed.add_field(name="License", value=licence["masked_key"], inline=True)
        embed.add_field(name="Plan", value=licence["plan"], inline=True)
        embed.add_field(name="Duration", value=licence["duration_type"], inline=True)
        embed.add_field(name="Expires", value=fmt_dt(iso(duration_expiry(licence["duration_type"], now_utc()))) if licence["duration_type"] != "lifetime" else "Lifetime", inline=True)
        embed.add_field(name="Device fingerprint", value=activation["hwid_hash"][:12] + "…", inline=True)
        await send_log(ACTIVATION_LOG_CHANNEL_ID, embed)
    elif cooldown_ok(_login_log_cooldown, licence["id"], LOGIN_LOG_COOLDOWN_SECONDS):
        embed = discord.Embed(title="🔑 Login", color=discord.Color.blurple(), timestamp=now_utc())
        embed.add_field(name="Discord", value=f"<@{discord_id}>", inline=True)
        embed.add_field(name="License", value=licence["masked_key"], inline=True)
        await send_log(LOGIN_LOG_CHANNEL_ID, embed)

    # Stash the one-time session token behind the activation token so Electron can poll and collect it once.
    _pending_sessions[activation["activation_token_hash"]] = session_token
    return HTMLResponse(_result_page(True, "Focuss Tweaks connected successfully. You may return to the application."))


_pending_sessions: dict[str, str] = {}


def _result_page(success: bool, message: str) -> str:
    color = "#3ddc84" if success else "#ff5c5c"
    return f"""<!DOCTYPE html><html><head><meta charset="utf-8"><title>Focuss Tweaks</title>
<style>body{{background:#060606;color:#eaeaea;font-family:Segoe UI,Arial,sans-serif;display:flex;
align-items:center;justify-content:center;height:100vh;margin:0}}
.card{{background:#111;border:1px solid #222;border-radius:14px;padding:40px 48px;text-align:center;max-width:420px}}
h1{{color:{color};font-size:20px;margin-bottom:12px}}p{{color:#aaa;font-size:14px;line-height:1.5}}</style>
</head><body><div class="card"><h1>{"Connected" if success else "Something went wrong"}</h1><p>{message}</p></div></body></html>"""


@app.get("/api/licence/status/{activation_id}")
async def licence_status(activation_id: str):
    require_supabase()
    act_h = token_hash(activation_id)
    res = await db(lambda: supabase.table("activations").select("*").eq("activation_token_hash", act_h).limit(1).execute())
    if not res.data:
        return err("ACTIVATION_EXPIRED", 404)
    activation = res.data[0]

    if activation["status"] == "completed":
        session_token = _pending_sessions.pop(act_h, None)
        if session_token is None or activation["session_delivered_at"]:
            # Already delivered once — never hand it out twice.
            return {"status": "already_delivered"}
        await db(lambda: supabase.table("activations").update({"session_delivered_at": iso(now_utc())}).eq("id", activation["id"]).execute())
        lic_res = await db(lambda: supabase.table("licences").select("*").eq("id", activation["licence_id"]).limit(1).execute())
        licence = lic_res.data[0]
        return {
            "status": "completed", "session_token": session_token,
            "expires_in": SESSION_LIFETIME_SECONDS, "plan": licence["plan"], "masked_key": licence["masked_key"],
        }
    if activation["status"] == "failed":
        return {"status": "failed"}
    if parse_dt(activation["expires_at"]) < now_utc():
        return {"status": "expired"}
    return {"status": activation["status"]}


class LicenceLoginBody(BaseModel):
    licence_key: str
    hwid_hash: str


@app.post("/api/licence/login")
async def licence_login(body: LicenceLoginBody, request: Request):
    """Returning device: key + HWID already match a previously-activated,
    Discord-linked licence, so we can issue a fresh session without a new
    OAuth round-trip (identity was already proven at first activation)."""
    require_supabase()
    ip = client_ip(request)
    if rate_limited(f"login:{ip}", 10, 60):
        return err("RATE_LIMITED", 429)

    key = normalize_key(body.licence_key)
    row = await find_licence_by_key(key)
    if not row:
        return err("LICENCE_NOT_FOUND")
    if row["status"] == "banned":
        return err("LICENCE_BANNED")
    if row["status"] == "deleted" or not row["discord_user_id"] or not row["hwid_hash"]:
        return err("ACCESS_REVOKED")
    if row["expires_at"] and parse_dt(row["expires_at"]) < now_utc():
        return err("LICENCE_EXPIRED")

    stored_hwid = hwid_store_hash(body.hwid_hash)
    if not const_eq(row["hwid_hash"], stored_hwid):
        await log_security(ip, row["id"], row["discord_user_id"], "hwid_mismatch")
        return err("HWID_MISMATCH")

    du = await db(lambda: supabase.table("discord_users").select("*").eq("discord_user_id", row["discord_user_id"]).limit(1).execute())
    if du.data and du.data[0]["banned"]:
        return err("DISCORD_BANNED")

    session_token = new_opaque_token()
    session_expiry = now_utc() + timedelta(seconds=SESSION_LIFETIME_SECONDS)
    await db(lambda: supabase.table("sessions").insert({
        "licence_id": row["id"], "discord_user_id": row["discord_user_id"], "token_hash": token_hash(session_token),
        "hwid_hash": stored_hwid, "expires_at": iso(session_expiry),
    }).execute())
    await db(lambda: supabase.table("licences").update({"last_login_at": iso(now_utc())}).eq("id", row["id"]).execute())
    await db(lambda: supabase.table("login_events").insert({
        "licence_id": row["id"], "discord_user_id": row["discord_user_id"], "hwid_hash": stored_hwid, "status": "success",
    }).execute())

    if cooldown_ok(_login_log_cooldown, row["id"], LOGIN_LOG_COOLDOWN_SECONDS):
        embed = discord.Embed(title="🔑 Login", color=discord.Color.blurple(), timestamp=now_utc())
        embed.add_field(name="Discord", value=f"<@{row['discord_user_id']}>", inline=True)
        embed.add_field(name="License", value=row["masked_key"], inline=True)
        await send_log(LOGIN_LOG_CHANNEL_ID, embed)

    return {"session_token": session_token, "expires_in": SESSION_LIFETIME_SECONDS, "plan": row["plan"], "masked_key": row["masked_key"]}


async def _resolve_session(session_token: str) -> tuple[Optional[dict], Optional[dict], Optional[str]]:
    """Returns (session_row, licence_row, error_code)."""
    th = token_hash(session_token)
    res = await db(lambda: supabase.table("sessions").select("*").eq("token_hash", th).limit(1).execute())
    if not res.data:
        return None, None, "SESSION_EXPIRED"
    session = res.data[0]
    if session["revoked"]:
        return session, None, "ACCESS_REVOKED"
    if parse_dt(session["expires_at"]) < now_utc():
        return session, None, "SESSION_EXPIRED"

    lic_res = await db(lambda: supabase.table("licences").select("*").eq("id", session["licence_id"]).limit(1).execute())
    licence = lic_res.data[0] if lic_res.data else None
    if not licence or licence["status"] in ("banned", "deleted"):
        return session, None, "ACCESS_REVOKED"
    if licence["expires_at"] and parse_dt(licence["expires_at"]) < now_utc():
        if licence["status"] != "expired":
            await db(lambda: supabase.table("licences").update({"status": "expired"}).eq("id", licence["id"]).execute())
        return session, None, "LICENCE_EXPIRED"

    du = await db(lambda: supabase.table("discord_users").select("banned").eq("discord_user_id", session["discord_user_id"]).limit(1).execute())
    if du.data and du.data[0]["banned"]:
        return session, None, "DISCORD_BANNED"

    if await is_banned("hwid", session["hwid_hash"]):
        return session, None, "HWID_MISMATCH"

    await db(lambda: supabase.table("sessions").update({"last_activity_at": iso(now_utc())}).eq("id", session["id"]).execute())
    return session, licence, None


class TokenBody(BaseModel):
    session_token: str


@app.post("/api/session/validate")
async def session_validate(body: TokenBody, request: Request):
    require_supabase()
    if rate_limited(f"validate:{client_ip(request)}", 30, 60):
        return err("RATE_LIMITED", 429)
    session, licence, error = await _resolve_session(body.session_token)
    if error:
        return err(error, 401)
    return {"valid": True, "plan": licence["plan"], "masked_key": licence["masked_key"],
            "expires_at": licence["expires_at"]}


@app.post("/api/session/refresh")
async def session_refresh(body: TokenBody, request: Request):
    require_supabase()
    if rate_limited(f"refresh:{client_ip(request)}", 10, 60):
        return err("RATE_LIMITED", 429)
    session, licence, error = await _resolve_session(body.session_token)
    if error:
        return err(error, 401)

    await db(lambda: supabase.table("sessions").update({
        "revoked": True, "revoked_at": iso(now_utc()), "revocation_reason": "refreshed",
    }).eq("id", session["id"]).execute())

    new_token = new_opaque_token()
    new_expiry = now_utc() + timedelta(seconds=SESSION_LIFETIME_SECONDS)
    await db(lambda: supabase.table("sessions").insert({
        "licence_id": licence["id"], "discord_user_id": session["discord_user_id"], "token_hash": token_hash(new_token),
        "hwid_hash": session["hwid_hash"], "expires_at": iso(new_expiry),
    }).execute())
    return {"session_token": new_token, "expires_in": SESSION_LIFETIME_SECONDS}


@app.get("/api/user/me")
async def user_me(session_token: str):
    require_supabase()
    session, licence, error = await _resolve_session(session_token)
    if error:
        return err(error, 401)
    du = await db(lambda: supabase.table("discord_users").select("*").eq("discord_user_id", session["discord_user_id"]).limit(1).execute())
    profile = du.data[0] if du.data else {}
    return {
        "discord_id": profile.get("discord_user_id"), "username": profile.get("username"),
        "display_name": profile.get("display_name"), "avatar_url": profile.get("avatar_url"),
        "plan": licence["plan"], "masked_key": licence["masked_key"],
        "activated_at": licence["activated_at"], "expires_at": licence["expires_at"],
        "device_recognised": True,
    }


@app.post("/api/logout")
async def logout(body: TokenBody):
    require_supabase()
    th = token_hash(body.session_token)
    await db(lambda: supabase.table("sessions").update({
        "revoked": True, "revoked_at": iso(now_utc()), "revocation_reason": "user_logout",
    }).eq("token_hash", th).execute())
    return {"ok": True}


class FeatureValidateBody(BaseModel):
    session_token: str
    feature_id: str = Field(..., max_length=128)


@app.post("/api/feature/validate")
async def feature_validate(body: FeatureValidateBody, request: Request):
    require_supabase()
    if rate_limited(f"feature:{client_ip(request)}", 60, 60):
        return err("RATE_LIMITED", 429)

    definition = TWEAK_DEFINITIONS.get(body.feature_id)
    if not definition:
        return err("UNKNOWN_FEATURE", 400)

    session, licence, error = await _resolve_session(body.session_token)
    if error:
        return err(error, 401)

    if not plan_satisfies(licence["plan"], definition["requiredPlan"]):
        return err("PLAN_REQUIRED", 403)

    return {"allowed": True}


class SecurityReportBody(BaseModel):
    session_token: Optional[str] = None
    event: str = Field(..., max_length=64)
    details: Optional[str] = Field(None, max_length=500)


@app.post("/api/security/report")
async def security_report(body: SecurityReportBody, request: Request):
    require_supabase()
    if rate_limited(f"secreport:{client_ip(request)}", 10, 60):
        return err("RATE_LIMITED", 429)
    discord_id = None
    if body.session_token:
        session, _licence, _error = await _resolve_session(body.session_token)
        if session:
            discord_id = session.get("discord_user_id")
    await log_security(client_ip(request), None, discord_id, f"client_report:{body.event}")
    return {"ok": True}


# ═════════════════════════════════════════════════════════════════════════
# BACKGROUND: expire licences whose date has passed
# ═════════════════════════════════════════════════════════════════════════
async def expiry_sweep():
    while True:
        try:
            if supabase:
                now_iso = iso(now_utc())
                res = await db(lambda: supabase.table("licences").select("id").eq("status", "active")
                                .lt("expires_at", now_iso).execute())
                for row in (res.data or []):
                    await db(lambda rid=row["id"]: supabase.table("licences").update({"status": "expired"}).eq("id", rid).execute())
                    await revoke_licence_sessions(row["id"], "licence_expired")
        except Exception:
            log.exception("expiry sweep failed")
        await asyncio.sleep(300)


# ═════════════════════════════════════════════════════════════════════════
# STARTUP — run the Discord bot and the FastAPI server together
# ═════════════════════════════════════════════════════════════════════════
async def run_all():
    config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level="info")
    server = uvicorn.Server(config)
    tasks = [asyncio.create_task(server.serve()), asyncio.create_task(expiry_sweep())]
    if DISCORD_BOT_TOKEN:
        tasks.append(asyncio.create_task(bot.start(DISCORD_BOT_TOKEN)))
    else:
        log.critical("DISCORD_BOT_TOKEN missing — bot will not start, API will still run.")
    await asyncio.gather(*tasks)


def main():
    if supabase is None:
        log.critical("Supabase is not configured — aborting.")
        return
    if not ADMIN_IDS and not STAFF_ROLE_IDS:
        log.warning("No admin IDs or staff roles configured — nobody can use staff commands!")
    try:
        asyncio.run(run_all())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
