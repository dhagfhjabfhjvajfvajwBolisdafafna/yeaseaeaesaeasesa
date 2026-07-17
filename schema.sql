-- Focuss Tweaks — license system schema
-- Run this against your Supabase project (SQL editor). Idempotent-ish; safe to re-run with IF NOT EXISTS guards.

create extension if not exists pgcrypto;

-- ─────────────────────────────────────────────────────────────
-- licences
-- ─────────────────────────────────────────────────────────────
create table if not exists licences (
    id                      uuid primary key default gen_random_uuid(),
    key_hash                text not null unique,          -- hmac-sha256(full key)
    key_prefix              text not null,                  -- "FOCUSS"
    key_last_four           text not null,
    masked_key              text not null,                  -- FOCUSS-****-****-A7X2
    plan                    text not null check (plan in ('basic','premium')),
    duration_type           text not null check (duration_type in ('1d','3d','7d','30d','lifetime')),
    duration_days           int,                             -- null for lifetime
    status                  text not null default 'unused' check (status in ('unused','active','expired','banned','deleted')),
    created_at              timestamptz not null default now(),
    activated_at            timestamptz,
    expires_at              timestamptz,
    discord_user_id         text,
    hwid_hash                text,                            -- hmac-sha256(sha256(hwid components))
    created_by_discord_id   text not null,
    last_login_at           timestamptz,
    revoked_at              timestamptz,
    deleted_at              timestamptz,
    staff_note              text
);
create index if not exists idx_licences_discord_user on licences(discord_user_id);
create index if not exists idx_licences_status on licences(status);
create index if not exists idx_licences_hwid on licences(hwid_hash);

-- ─────────────────────────────────────────────────────────────
-- discord_users
-- ─────────────────────────────────────────────────────────────
create table if not exists discord_users (
    discord_user_id  text primary key,
    username         text,
    display_name     text,
    avatar_url       text,
    created_at       timestamptz not null default now(),
    updated_at       timestamptz not null default now(),
    banned           boolean not null default false,
    ban_reason       text,
    banned_at        timestamptz
);

-- ─────────────────────────────────────────────────────────────
-- activations (short-lived OAuth activation requests)
-- ─────────────────────────────────────────────────────────────
create table if not exists activations (
    id                      uuid primary key default gen_random_uuid(),
    licence_id              uuid not null references licences(id) on delete cascade,
    activation_token_hash   text not null unique,
    oauth_state_hash        text not null unique,
    hwid_hash                text not null,
    status                  text not null default 'pending' check (status in ('pending','oauth_started','completed','expired','failed')),
    created_at              timestamptz not null default now(),
    expires_at              timestamptz not null,
    completed_at            timestamptz,
    session_delivered_at    timestamptz
);
create index if not exists idx_activations_licence on activations(licence_id);
create index if not exists idx_activations_status on activations(status);

-- ─────────────────────────────────────────────────────────────
-- sessions
-- ─────────────────────────────────────────────────────────────
create table if not exists sessions (
    id                  uuid primary key default gen_random_uuid(),
    licence_id          uuid not null references licences(id) on delete cascade,
    discord_user_id     text not null,
    token_hash          text not null unique,
    hwid_hash            text not null,
    created_at          timestamptz not null default now(),
    expires_at          timestamptz not null,
    last_activity_at    timestamptz not null default now(),
    revoked             boolean not null default false,
    revoked_at          timestamptz,
    revocation_reason   text
);
create index if not exists idx_sessions_licence on sessions(licence_id);
create index if not exists idx_sessions_token on sessions(token_hash);
create index if not exists idx_sessions_revoked on sessions(revoked);

-- ─────────────────────────────────────────────────────────────
-- bans
-- ─────────────────────────────────────────────────────────────
create table if not exists bans (
    id                      uuid primary key default gen_random_uuid(),
    ban_type                text not null check (ban_type in ('licence','discord_user','hwid')),
    target_hash_or_id       text not null,
    reason                  text not null,
    created_by_discord_id   text not null,
    created_at              timestamptz not null default now(),
    active                  boolean not null default true,
    removed_at              timestamptz,
    removed_by_discord_id   text
);
create index if not exists idx_bans_target on bans(target_hash_or_id) where active;

-- ─────────────────────────────────────────────────────────────
-- login_events
-- ─────────────────────────────────────────────────────────────
create table if not exists login_events (
    id                  uuid primary key default gen_random_uuid(),
    licence_id          uuid references licences(id) on delete set null,
    discord_user_id     text,
    hwid_hash            text,
    status              text not null check (status in ('success','failure')),
    failure_reason      text,
    ip_hash             text,
    session_id          uuid,
    created_at          timestamptz not null default now()
);
create index if not exists idx_login_events_licence on login_events(licence_id);

-- ─────────────────────────────────────────────────────────────
-- audit_logs
-- ─────────────────────────────────────────────────────────────
create table if not exists audit_logs (
    id                  uuid primary key default gen_random_uuid(),
    action              text not null,
    admin_discord_id    text,
    licence_id          uuid,
    discord_user_id     text,
    details             text,
    created_at          timestamptz not null default now()
);

-- ─────────────────────────────────────────────────────────────
-- RLS — public/anon has zero access. Only the service-role key (used
-- exclusively by the Railway backend) can read/write these tables.
-- ─────────────────────────────────────────────────────────────
alter table licences enable row level security;
alter table discord_users enable row level security;
alter table activations enable row level security;
alter table sessions enable row level security;
alter table bans enable row level security;
alter table login_events enable row level security;
alter table audit_logs enable row level security;
-- No policies are created, so with RLS enabled, only service_role (bypasses RLS) can access these tables.
