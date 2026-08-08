begin;

create extension if not exists pgcrypto;

create schema if not exists authlink;
create schema if not exists audit;
create schema if not exists outbox;

create table if not exists authlink.identity (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  subject text not null unique,
  display_name text,
  avatar_ref text,
  assurance_level text not null default 'basic',
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists authlink.trusted_device (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  device_public_id text not null,
  platform text not null,
  trust_state text not null default 'pending',
  attestation_kind text,
  attestation_ref text,
  last_seen_at timestamptz,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  unique(identity_id, device_public_id)
);

create table if not exists authlink.session (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  trusted_device_id uuid references authlink.trusted_device(id),
  audience text not null,
  purpose text not null,
  auth_strength text not null,
  state text not null default 'active',
  expires_at timestamptz not null,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists authlink.consent_grant (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  purpose text not null,
  resource_ref text not null,
  scopes jsonb not null default '[]'::jsonb,
  state text not null default 'granted',
  expires_at timestamptz,
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create table if not exists audit.journal (
  sequence bigserial primary key,
  event_id uuid not null unique,
  tenant_id uuid not null,
  actor_id uuid,
  object_ref text not null,
  purpose text not null,
  correlation_id uuid not null,
  event_type text not null,
  summary jsonb not null default '{}'::jsonb,
  previous_hash bytea,
  entry_hash bytea not null,
  occurred_at timestamptz not null default now()
);

create table if not exists outbox.domain_event (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  aggregate_ref text not null,
  event_type text not null,
  correlation_id uuid not null,
  payload jsonb not null,
  created_at timestamptz not null default now(),
  published_at timestamptz
);

create index if not exists idx_session_identity_state on authlink.session(identity_id, state);
create index if not exists idx_consent_identity_purpose on authlink.consent_grant(identity_id, purpose, state);
create index if not exists idx_audit_object_ref on audit.journal(object_ref, sequence desc);
create index if not exists idx_outbox_unpublished on outbox.domain_event(created_at) where published_at is null;

commit;
