begin;

alter table authlink.trusted_device
  add column if not exists display_name text,
  add column if not exists key_alg text,
  add column if not exists public_key_jwk jsonb,
  add column if not exists proofed_at timestamptz,
  add column if not exists revoked_at timestamptz;

alter table authlink.session
  add column if not exists assurance_evidence jsonb not null default '{}'::jsonb;

create table if not exists authlink.device_challenge (
  id uuid primary key,
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  session_id uuid not null references authlink.session(id) on delete cascade,
  device_id uuid references authlink.trusted_device(id) on delete cascade,
  action text not null check (action in ('enroll', 'bind-session')),
  nonce bytea not null check (octet_length(nonce) = 32),
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_device_challenge_active
  on authlink.device_challenge(session_id, expires_at)
  where used_at is null;

create index if not exists idx_trusted_device_owner_state
  on authlink.trusted_device(tenant_id, identity_id, trust_state, last_seen_at desc);

comment on table authlink.device_challenge is
  'Single-use possession challenges bound to the current AuthLink session and identity.';

comment on column authlink.trusted_device.public_key_jwk is
  'Public P-256 JWK only. Private device keys must never leave the client keystore/WebCrypto container.';

commit;
