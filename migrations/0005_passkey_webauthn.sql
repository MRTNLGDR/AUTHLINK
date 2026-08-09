begin;

create table if not exists authlink.passkey_credential (
  id uuid primary key,
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  credential_id text not null unique,
  public_key bytea not null,
  counter bigint not null default 0 check (counter >= 0),
  transports jsonb not null default '[]'::jsonb,
  aaguid text,
  attestation_format text,
  credential_device_type text not null,
  credential_backed_up boolean not null default false,
  state text not null default 'active' check (state in ('active','revoked')),
  created_at timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at timestamptz,
  version bigint not null default 1
);

create table if not exists authlink.passkey_challenge (
  id uuid primary key,
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  session_id uuid not null references authlink.session(id) on delete cascade,
  action text not null check (action in ('register','authenticate')),
  challenge bytea not null check (octet_length(challenge) = 32),
  expires_at timestamptz not null,
  used_at timestamptz,
  created_at timestamptz not null default now()
);

create index if not exists idx_passkey_owner_active
  on authlink.passkey_credential(tenant_id, identity_id, created_at desc)
  where state = 'active';

create index if not exists idx_passkey_challenge_active
  on authlink.passkey_challenge(session_id, action, expires_at)
  where used_at is null;

comment on table authlink.passkey_credential is
  'Verified WebAuthn credentials. public_key is COSE credential public key; private keys never leave authenticators.';

comment on table authlink.passkey_challenge is
  'Single-use WebAuthn ceremony challenges owned by Rust AuthLink state, never by the verifier adapter.';

commit;
