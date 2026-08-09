begin;

create table if not exists authlink.vault_item (
  id uuid primary key,
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  kind text not null,
  purpose text not null,
  key_version integer not null check (key_version > 0),
  envelope jsonb not null,
  state text not null default 'active' check (state in ('active', 'deleted')),
  version bigint not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  deleted_at timestamptz,
  check (jsonb_typeof(envelope) = 'object')
);

create index if not exists idx_vault_item_owner_active
  on authlink.vault_item(tenant_id, identity_id, created_at desc)
  where state = 'active';

create index if not exists idx_vault_item_key_version
  on authlink.vault_item(key_version)
  where state = 'active';

comment on table authlink.vault_item is
  'Encrypted AuthLink Vault envelopes only. Master keys and plaintext must never be stored here.';

commit;
