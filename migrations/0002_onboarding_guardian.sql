begin;

create table if not exists authlink.onboarding_ceremony (
  id uuid primary key,
  tenant_id uuid,
  identity_id uuid references authlink.identity(id) on delete cascade,
  device_public_id text,
  current_step text not null default 'welcome',
  completed_steps integer not null default 0,
  total_steps integer not null default 16,
  auth_strength text not null default 'anonymous',
  trusted_device boolean not null default false,
  risk_score smallint not null default 24 check (risk_score between 0 and 100),
  state text not null default 'active',
  evidence_refs jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  completed_at timestamptz
);

create table if not exists authlink.guardian_decision (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid,
  identity_id uuid references authlink.identity(id) on delete cascade,
  session_id uuid references authlink.session(id) on delete set null,
  device_id uuid references authlink.trusted_device(id) on delete set null,
  score smallint not null check (score between 0 and 100),
  level text not null,
  action text not null,
  reasons jsonb not null default '[]'::jsonb,
  signal_summary jsonb not null default '{}'::jsonb,
  correlation_id uuid,
  created_at timestamptz not null default now()
);

create table if not exists authlink.credential_ref (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null,
  identity_id uuid not null references authlink.identity(id) on delete cascade,
  kind text not null,
  label text not null,
  provider text,
  public_ref text,
  secret_ref text,
  state text not null default 'active',
  last_used_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(identity_id, kind, label)
);

create index if not exists idx_onboarding_identity on authlink.onboarding_ceremony(identity_id, state);
create index if not exists idx_guardian_identity_time on authlink.guardian_decision(identity_id, created_at desc);
create index if not exists idx_credential_identity_kind on authlink.credential_ref(identity_id, kind, state);

commit;
