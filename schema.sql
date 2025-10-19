create table if not exists families (
  id uuid primary key default gen_random_uuid(),
  email text unique not null,
  password_hash text not null,
  created_at timestamptz default now()
);

create table if not exists children (
  id uuid primary key default gen_random_uuid(),
  family_id uuid references families(id) on delete cascade,
  name text not null,
  yob int,
  created_at timestamptz default now()
);

create table if not exists rules (
  id uuid primary key default gen_random_uuid(),
  family_id uuid references families(id) on delete cascade,
  platform text not null,
  daily_minutes int not null,
  bedtime text not null,
  whitelist jsonb default '[]',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists usage_events (
  id bigserial primary key,
  family_id uuid references families(id) on delete cascade,
  child_id uuid references children(id) on delete set null,
  platform text not null,
  kind text not null,
  payload jsonb default '{}'::jsonb,
  created_at timestamptz default now()
);
