create table if not exists users (
  id serial primary key,
  email text unique not null,
  password_hash text not null,
  role text not null default 'user' check (role in ('user','admin')),
  created_at timestamptz default now()
);

create table if not exists sessions (
  token_hash text primary key,
  user_id int references users(id) on delete cascade,
  expires_at timestamptz not null
);
