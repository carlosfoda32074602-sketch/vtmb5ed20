-- VTM 5e d20 Mesa Virtual — Supabase initial schema
-- Run in Supabase Dashboard > SQL Editor after enabling Email auth.
-- Requires pgcrypto (available in Supabase projects).
create extension if not exists pgcrypto with schema extensions;

create table if not exists public.vtm_rooms (
  id uuid primary key default gen_random_uuid(),
  code text not null unique check (code ~ '^[A-Z0-9]{6}$'),
  name text not null default 'Crônica sem nome' check (char_length(name) between 1 and 70),
  owner_id uuid not null references auth.users(id) on delete cascade,
  host_password_hash text not null,
  invite_password_hash text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.vtm_room_members (
  room_id uuid not null references public.vtm_rooms(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('narrator','player')),
  display_name text not null default 'Jogador' check (char_length(display_name) between 1 and 40),
  joined_at timestamptz not null default now(),
  primary key (room_id, user_id)
);

create table if not exists public.vtm_room_state (
  room_id uuid primary key references public.vtm_rooms(id) on delete cascade,
  state jsonb not null default '{}'::jsonb,
  updated_by uuid references auth.users(id) on delete set null,
  updated_at timestamptz not null default now()
);

create table if not exists public.vtm_chat_messages (
  id uuid primary key default gen_random_uuid(),
  room_id uuid not null references public.vtm_rooms(id) on delete cascade,
  sender_id uuid not null default auth.uid() references auth.users(id) on delete cascade,
  sender_name text not null check (char_length(sender_name) between 1 and 40),
  body text not null check (char_length(body) between 1 and 2000),
  kind text not null default 'message' check (char_length(kind) <= 30),
  detail text not null default '' check (char_length(detail) <= 300),
  created_at timestamptz not null default now()
);
create index if not exists vtm_chat_room_created_idx on public.vtm_chat_messages(room_id, created_at desc);

alter table public.vtm_rooms enable row level security;
alter table public.vtm_room_members enable row level security;
alter table public.vtm_room_state enable row level security;
alter table public.vtm_chat_messages enable row level security;

-- SECURITY DEFINER helper avoids recursive RLS evaluation on vtm_room_members.
create or replace function public.vtm_is_room_member(p_room_id uuid)
returns boolean language sql stable security definer
set search_path = public, pg_temp as $$
  select exists (select 1 from public.vtm_room_members m where m.room_id = p_room_id and m.user_id = auth.uid());
$$;
revoke all on function public.vtm_is_room_member(uuid) from public, anon;
grant execute on function public.vtm_is_room_member(uuid) to authenticated;

-- Room records and password hashes are only visible to members. Password hashes are never returned by RPCs.
create policy "room members can read room metadata" on public.vtm_rooms for select to authenticated
using (public.vtm_is_room_member(id));
create policy "members can see room members" on public.vtm_room_members for select to authenticated
using (public.vtm_is_room_member(room_id));
create policy "members can read room state" on public.vtm_room_state for select to authenticated
using (public.vtm_is_room_member(room_id));
create policy "narrator can update room state" on public.vtm_room_state for update to authenticated
using (exists (select 1 from public.vtm_room_members m where m.room_id = vtm_room_state.room_id and m.user_id = auth.uid() and m.role = 'narrator'))
with check (exists (select 1 from public.vtm_room_members m where m.room_id = vtm_room_state.room_id and m.user_id = auth.uid() and m.role = 'narrator'));
create policy "members can read chat" on public.vtm_chat_messages for select to authenticated
using (public.vtm_is_room_member(room_id));
create policy "members can send chat" on public.vtm_chat_messages for insert to authenticated
with check (sender_id = auth.uid() and public.vtm_is_room_member(room_id));

-- Creation/join are RPC-only; client cannot directly insert rooms or memberships.
revoke all on public.vtm_rooms, public.vtm_room_members from anon, authenticated;
grant select on public.vtm_rooms, public.vtm_room_members to authenticated;
grant select on public.vtm_room_state, public.vtm_chat_messages to authenticated;
grant insert on public.vtm_chat_messages to authenticated;
grant update (state, updated_by, updated_at) on public.vtm_room_state to authenticated;

create or replace function public.vtm_create_room(
  p_name text, p_host_password text, p_invite_password text, p_display_name text
) returns jsonb
language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare v_user uuid := auth.uid(); v_code text; v_room public.vtm_rooms; v_display text;
begin
  if v_user is null then raise exception 'Faça login antes de criar uma sala.'; end if;
  if length(coalesce(p_host_password,'')) < 8 then raise exception 'A senha do Narrador deve ter pelo menos 8 caracteres.'; end if;
  if length(coalesce(p_invite_password,'')) < 6 then raise exception 'A senha de convite deve ter pelo menos 6 caracteres.'; end if;
  v_display := left(coalesce(nullif(trim(p_display_name),''),'Narrador'),40);
  loop
    v_code := upper(substr(encode(gen_random_bytes(5),'hex'),1,6));
    exit when not exists (select 1 from public.vtm_rooms where code = v_code);
  end loop;
  insert into public.vtm_rooms(code,name,owner_id,host_password_hash,invite_password_hash)
  values(v_code, left(coalesce(nullif(trim(p_name),''),'Crônica sem nome'),70), v_user,
         extensions.crypt(p_host_password, extensions.gen_salt('bf')),
         extensions.crypt(p_invite_password, extensions.gen_salt('bf')))
  returning * into v_room;
  insert into public.vtm_room_members(room_id,user_id,role,display_name) values(v_room.id,v_user,'narrator',v_display);
  insert into public.vtm_room_state(room_id,state,updated_by) values(v_room.id,'{}'::jsonb,v_user);
  return jsonb_build_object('id',v_room.id,'code',v_room.code,'name',v_room.name,'role','narrator','display_name',v_display);
end $$;

create or replace function public.vtm_join_room(p_code text, p_invite_password text, p_display_name text)
returns jsonb language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare v_user uuid := auth.uid(); v_room public.vtm_rooms; v_display text;
begin
  if v_user is null then raise exception 'Faça login antes de entrar em uma sala.'; end if;
  select * into v_room from public.vtm_rooms where code = upper(regexp_replace(coalesce(p_code,''),'[^A-Z0-9]','','g'));
  if not found then raise exception 'Sala não encontrada.'; end if;
  if extensions.crypt(coalesce(p_invite_password,''), v_room.invite_password_hash) <> v_room.invite_password_hash then
    raise exception 'Senha de convite incorreta.';
  end if;
  v_display := left(coalesce(nullif(trim(p_display_name),''),'Jogador'),40);
  insert into public.vtm_room_members(room_id,user_id,role,display_name)
  values(v_room.id,v_user,case when v_room.owner_id = v_user then 'narrator' else 'player' end,v_display)
  on conflict (room_id,user_id) do update set display_name = excluded.display_name;
  return jsonb_build_object('id',v_room.id,'code',v_room.code,'name',v_room.name,
    'role',case when v_room.owner_id = v_user then 'narrator' else 'player' end,'display_name',v_display);
end $$;

create or replace function public.vtm_resume_as_narrator(p_code text, p_host_password text, p_display_name text)
returns jsonb language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare v_user uuid := auth.uid(); v_room public.vtm_rooms; v_display text;
begin
  if v_user is null then raise exception 'Faça login antes de retomar uma sala.'; end if;
  select * into v_room from public.vtm_rooms where code = upper(regexp_replace(coalesce(p_code,''),'[^A-Z0-9]','','g'));
  if not found or v_room.owner_id <> v_user then raise exception 'Sala não encontrada para esta conta.'; end if;
  if extensions.crypt(coalesce(p_host_password,''), v_room.host_password_hash) <> v_room.host_password_hash then
    raise exception 'Senha do Narrador incorreta.';
  end if;
  v_display := left(coalesce(nullif(trim(p_display_name),''),'Narrador'),40);
  insert into public.vtm_room_members(room_id,user_id,role,display_name) values(v_room.id,v_user,'narrator',v_display)
  on conflict (room_id,user_id) do update set role='narrator',display_name=excluded.display_name;
  return jsonb_build_object('id',v_room.id,'code',v_room.code,'name',v_room.name,'role','narrator','display_name',v_display);
end $$;

revoke all on function public.vtm_create_room(text,text,text,text) from public, anon;
revoke all on function public.vtm_join_room(text,text,text) from public, anon;
revoke all on function public.vtm_resume_as_narrator(text,text,text) from public, anon;
grant execute on function public.vtm_create_room(text,text,text,text) to authenticated;
grant execute on function public.vtm_join_room(text,text,text) to authenticated;
grant execute on function public.vtm_resume_as_narrator(text,text,text) to authenticated;

-- Enable Supabase Realtime for state and chat changes.
do $$ begin
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='vtm_room_state') then
    alter publication supabase_realtime add table public.vtm_room_state;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='vtm_chat_messages') then
    alter publication supabase_realtime add table public.vtm_chat_messages;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname='supabase_realtime' and schemaname='public' and tablename='vtm_room_members') then
    alter publication supabase_realtime add table public.vtm_room_members;
  end if;
end $$;

-- Character sheets are separate room records: players can save their own sheets,
-- while the narrator can manage all sheets. This avoids whole-room snapshots
-- overwriting another player's local character editor.
create table if not exists public.vtm_room_characters (
  room_id uuid not null references public.vtm_rooms(id) on delete cascade,
  id text not null,
  owner_id uuid not null references auth.users(id) on delete cascade,
  updated_by uuid references auth.users(id) on delete set null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (room_id, id)
);
alter table public.vtm_room_characters enable row level security;

create policy "members can read room characters"
on public.vtm_room_characters for select to authenticated
using (public.vtm_is_room_member(room_id));

create policy "owners and narrator can insert room characters"
on public.vtm_room_characters for insert to authenticated
with check (
  public.vtm_is_room_member(room_id)
  and (
    owner_id = auth.uid()
    or exists (
      select 1 from public.vtm_room_members m
      where m.room_id = vtm_room_characters.room_id
        and m.user_id = auth.uid()
        and m.role = 'narrator'
    )
  )
);

create policy "owners and narrator can update room characters"
on public.vtm_room_characters for update to authenticated
using (
  public.vtm_is_room_member(room_id)
  and (
    owner_id = auth.uid()
    or exists (
      select 1 from public.vtm_room_members m
      where m.room_id = vtm_room_characters.room_id
        and m.user_id = auth.uid()
        and m.role = 'narrator'
    )
  )
)
with check (
  public.vtm_is_room_member(room_id)
  and (
    owner_id = auth.uid()
    or exists (
      select 1 from public.vtm_room_members m
      where m.room_id = vtm_room_characters.room_id
        and m.user_id = auth.uid()
        and m.role = 'narrator'
    )
  )
);

create policy "owners and narrator can delete room characters"
on public.vtm_room_characters for delete to authenticated
using (
  public.vtm_is_room_member(room_id)
  and (
    owner_id = auth.uid()
    or exists (
      select 1 from public.vtm_room_members m
      where m.room_id = vtm_room_characters.room_id
        and m.user_id = auth.uid()
        and m.role = 'narrator'
    )
  )
);

grant select, insert, update, delete on public.vtm_room_characters to authenticated;

do $$ begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname='supabase_realtime'
      and schemaname='public'
      and tablename='vtm_room_characters'
  ) then
    alter publication supabase_realtime add table public.vtm_room_characters;
  end if;
end $$;
