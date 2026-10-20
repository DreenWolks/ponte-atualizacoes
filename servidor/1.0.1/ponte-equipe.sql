-- =====================================================================
-- Ponte — banco de dados da equipe (Supabase ou Ponte Servidor)
-- Como usar no Supabase: SQL Editor > New query > cole TUDO > Run.
-- Pode rodar de novo quando o Ponte pedir (ele atualiza sem apagar dados).
-- No Ponte Servidor (sua VM) não precisa fazer nada: ele roda este arquivo sozinho.
-- =====================================================================

create sequence if not exists public.ponte_seq;

create table if not exists public.ponte_teams (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  owner uuid not null,
  created_at timestamptz not null default now()
);

create table if not exists public.ponte_members (
  team_id uuid not null references public.ponte_teams(id) on delete cascade,
  user_id uuid not null,
  email text,
  name text not null,
  role text not null default 'member' check (role in ('owner', 'member')),
  perms jsonb not null default '{}'::jsonb,
  active boolean not null default true,
  last_seen timestamptz,
  client text,
  app_version text,
  joined_at timestamptz not null default now(),
  primary key (team_id, user_id)
);

create table if not exists public.ponte_invites (
  code text primary key,
  team_id uuid not null references public.ponte_teams(id) on delete cascade,
  role text not null default 'member',
  perms jsonb not null default '{}'::jsonb,
  label text,
  created_by uuid,
  created_at timestamptz not null default now(),
  expires_at timestamptz not null,
  used_by uuid,
  used_at timestamptz
);

create table if not exists public.ponte_docs (
  team_id uuid not null references public.ponte_teams(id) on delete cascade,
  kind text not null,
  key text not null,
  data jsonb,
  deleted boolean not null default false,
  version bigint not null default nextval('public.ponte_seq'),
  updated_by uuid,
  updated_name text,
  updated_at timestamptz not null default now(),
  primary key (team_id, kind, key)
);
create index if not exists ponte_docs_version on public.ponte_docs (team_id, version);

create table if not exists public.ponte_leases (
  team_id uuid not null references public.ponte_teams(id) on delete cascade,
  name text not null,
  holder uuid,
  holder_name text,
  client text,
  until timestamptz,
  primary key (team_id, name)
);
alter table public.ponte_leases add column if not exists app text;

-- equipe trazida de outro servidor: quem ainda não entrou no servidor novo
create table if not exists public.ponte_pending (
  team_id uuid not null references public.ponte_teams(id) on delete cascade,
  email text not null,
  name text not null,
  role text not null default 'member',
  perms jsonb not null default '{}'::jsonb,
  token_hash text not null,
  created_at timestamptz not null default now(),
  primary key (team_id, email)
);

-- ninguém acessa as tabelas diretamente: tudo passa pelas funções abaixo, que conferem a equipe e as permissões
alter table public.ponte_teams enable row level security;
alter table public.ponte_members enable row level security;
alter table public.ponte_invites enable row level security;
alter table public.ponte_docs enable row level security;
alter table public.ponte_leases enable row level security;
alter table public.ponte_pending enable row level security;
revoke all on public.ponte_teams, public.ponte_members, public.ponte_invites, public.ponte_docs, public.ponte_leases, public.ponte_pending from anon, authenticated;
revoke all on sequence public.ponte_seq from anon, authenticated;

-- ---------------------------------------------------------------- utilidades
create or replace function public.ponte_schema_version() returns int
language sql stable as $$ select 5 $$;

-- compara versões do app (1.10.0 > 1.9.2)
create or replace function public._ponte_ver_lt(a text, b text) returns boolean
language sql immutable as $$
  select coalesce(string_to_array(regexp_replace(coalesce(a, '0'), '[^0-9.]', '', 'g'), '.')::int[] < string_to_array(regexp_replace(coalesce(b, '0'), '[^0-9.]', '', 'g'), '.')::int[], false)
$$;

create or replace function public._ponte_founder(p_team uuid) returns uuid
language sql stable security definer set search_path = public as $$ select owner from public.ponte_teams where id = p_team $$;

create or replace function public._ponte_me(p_team uuid) returns public.ponte_members
language plpgsql stable security definer set search_path = public as $$
declare m public.ponte_members;
begin
  if auth.uid() is null then raise exception 'Faça login na equipe novamente.' using errcode = 'P0001'; end if;
  select * into m from public.ponte_members where team_id = p_team and user_id = auth.uid();
  if not found or not m.active then raise exception 'Você não faz parte desta equipe (ou foi removido pelo dono).' using errcode = 'P0001'; end if;
  return m;
end $$;

create or replace function public._ponte_can(m public.ponte_members, p text) returns boolean
language sql immutable as $$
  select m.role = 'owner' or coalesce((m.perms ->> p)::boolean, false)
$$;

-- campos que só quem vê custos pode ler ou gravar
create or replace function public._ponte_cost_keys(p_kind text) returns text[]
language sql immutable as $$
  select case p_kind
    when 'product' then array['manualCost', 'batchId', 'costSource']
    when 'order' then array['paidAmount', 'extraCost', 'recovered', 'returnShipping']
    when 'draft' then array['cost']
    else array[]::text[] end
$$;

create or replace function public._ponte_visible(m public.ponte_members, p_kind text, p_key text, p_sharing jsonb) returns boolean
language plpgsql immutable as $$
begin
  if m.role = 'owner' then return true; end if;
  if p_kind = 'private' then return false; end if;
  if p_kind = 'moved' then return p_key = 'all' or p_key = m.user_id::text; end if;
  -- dados do celular: cada um recebe a versão que pode ver
  if p_kind = 'mobile' then
    return case p_key when 'team' then true when 'costs' then public._ponte_can(m, 'custos') else false end;
  end if;
  -- notificações: cada pessoa vê as próprias inscrições; o computador principal vê todas (para mandar)
  if p_kind = 'pushsub' then return split_part(p_key, ':', 1) = m.user_id::text or coalesce((p_sharing ->> '_worker')::boolean, false); end if;
  if p_kind = 'config' and p_key = 'vapid' then return coalesce((p_sharing ->> '_worker')::boolean, false); end if;
  if p_kind = 'batch' or p_kind = 'fin' then return public._ponte_can(m, 'custos'); end if;
  if p_kind = 'purchase' then return public._ponte_can(m, 'compras') or public._ponte_can(m, 'custos'); end if;
  if p_kind = 'product' and coalesce(p_sharing -> 'listings' ->> 'mode', 'all') = 'selected' then
    return coalesce(p_sharing -> 'listings' -> 'ids', '[]'::jsonb) ? p_key;
  end if;
  if p_kind = 'mlacc' and p_sharing ? 'accounts' then
    return coalesce(p_sharing -> 'accounts', '[]'::jsonb) ? p_key;
  end if;
  return true;
end $$;

create or replace function public._ponte_lease_held(p_team uuid, p_name text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.ponte_leases
                  where team_id = p_team and name = p_name and holder = auth.uid() and until > now())
$$;

create or replace function public._ponte_can_write(m public.ponte_members, p_team uuid, p_kind text, p_key text) returns boolean
language plpgsql stable security definer set search_path = public as $$
begin
  if m.role = 'owner' then return true; end if;
  return case p_kind
    when 'product' then public._ponte_can(m, 'links')
    when 'order' then public._ponte_can(m, 'pedidos')
    when 'batch' then public._ponte_can(m, 'custos')
    when 'stock' then public._ponte_can(m, 'estoque') or public._ponte_lease_held(p_team, 'worker')
    when 'mlacc' then public._ponte_lease_held(p_team, 'tok:' || p_key)
    when 'act' then true
    when 'draft' then true
    when 'cmd' then true
    when 'purchase' then public._ponte_can(m, 'compras')
    when 'fin' then public._ponte_can(m, 'custos')
    when 'mobile' then public._ponte_lease_held(p_team, 'worker')
    when 'pushsub' then split_part(p_key, ':', 1) = m.user_id::text or public._ponte_lease_held(p_team, 'worker')
    else false end;
end $$;

-- ---------------------------------------------------------------- equipes e membros
create or replace function public.ponte_whoami() returns jsonb
language plpgsql stable security definer set search_path = public as $$
begin
  if auth.uid() is null then raise exception 'Faça login na equipe novamente.' using errcode = 'P0001'; end if;
  return jsonb_build_object(
    'user_id', auth.uid(),
    'schema', public.ponte_schema_version(),
    'teams', coalesce((
      select jsonb_agg(jsonb_build_object('id', t.id, 'name', t.name, 'role', m.role, 'perms', m.perms, 'member_name', m.name) order by m.joined_at)
        from public.ponte_members m join public.ponte_teams t on t.id = m.team_id
       where m.user_id = auth.uid() and m.active), '[]'::jsonb));
end $$;

create or replace function public.ponte_team_create(p_name text, p_member_name text, p_email text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare t public.ponte_teams;
begin
  if auth.uid() is null then raise exception 'Faça login primeiro.' using errcode = 'P0001'; end if;
  if coalesce(trim(p_name), '') = '' then raise exception 'Dê um nome para a equipe.' using errcode = 'P0001'; end if;
  insert into public.ponte_teams (name, owner) values (trim(p_name), auth.uid()) returning * into t;
  insert into public.ponte_members (team_id, user_id, email, name, role, perms)
       values (t.id, auth.uid(), p_email, coalesce(nullif(trim(p_member_name), ''), 'Dono'), 'owner', '{}'::jsonb);
  return jsonb_build_object('id', t.id, 'name', t.name, 'role', 'owner', 'perms', '{}'::jsonb);
end $$;

create or replace function public.ponte_team_rename(p_team uuid, p_name text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
begin
  if m.role <> 'owner' then raise exception 'Só o dono pode renomear a equipe.' using errcode = 'P0001'; end if;
  update public.ponte_teams set name = trim(p_name) where id = p_team;
  return jsonb_build_object('ok', true);
end $$;

drop function if exists public.ponte_invite_create(uuid, jsonb, text, int);
create or replace function public.ponte_invite_create(p_team uuid, p_perms jsonb, p_label text default null, p_days int default 7, p_role text default 'member') returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        v_code text;
begin
  if m.role <> 'owner' then raise exception 'Só o dono pode convidar pessoas.' using errcode = 'P0001'; end if;
  if coalesce(p_role, 'member') not in ('owner', 'member') then raise exception 'Cargo inválido.' using errcode = 'P0001'; end if;
  v_code := upper(substr(md5(gen_random_uuid()::text || clock_timestamp()::text), 1, 10));
  insert into public.ponte_invites (code, team_id, role, perms, label, created_by, expires_at)
       values (v_code, p_team, coalesce(p_role, 'member'), coalesce(p_perms, '{}'::jsonb), p_label, auth.uid(), now() + make_interval(days => greatest(1, least(coalesce(p_days, 7), 30))));
  return jsonb_build_object('code', v_code, 'expires_at', now() + make_interval(days => greatest(1, least(coalesce(p_days, 7), 30))));
end $$;

create or replace function public.ponte_invites_list(p_team uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
begin
  if m.role <> 'owner' then return '[]'::jsonb; end if;
  return coalesce((select jsonb_agg(jsonb_build_object('code', code, 'label', label, 'role', role, 'perms', perms, 'expires_at', expires_at, 'created_at', created_at) order by created_at desc)
                     from public.ponte_invites where team_id = p_team and used_by is null and expires_at > now()), '[]'::jsonb);
end $$;

create or replace function public.ponte_invite_revoke(p_team uuid, p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
begin
  if m.role <> 'owner' then raise exception 'Só o dono pode cancelar convites.' using errcode = 'P0001'; end if;
  delete from public.ponte_invites where team_id = p_team and code = upper(p_code);
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ponte_invite_accept(p_code text, p_name text, p_email text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare i public.ponte_invites;
        t public.ponte_teams;
begin
  if auth.uid() is null then raise exception 'Faça login primeiro.' using errcode = 'P0001'; end if;
  select * into i from public.ponte_invites where code = upper(trim(p_code)) for update;
  if not found then raise exception 'Convite não encontrado. Confira o código com o dono da equipe.' using errcode = 'P0001'; end if;
  if i.used_by is not null and i.used_by <> auth.uid() then raise exception 'Este convite já foi usado. Peça um novo ao dono da equipe.' using errcode = 'P0001'; end if;
  if i.expires_at < now() then raise exception 'Este convite expirou. Peça um novo ao dono da equipe.' using errcode = 'P0001'; end if;
  select * into t from public.ponte_teams where id = i.team_id;
  if exists (select 1 from public.ponte_members where team_id = i.team_id and user_id = auth.uid() and role = 'owner') then
    raise exception 'Você já é o dono desta equipe.' using errcode = 'P0001';
  end if;
  insert into public.ponte_members (team_id, user_id, email, name, role, perms, active)
       values (i.team_id, auth.uid(), p_email, coalesce(nullif(trim(p_name), ''), case when i.role = 'owner' then 'Dono' else 'Funcionário' end), coalesce(i.role, 'member'), i.perms, true)
  on conflict (team_id, user_id) do update set perms = excluded.perms, active = true, name = excluded.name, email = excluded.email, role = excluded.role;
  update public.ponte_invites set used_by = auth.uid(), used_at = now() where code = i.code;
  return jsonb_build_object('id', t.id, 'name', t.name, 'role', coalesce(i.role, 'member'), 'perms', i.perms);
end $$;

create or replace function public.ponte_members_list(p_team uuid) returns jsonb
language plpgsql stable security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
begin
  return coalesce((select jsonb_agg(jsonb_build_object(
            'user_id', x.user_id, 'name', x.name, 'role', x.role, 'active', x.active,
            'founder', x.user_id = public._ponte_founder(p_team),
            'last_seen', x.last_seen, 'app_version', x.app_version,
            'email', case when m.role = 'owner' or x.user_id = auth.uid() then x.email end,
            'perms', case when m.role = 'owner' or x.user_id = auth.uid() then x.perms end) order by x.role desc, x.joined_at)
          from public.ponte_members x where x.team_id = p_team and (x.active or m.role = 'owner')), '[]'::jsonb);
end $$;

drop function if exists public.ponte_member_update(uuid, uuid, jsonb, boolean, text);
create or replace function public.ponte_member_update(p_team uuid, p_user uuid, p_perms jsonb default null, p_active boolean default null, p_name text default null, p_role text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        x public.ponte_members;
begin
  if p_user = auth.uid() and p_perms is null and p_active is null and p_role is null then
    update public.ponte_members set name = coalesce(nullif(trim(p_name), ''), name) where team_id = p_team and user_id = p_user;
    return jsonb_build_object('ok', true);
  end if;
  if m.role <> 'owner' then raise exception 'Só um dono pode mudar permissões.' using errcode = 'P0001'; end if;
  select * into x from public.ponte_members where team_id = p_team and user_id = p_user;
  if not found then raise exception 'Pessoa não encontrada na equipe.' using errcode = 'P0001'; end if;
  if p_role is not null and p_role not in ('owner', 'member') then raise exception 'Cargo inválido.' using errcode = 'P0001'; end if;
  if p_user = public._ponte_founder(p_team) and (p_active is false or p_role = 'member') then
    raise exception 'Quem criou a equipe é sempre dono e não pode perder o acesso.' using errcode = 'P0001';
  end if;
  if x.role = 'owner' and (p_active is false or p_role = 'member')
     and (select count(*) from public.ponte_members where team_id = p_team and role = 'owner' and active and user_id <> p_user) = 0 then
    raise exception 'A equipe precisa de pelo menos um dono.' using errcode = 'P0001';
  end if;
  update public.ponte_members
     set perms = coalesce(p_perms, perms), active = coalesce(p_active, active), name = coalesce(nullif(trim(p_name), ''), name), role = coalesce(p_role, role)
   where team_id = p_team and user_id = p_user;
  if p_active is false then delete from public.ponte_leases where team_id = p_team and holder = p_user; end if;
  return jsonb_build_object('ok', true);
end $$;

create or replace function public.ponte_member_remove(p_team uuid, p_user uuid) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
begin
  if p_user = public._ponte_founder(p_team) then
    raise exception 'Quem criou a equipe não pode ser removido.' using errcode = 'P0001';
  end if;
  if p_user <> auth.uid() and m.role <> 'owner' then
    raise exception 'Só um dono pode remover pessoas.' using errcode = 'P0001';
  end if;
  if exists (select 1 from public.ponte_members where team_id = p_team and user_id = p_user and role = 'owner')
     and (select count(*) from public.ponte_members where team_id = p_team and role = 'owner' and active and user_id <> p_user) = 0 then
    raise exception 'A equipe precisa de pelo menos um dono.' using errcode = 'P0001';
  end if;
  delete from public.ponte_members where team_id = p_team and user_id = p_user;
  delete from public.ponte_leases where team_id = p_team and holder = p_user;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------- dados compartilhados
create or replace function public._ponte_out(m public.ponte_members, d public.ponte_docs, p_sharing jsonb) returns jsonb
language plpgsql immutable as $$
declare v jsonb;
begin
  if d.deleted or not public._ponte_visible(m, d.kind, d.key, p_sharing) then
    return jsonb_build_object('kind', d.kind, 'key', d.key, 'version', d.version, 'deleted', true);
  end if;
  v := d.data;
  if not public._ponte_can(m, 'custos') and jsonb_typeof(v) = 'object' then
    v := v - public._ponte_cost_keys(d.kind);
  end if;
  return jsonb_build_object('kind', d.kind, 'key', d.key, 'version', d.version, 'deleted', false, 'data', v,
                            'by', d.updated_name, 'at', d.updated_at);
end $$;

create or replace function public.ponte_pull(p_team uuid, p_since bigint default 0, p_client text default null, p_app text default null, p_limit int default 500) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        v_sharing jsonb;
        v_docs jsonb;
        v_max bigint;
        v_count int;
        v_lim int := greatest(10, least(coalesce(p_limit, 500), 1000));
begin
  update public.ponte_members set last_seen = now(), client = coalesce(p_client, client), app_version = coalesce(p_app, app_version)
   where team_id = p_team and user_id = auth.uid();
  select data into v_sharing from public.ponte_docs where team_id = p_team and kind = 'config' and key = 'sharing' and not deleted;
  v_sharing := coalesce(v_sharing, '{}'::jsonb) || jsonb_build_object('_worker', public._ponte_lease_held(p_team, 'worker'));
  with rows as (
    -- os dados do celular são grandes e só servem para o celular: não vão para os computadores
    select * from public.ponte_docs where team_id = p_team and version > coalesce(p_since, 0) and kind <> 'mobile' order by version limit v_lim
  )
  select coalesce(jsonb_agg(public._ponte_out(m, r, coalesce(v_sharing, '{}'::jsonb)) order by r.version), '[]'::jsonb), max(r.version), count(*)
    into v_docs, v_max, v_count from rows r;
  return jsonb_build_object(
    'docs', v_docs,
    'version', coalesce(v_max, p_since, 0),
    'more', v_count >= v_lim,
    'me', jsonb_build_object('role', m.role, 'perms', m.perms, 'name', m.name),
    'team', (select name from public.ponte_teams where id = p_team),
    'sharing', coalesce(v_sharing, '{}'::jsonb) - '_worker',
    'members', (select coalesce(jsonb_agg(jsonb_build_object('user_id', x.user_id, 'name', x.name, 'role', x.role, 'last_seen', x.last_seen, 'founder', x.user_id = public._ponte_founder(p_team))), '[]'::jsonb)
                  from public.ponte_members x where x.team_id = p_team and x.active),
    'leases', (select coalesce(jsonb_object_agg(l.name, jsonb_build_object('holder', l.holder, 'name', l.holder_name, 'client', l.client, 'until', l.until, 'app', l.app)), '{}'::jsonb)
                 from public.ponte_leases l where l.team_id = p_team and l.until > now() and l.name not like 'tok:%'),
    'now', now());
end $$;

-- um documento só (usado pelo app do celular)
drop function if exists public.ponte_get(uuid, text, text);
-- p_since: o celular já tem esta versão; se nada mudou, volta só a confirmação (economiza internet)
create or replace function public.ponte_get(p_team uuid, p_kind text, p_key text, p_since bigint default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        d public.ponte_docs;
        v_sharing jsonb;
begin
  update public.ponte_members set last_seen = now() where team_id = p_team and user_id = auth.uid();
  select data into v_sharing from public.ponte_docs where team_id = p_team and kind = 'config' and key = 'sharing' and not deleted;
  v_sharing := coalesce(v_sharing, '{}'::jsonb) || jsonb_build_object('_worker', public._ponte_lease_held(p_team, 'worker'));
  select * into d from public.ponte_docs where team_id = p_team and kind = p_kind and key = p_key;
  if found and p_since is not null and d.version <= p_since and public._ponte_visible(m, d.kind, d.key, v_sharing) then
    return jsonb_build_object('kind', d.kind, 'key', d.key, 'version', d.version, 'unchanged', true,
             'me', jsonb_build_object('role', m.role, 'perms', m.perms, 'name', m.name),
             'worker', (select jsonb_build_object('name', l.holder_name, 'app', l.app, 'until', l.until) from public.ponte_leases l where l.team_id = p_team and l.name = 'worker' and l.until > now()));
  end if;
  if not found then
    return jsonb_build_object('missing', true, 'me', jsonb_build_object('role', m.role, 'perms', m.perms, 'name', m.name),
                              'worker', (select jsonb_build_object('name', l.holder_name, 'app', l.app, 'until', l.until) from public.ponte_leases l where l.team_id = p_team and l.name = 'worker' and l.until > now()));
  end if;
  return public._ponte_out(m, d, coalesce(v_sharing, '{}'::jsonb)) || jsonb_build_object('me', jsonb_build_object('role', m.role, 'perms', m.perms, 'name', m.name),
           'worker', (select jsonb_build_object('name', l.holder_name, 'app', l.app, 'until', l.until) from public.ponte_leases l where l.team_id = p_team and l.name = 'worker' and l.until > now()));
end $$;

create or replace function public._ponte_write(p_team uuid, p_kind text, p_key text, p_data jsonb, p_patch boolean, p_expected bigint, p_deleted boolean) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        cur public.ponte_docs;
        v_new jsonb;
        v_hidden text[];
        v_ver bigint;
        k text;
begin
  if p_kind is null or p_key is null or length(p_key) > 200 then raise exception 'Documento inválido.' using errcode = 'P0001'; end if;
  if not public._ponte_can_write(m, p_team, p_kind, p_key) then
    raise exception 'Sem permissão para alterar isso. Peça ao dono da equipe.' using errcode = 'P0001';
  end if;
  -- pedidos feitos pelo celular respeitam as permissões de quem pediu
  if p_kind = 'cmd' and m.role <> 'owner' and coalesce(p_data ->> 'status', 'pending') = 'pending' and not coalesce(p_deleted, false) then
    case coalesce(p_data ->> 'type', '')
      when 'answer', 'message', 'messages', 'ai' then
        if not public._ponte_can(m, 'atendimento') then raise exception 'Sem permissão para responder e atender compradores.' using errcode = 'P0001'; end if;
      when 'status', 'meta' then
        if not public._ponte_can(m, 'pedidos') then raise exception 'Sem permissão para mudar pedidos.' using errcode = 'P0001'; end if;
      when 'item_status' then
        if not public._ponte_can(m, 'pausar') then raise exception 'Sem permissão para pausar ou reativar anúncios.' using errcode = 'P0001'; end if;
      when 'item_edit' then
        if not public._ponte_can(m, 'editar') then raise exception 'Sem permissão para editar anúncios.' using errcode = 'P0001'; end if;
      when 'stock' then
        if not public._ponte_can(m, 'estoque') then raise exception 'Sem permissão para mexer no estoque.' using errcode = 'P0001'; end if;
      when 'refresh' then null;
      else raise exception 'Comando não permitido.' using errcode = 'P0001';
    end case;
  end if;
  -- quem pediu (pelo celular) ou se inscreveu nas notificações fica registrado pelo servidor, não pelo aparelho
  if p_kind in ('cmd', 'pushsub') and not coalesce(p_deleted, false) and jsonb_typeof(p_data) = 'object'
     and (p_kind = 'pushsub' or coalesce(p_data ->> 'status', 'pending') = 'pending') then
    p_data := p_data || jsonb_build_object('_uid', auth.uid(), '_role', m.role, '_perms', m.perms, '_name', m.name);
  end if;
  -- uma gravação por vez em cada equipe: as versões ficam sempre em ordem
  perform pg_advisory_xact_lock(hashtext('ponte:' || p_team::text));
  select * into cur from public.ponte_docs where team_id = p_team and kind = p_kind and key = p_key;
  if p_expected is not null and coalesce(cur.version, 0) <> p_expected then
    raise exception 'conflict' using errcode = 'P0001', detail = coalesce(cur.version, 0)::text;
  end if;
  v_hidden := case when public._ponte_can(m, 'custos') then array[]::text[] else public._ponte_cost_keys(p_kind) end;
  if p_deleted then
    v_new := null;
  elsif p_patch then
    v_new := case when cur.deleted or cur.data is null or jsonb_typeof(cur.data) <> 'object' then '{}'::jsonb else cur.data end;
    for k in select jsonb_object_keys(coalesce(p_data, '{}'::jsonb)) loop
      if k = any (v_hidden) then continue; end if;
      if p_data -> k = 'null'::jsonb then v_new := v_new - k; else v_new := v_new || jsonb_build_object(k, p_data -> k); end if;
    end loop;
  else
    v_new := p_data;
    if array_length(v_hidden, 1) > 0 and jsonb_typeof(v_new) = 'object' then
      v_new := v_new - v_hidden;
      if cur.data is not null and jsonb_typeof(cur.data) = 'object' then
        foreach k in array v_hidden loop
          if cur.data ? k then v_new := v_new || jsonb_build_object(k, cur.data -> k); end if;
        end loop;
      end if;
    end if;
  end if;
  v_ver := nextval('public.ponte_seq');
  insert into public.ponte_docs as d (team_id, kind, key, data, deleted, version, updated_by, updated_name, updated_at)
       values (p_team, p_kind, p_key, v_new, coalesce(p_deleted, false), v_ver, auth.uid(), m.name, now())
  on conflict (team_id, kind, key) do update
     set data = excluded.data, deleted = excluded.deleted, version = excluded.version,
         updated_by = excluded.updated_by, updated_name = excluded.updated_name, updated_at = excluded.updated_at;
  if p_kind = 'act' and random() < 0.05 then
    delete from public.ponte_docs where team_id = p_team and kind = 'act' and updated_at < now() - interval '45 days';
  end if;
  return jsonb_build_object('version', v_ver, 'data', case when p_deleted then null
           when array_length(v_hidden, 1) > 0 and jsonb_typeof(v_new) = 'object' then v_new - v_hidden else v_new end);
end $$;

create or replace function public.ponte_put(p_team uuid, p_kind text, p_key text, p_data jsonb, p_expected bigint default null, p_deleted boolean default false) returns jsonb
language sql security definer set search_path = public as $$
  select public._ponte_write(p_team, p_kind, p_key, p_data, false, p_expected, coalesce(p_deleted, false))
$$;

create or replace function public.ponte_patch(p_team uuid, p_kind text, p_key text, p_patch jsonb) returns jsonb
language sql security definer set search_path = public as $$
  select public._ponte_write(p_team, p_kind, p_key, p_patch, true, null, false)
$$;

-- várias gravações de uma vez (cada item: {kind, key, data, patch, deleted})
create or replace function public.ponte_batch(p_team uuid, p_ops jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare op jsonb;
        out jsonb := '[]'::jsonb;
        r jsonb;
begin
  for op in select * from jsonb_array_elements(coalesce(p_ops, '[]'::jsonb)) loop
    begin
      r := public._ponte_write(p_team, op ->> 'kind', op ->> 'key', op -> 'data', coalesce((op ->> 'patch')::boolean, false), null, coalesce((op ->> 'deleted')::boolean, false));
      out := out || jsonb_build_array(jsonb_build_object('kind', op ->> 'kind', 'key', op ->> 'key', 'ok', true, 'version', r -> 'version'));
    exception when others then
      out := out || jsonb_build_array(jsonb_build_object('kind', op ->> 'kind', 'key', op ->> 'key', 'ok', false, 'error', sqlerrm));
    end;
  end loop;
  return out;
end $$;

-- anúncio criado por um funcionário entra na lista de anúncios que a equipe vê
create or replace function public.ponte_share_listings(p_team uuid, p_ids jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        cur public.ponte_docs;
        v_data jsonb;
        v_ids jsonb;
begin
  if not public._ponte_can(m, 'criar') then raise exception 'Sem permissão para criar anúncios.' using errcode = 'P0001'; end if;
  perform pg_advisory_xact_lock(hashtext('ponte:' || p_team::text));
  select * into cur from public.ponte_docs where team_id = p_team and kind = 'config' and key = 'sharing';
  v_data := coalesce(case when cur.deleted then null else cur.data end, '{}'::jsonb);
  if coalesce(v_data -> 'listings' ->> 'mode', 'all') <> 'selected' then return jsonb_build_object('ok', true); end if;
  select coalesce(jsonb_agg(distinct x), '[]'::jsonb) into v_ids
    from (select jsonb_array_elements_text(coalesce(v_data -> 'listings' -> 'ids', '[]'::jsonb)) as x
          union select jsonb_array_elements_text(coalesce(p_ids, '[]'::jsonb))) t;
  v_data := jsonb_set(v_data, '{listings,ids}', v_ids, true);
  update public.ponte_docs set data = v_data, version = nextval('public.ponte_seq'), updated_by = auth.uid(), updated_name = m.name, updated_at = now()
   where team_id = p_team and kind = 'config' and key = 'sharing';
  return jsonb_build_object('ok', true, 'count', jsonb_array_length(v_ids));
end $$;

-- ---------------------------------------------------------------- tarefas que só um computador faz por vez
drop function if exists public.ponte_lease(uuid, text, text, int, boolean);
-- p_takeover: um dono escolheu "usar este computador como principal"
-- p_app: versão do Ponte; uma versão mais nova assume o lugar de uma mais velha (que não sabe fazer tudo)
create or replace function public.ponte_lease(p_team uuid, p_name text, p_client text, p_ttl int default 60, p_force boolean default false, p_app text default null, p_takeover boolean default false) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
        l public.ponte_leases;
        v_ttl int := greatest(5, least(coalesce(p_ttl, 60), 900));
begin
  perform pg_advisory_xact_lock(hashtext('ponte-lease:' || p_team::text || p_name));
  select * into l from public.ponte_leases where team_id = p_team and name = p_name;
  if not found or l.until is null or l.until <= now() or (l.holder = auth.uid() and l.client is not distinct from p_client)
     or (p_name = 'worker' and p_takeover and m.role = 'owner')
     or (p_name = 'worker' and p_app is not null and (l.app is null or public._ponte_ver_lt(l.app, p_app)))
     or (p_force and m.role = 'owner' and p_name = 'worker'
         and not exists (select 1 from public.ponte_members x where x.team_id = p_team and x.user_id = l.holder and x.role = 'owner')) then
    insert into public.ponte_leases (team_id, name, holder, holder_name, client, until, app)
         values (p_team, p_name, auth.uid(), m.name, p_client, now() + make_interval(secs => v_ttl), p_app)
    on conflict (team_id, name) do update set holder = excluded.holder, holder_name = excluded.holder_name, client = excluded.client, until = excluded.until, app = excluded.app;
    return jsonb_build_object('held', true, 'until', now() + make_interval(secs => v_ttl));
  end if;
  return jsonb_build_object('held', false, 'holder', l.holder_name, 'until', l.until, 'app', l.app);
end $$;

create or replace function public.ponte_lease_release(p_team uuid, p_name text, p_client text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare m public.ponte_members := public._ponte_me(p_team);
begin
  delete from public.ponte_leases where team_id = p_team and name = p_name and holder = auth.uid() and client is not distinct from p_client;
  return jsonb_build_object('ok', true);
end $$;

-- ---------------------------------------------------------------- mudança de servidor
-- o dono traz a equipe inteira de outro servidor (mesmo id, mesmos dados); quem já estava na equipe entra com o código que recebeu
create or replace function public.ponte_team_import(p_team uuid, p_name text, p_member_name text, p_email text, p_docs jsonb, p_members jsonb) returns jsonb
language plpgsql security definer set search_path = public as $$
declare d jsonb;
        x jsonb;
        n int := 0;
begin
  if auth.uid() is null then raise exception 'Faça login primeiro.' using errcode = 'P0001'; end if;
  if exists (select 1 from public.ponte_teams where id = p_team) then
    if not exists (select 1 from public.ponte_members where team_id = p_team and user_id = auth.uid() and role = 'owner' and active) then
      raise exception 'Esta equipe já existe neste servidor.' using errcode = 'P0001';
    end if;
  else
    insert into public.ponte_teams (id, name, owner) values (p_team, coalesce(nullif(trim(p_name), ''), 'Equipe'), auth.uid());
    insert into public.ponte_members (team_id, user_id, email, name, role, perms)
         values (p_team, auth.uid(), p_email, coalesce(nullif(trim(p_member_name), ''), 'Dono'), 'owner', '{}'::jsonb);
  end if;
  perform pg_advisory_xact_lock(hashtext('ponte:' || p_team::text));
  for d in select * from jsonb_array_elements(coalesce(p_docs, '[]'::jsonb)) loop
    if (d ->> 'kind') in ('moved', 'mobile', 'cmd', 'pushsub') then continue; end if;
    insert into public.ponte_docs (team_id, kind, key, data, deleted, version, updated_by, updated_name, updated_at)
         values (p_team, d ->> 'kind', d ->> 'key', d -> 'data', coalesce((d ->> 'deleted')::boolean, false), nextval('public.ponte_seq'),
                 auth.uid(), coalesce(d ->> 'by', p_member_name), coalesce((d ->> 'at')::timestamptz, now()))
    on conflict (team_id, kind, key) do update set data = excluded.data, deleted = excluded.deleted, version = excluded.version,
           updated_name = excluded.updated_name, updated_at = excluded.updated_at;
    n := n + 1;
  end loop;
  for x in select * from jsonb_array_elements(coalesce(p_members, '[]'::jsonb)) loop
    if coalesce(x ->> 'email', '') = '' or lower(x ->> 'email') = lower(coalesce(p_email, '')) then continue; end if;
    insert into public.ponte_pending (team_id, email, name, role, perms, token_hash)
         values (p_team, lower(x ->> 'email'), coalesce(x ->> 'name', 'Funcionário'), case when x ->> 'role' = 'owner' then 'owner' else 'member' end,
                 coalesce(x -> 'perms', '{}'::jsonb), x ->> 'token_hash')
    on conflict (team_id, email) do update set name = excluded.name, role = excluded.role, perms = excluded.perms, token_hash = excluded.token_hash;
  end loop;
  return jsonb_build_object('ok', true, 'docs', n, 'id', p_team);
end $$;

create or replace function public.ponte_team_claim(p_team uuid, p_token text, p_name text default null, p_email text default null) returns jsonb
language plpgsql security definer set search_path = public as $$
declare pd public.ponte_pending;
        t public.ponte_teams;
begin
  if auth.uid() is null then raise exception 'Faça login primeiro.' using errcode = 'P0001'; end if;
  select * into pd from public.ponte_pending where team_id = p_team and token_hash = encode(sha256(convert_to(coalesce(p_token, ''), 'UTF8')), 'hex');
  if not found then
    if exists (select 1 from public.ponte_members where team_id = p_team and user_id = auth.uid() and active) then
      select * into t from public.ponte_teams where id = p_team;
      return jsonb_build_object('id', t.id, 'name', t.name);
    end if;
    raise exception 'Este acesso à equipe no servidor novo não vale mais. Peça um convite ao dono.' using errcode = 'P0001';
  end if;
  insert into public.ponte_members (team_id, user_id, email, name, role, perms, active)
       values (p_team, auth.uid(), coalesce(p_email, pd.email), coalesce(nullif(trim(p_name), ''), pd.name), pd.role, pd.perms, true)
  on conflict (team_id, user_id) do update set role = excluded.role, perms = excluded.perms, active = true;
  delete from public.ponte_pending where team_id = p_team and email = pd.email;
  select * into t from public.ponte_teams where id = p_team;
  return jsonb_build_object('id', t.id, 'name', t.name, 'role', pd.role, 'perms', pd.perms);
end $$;

-- ---------------------------------------------------------------- acesso às funções
do $$
declare f record;
begin
  for f in select p.oid::regprocedure as sig, p.proname from pg_proc p join pg_namespace n on n.oid = p.pronamespace
            where n.nspname = 'public' and p.proname like '%ponte%' loop
    execute format('revoke all on function %s from public, anon', f.sig);
    if f.proname like 'ponte\_%' then
      execute format('grant execute on function %s to authenticated', f.sig);
    end if;
  end loop;
end $$;
