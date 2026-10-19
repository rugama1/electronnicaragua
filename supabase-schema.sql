-- Run this script in Supabase SQL Editor. It configures shared app data and
-- server-enforced read/write permissions for authenticated accounts.

create table if not exists public.app_records (
  user_id uuid not null,
  collection text not null,
  id text not null,
  data jsonb not null default '{}'::jsonb,
  updated_at timestamptz not null default now(),
  primary key (user_id, collection, id)
);

alter table public.app_records add column if not exists user_id uuid;
alter table public.app_records add column if not exists collection text;
alter table public.app_records add column if not exists id text;
alter table public.app_records add column if not exists data jsonb not null default '{}'::jsonb;
alter table public.app_records add column if not exists updated_at timestamptz not null default now();
create unique index if not exists app_records_user_collection_id_key
  on public.app_records(user_id, collection, id);
alter table public.app_records enable row level security;
revoke all on public.app_records from public, anon;
grant select, insert, update, delete on public.app_records to authenticated;

create table if not exists public.app_account_permissions (
  user_id uuid primary key references auth.users(id) on delete cascade,
  can_read boolean not null default true,
  can_write boolean not null default false,
  updated_at timestamptz not null default now(),
  constraint app_account_permissions_write_requires_read check (not can_write or can_read)
);
alter table public.app_account_permissions enable row level security;
revoke all on public.app_account_permissions from public, anon, authenticated;

create or replace function public.app_is_admin()
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
  select exists (
    select 1 from auth.users
    where id = (select auth.uid())
      and lower(email) = 'mariorugama1@gmail.com'
  );
$$;

create or replace function public.app_current_data_owner()
returns uuid
language plpgsql
stable
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
declare
  owner_id uuid;
  has_read_access boolean;
begin
  if (select auth.uid()) is null then
    return null;
  end if;

  select id into owner_id
  from auth.users
  where lower(email) = 'mariorugama1@gmail.com'
  limit 1;

  if owner_id is null then
    return null;
  end if;

  if owner_id = (select auth.uid()) then
    return owner_id;
  end if;

  select can_read into has_read_access
  from public.app_account_permissions
  where user_id = (select auth.uid());

  if coalesce(has_read_access, false) then
    return owner_id;
  end if;
  return null;
end;
$$;

create or replace function public.app_can_read_data()
returns boolean
language sql
stable
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
  select public.app_current_data_owner() is not null;
$$;

create or replace function public.app_can_write_data()
returns boolean
language plpgsql
stable
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
declare
  has_write_access boolean;
begin
  if public.app_is_admin() then
    return true;
  end if;

  select can_read and can_write into has_write_access
  from public.app_account_permissions
  where user_id = (select auth.uid());
  return coalesce(has_write_access, false);
end;
$$;

create or replace function public.get_app_data_access()
returns table(data_owner_id uuid, can_read boolean, can_write boolean, is_admin boolean)
language plpgsql
stable
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
declare
  owner_id uuid;
  read_access boolean;
  write_access boolean;
  admin_access boolean;
begin
  if (select auth.uid()) is null then
    raise exception 'Authentication required';
  end if;

  select id into owner_id
  from auth.users
  where lower(email) = 'mariorugama1@gmail.com'
  limit 1;

  admin_access := public.app_is_admin();
  if admin_access then
    return query select owner_id, owner_id is not null, owner_id is not null, true;
    return;
  end if;

  select p.can_read, p.can_read and p.can_write
  into read_access, write_access
  from public.app_account_permissions p
  where p.user_id = (select auth.uid());

  read_access := coalesce(read_access, false) and owner_id is not null;
  write_access := coalesce(write_access, false) and read_access;
  return query select case when read_access then owner_id else null end,
                      read_access, write_access, false;
end;
$$;

create or replace function public.admin_list_accounts()
returns table(user_id uuid, email text, created_at timestamptz, can_read boolean, can_write boolean, is_admin boolean)
language plpgsql
stable
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
begin
  if not public.app_is_admin() then
    raise exception 'Only the administrator can list accounts';
  end if;

  return query
  select u.id, u.email::text, u.created_at,
         case when lower(u.email) = 'mariorugama1@gmail.com' then true else coalesce(p.can_read, true) end,
         case when lower(u.email) = 'mariorugama1@gmail.com' then true else coalesce(p.can_write, false) end,
         lower(u.email) = 'mariorugama1@gmail.com'
  from auth.users u
  left join public.app_account_permissions p on p.user_id = u.id
  order by u.created_at, u.email;
end;
$$;

create or replace function public.admin_set_account_access(p_email text, p_can_read boolean, p_can_write boolean)
returns void
language plpgsql
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
declare
  target_user_id uuid;
  normalized_email text := lower(trim(p_email));
begin
  if not public.app_is_admin() then
    raise exception 'Only the administrator can change account access';
  end if;
  if normalized_email is null or normalized_email = '' then
    raise exception 'Provide an account email';
  end if;
  if p_can_read is null or p_can_write is null or (p_can_write and not p_can_read) then
    raise exception 'Write access requires read access';
  end if;

  select id into target_user_id
  from auth.users
  where lower(email) = normalized_email
  limit 1;
  if target_user_id is null then
    raise exception 'No registered account was found for that email';
  end if;
  if public.app_is_admin() and target_user_id = (select auth.uid()) then
    raise exception 'Administrator permissions cannot be changed here';
  end if;

  insert into public.app_account_permissions(user_id, can_read, can_write, updated_at)
  values (target_user_id, p_can_read, p_can_write, now())
  on conflict (user_id) do update
    set can_read = excluded.can_read,
        can_write = excluded.can_write,
        updated_at = excluded.updated_at;
end;
$$;

create or replace function public.app_validate_registration_code()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
begin
  if new.raw_user_meta_data->>'admin_registration_code' is distinct from 'ELECTRON2711' then
    raise exception 'A valid administrator registration code is required';
  end if;
  new.raw_user_meta_data := coalesce(new.raw_user_meta_data, '{}'::jsonb) - 'admin_registration_code';
  return new;
end;
$$;

create or replace function public.app_handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public, auth, pg_temp
set row_security = off
as $$
begin
  if lower(new.email) is distinct from 'mariorugama1@gmail.com' then
    insert into public.app_account_permissions(user_id, can_read, can_write)
    values (new.id, true, false)
    on conflict (user_id) do nothing;
  end if;
  return new;
end;
$$;

drop trigger if exists on_auth_user_validate_registration_code on auth.users;
create trigger on_auth_user_validate_registration_code
  before insert on auth.users
  for each row execute function public.app_validate_registration_code();

drop trigger if exists on_auth_user_created_app_permissions on auth.users;
create trigger on_auth_user_created_app_permissions
  after insert on auth.users
  for each row execute function public.app_handle_new_user();

-- Existing accounts receive read-only access unless the administrator changes it.
insert into public.app_account_permissions(user_id, can_read, can_write)
select id, true, false
from auth.users
where lower(email) is distinct from 'mariorugama1@gmail.com'
on conflict (user_id) do nothing;

-- Replace app_records policies so old policies cannot bypass account permissions.
do $$
declare
  policy_row record;
begin
  for policy_row in
    select policyname from pg_policies
    where schemaname = 'public' and tablename = 'app_records'
  loop
    execute format('drop policy %I on public.app_records', policy_row.policyname);
  end loop;
end;
$$;

create policy app_records_read_owner_or_shared
  on public.app_records for select to authenticated
  using (user_id = public.app_current_data_owner());

create policy app_records_insert_shared_writer
  on public.app_records for insert to authenticated
  with check (user_id = public.app_current_data_owner() and public.app_can_write_data());

create policy app_records_update_shared_writer
  on public.app_records for update to authenticated
  using (user_id = public.app_current_data_owner() and public.app_can_write_data())
  with check (user_id = public.app_current_data_owner() and public.app_can_write_data());

create policy app_records_delete_shared_writer
  on public.app_records for delete to authenticated
  using (user_id = public.app_current_data_owner() and public.app_can_write_data());

insert into storage.buckets(id, name, public)
values ('gestor-inst-media', 'gestor-inst-media', false)
on conflict (id) do update set public = false;

-- Remove prior policies scoped to this app's bucket before applying role checks.
do $$
declare
  policy_row record;
begin
  for policy_row in
    select policyname from pg_policies
    where schemaname = 'storage' and tablename = 'objects'
      and (coalesce(qual, '') || coalesce(with_check, '')) ilike '%gestor-inst-media%'
  loop
    execute format('drop policy %I on storage.objects', policy_row.policyname);
  end loop;
end;
$$;

create policy app_media_read_shared
  on storage.objects for select to authenticated
  using (
    bucket_id = 'gestor-inst-media'
    and (
      name = (select auth.uid())::text || '/profile/avatar.jpg'
      or (
        (storage.foldername(name))[1] = public.app_current_data_owner()::text
        and public.app_can_read_data()
      )
    )
  );

create policy app_media_insert_shared
  on storage.objects for insert to authenticated
  with check (
    bucket_id = 'gestor-inst-media'
    and (
      name = (select auth.uid())::text || '/profile/avatar.jpg'
      or (
        (storage.foldername(name))[1] = public.app_current_data_owner()::text
        and public.app_can_write_data()
      )
    )
  );

create policy app_media_update_shared
  on storage.objects for update to authenticated
  using (
    bucket_id = 'gestor-inst-media'
    and (
      name = (select auth.uid())::text || '/profile/avatar.jpg'
      or (
        (storage.foldername(name))[1] = public.app_current_data_owner()::text
        and public.app_can_write_data()
      )
    )
  )
  with check (
    bucket_id = 'gestor-inst-media'
    and (
      name = (select auth.uid())::text || '/profile/avatar.jpg'
      or (
        (storage.foldername(name))[1] = public.app_current_data_owner()::text
        and public.app_can_write_data()
      )
    )
  );

create policy app_media_delete_shared
  on storage.objects for delete to authenticated
  using (
    bucket_id = 'gestor-inst-media'
    and (
      name = (select auth.uid())::text || '/profile/avatar.jpg'
      or (
        (storage.foldername(name))[1] = public.app_current_data_owner()::text
        and public.app_can_write_data()
      )
    )
  );

revoke all on function public.app_is_admin() from public, anon;
revoke all on function public.app_current_data_owner() from public, anon;
revoke all on function public.app_can_read_data() from public, anon;
revoke all on function public.app_can_write_data() from public, anon;
revoke all on function public.get_app_data_access() from public, anon;
revoke all on function public.admin_list_accounts() from public, anon;
revoke all on function public.admin_set_account_access(text, boolean, boolean) from public, anon;
revoke all on function public.app_validate_registration_code() from public, anon, authenticated;
revoke all on function public.app_handle_new_user() from public, anon, authenticated;
grant execute on function public.app_is_admin() to authenticated;
grant execute on function public.app_current_data_owner() to authenticated;
grant execute on function public.app_can_read_data() to authenticated;
grant execute on function public.app_can_write_data() to authenticated;
grant execute on function public.get_app_data_access() to authenticated;
grant execute on function public.admin_list_accounts() to authenticated;
grant execute on function public.admin_set_account_access(text, boolean, boolean) to authenticated;
