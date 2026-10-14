-- FlicMap: public map, accounts and moderation.
-- Safe to run more than once. Paste into Supabase > SQL Editor > Run.

alter table public.spots
  add column if not exists lat double precision,
  add column if not exists lng double precision,
  add column if not exists thumb_path text,
  add column if not exists tags jsonb not null default '{}'::jsonb,
  add column if not exists hidden boolean not null default false,
  add column if not exists report_count int not null default 0;

alter table public.spots drop constraint if exists spots_note_len;
alter table public.spots add constraint spots_note_len check (note is null or char_length(note) <= 80);
alter table public.spots drop constraint if exists spots_latlng_range;
alter table public.spots add constraint spots_latlng_range check (lat between -90 and 90 and lng between -180 and 180);

create index if not exists spots_lat_lng_idx on public.spots (lat, lng) where is_public and not hidden;
create index if not exists spots_user_idx on public.spots (user_id);

create or replace function public.spots_set_location() returns trigger
language plpgsql set search_path = public, extensions as $$
begin
  if new.lat is not null and new.lng is not null then
    new.location := st_setsrid(st_makepoint(new.lng, new.lat), 4326)::geography;
  end if;
  return new;
end $$;
drop trigger if exists spots_set_location on public.spots;
create trigger spots_set_location before insert or update of lat, lng on public.spots
  for each row execute function public.spots_set_location();

create or replace function public.spots_rate_limit() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  if (select count(*) from public.spots where user_id = new.user_id and created_at > now() - interval '1 day') >= 30 then
    raise exception 'Daily share limit reached';
  end if;
  return new;
end $$;
drop trigger if exists spots_rate_limit on public.spots;
create trigger spots_rate_limit before insert on public.spots
  for each row execute function public.spots_rate_limit();

drop policy if exists "see public spots or your own" on public.spots;
drop policy if exists "see visible public spots or your own" on public.spots;
drop policy if exists "add your own spots" on public.spots;
drop policy if exists "edit your own spots" on public.spots;
drop policy if exists "delete your own spots" on public.spots;
create policy "see visible public spots or your own" on public.spots
  for select using ((is_public and not hidden) or (select auth.uid()) = user_id);
create policy "add your own spots" on public.spots
  for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "edit your own spots" on public.spots
  for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "delete your own spots" on public.spots
  for delete to authenticated using ((select auth.uid()) = user_id);

revoke insert, update, delete on public.spots from anon;
revoke insert, update on public.spots from authenticated;
grant select on public.spots to anon, authenticated;
grant insert (id, photo_path, thumb_path, lat, lng, heading, note, tags, is_public) on public.spots to authenticated;
grant update (photo_path, thumb_path, lat, lng, heading, note, tags, is_public) on public.spots to authenticated;
grant delete on public.spots to authenticated;

create table if not exists public.profiles (
  id uuid primary key references auth.users on delete cascade,
  username text unique check (username is null or username ~ '^[a-z0-9._]{3,20}$'),
  city text check (city is null or char_length(city) <= 40),
  created_at timestamptz not null default now()
);
alter table public.profiles enable row level security;
drop policy if exists "profiles are readable" on public.profiles;
drop policy if exists "create your own profile" on public.profiles;
drop policy if exists "edit your own profile" on public.profiles;
create policy "profiles are readable" on public.profiles for select using (true);
create policy "create your own profile" on public.profiles for insert to authenticated with check ((select auth.uid()) = id);
create policy "edit your own profile" on public.profiles for update to authenticated using ((select auth.uid()) = id) with check ((select auth.uid()) = id);
revoke insert, update, delete on public.profiles from anon;
grant select on public.profiles to anon, authenticated;
grant insert, update on public.profiles to authenticated;

create table if not exists public.spot_reports (
  spot_id uuid not null references public.spots on delete cascade,
  reporter uuid not null default auth.uid() references auth.users on delete cascade,
  reason text not null check (reason in ('private', 'unsafe', 'inappropriate', 'spam')),
  created_at timestamptz not null default now(),
  primary key (spot_id, reporter)
);
create index if not exists spot_reports_reporter_idx on public.spot_reports (reporter);
alter table public.spot_reports enable row level security;
drop policy if exists "report other people's spots" on public.spot_reports;
drop policy if exists "see your own reports" on public.spot_reports;
create policy "report other people's spots" on public.spot_reports for insert to authenticated
  with check ((select auth.uid()) = reporter and not exists (select 1 from public.spots s where s.id = spot_id and s.user_id = (select auth.uid())));
create policy "see your own reports" on public.spot_reports for select to authenticated using ((select auth.uid()) = reporter);
revoke all on public.spot_reports from anon;
revoke update, delete on public.spot_reports from authenticated;
grant select, insert on public.spot_reports to authenticated;

create or replace function public.spot_reports_apply() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update public.spots
     set report_count = report_count + 1,
         hidden = hidden or new.reason = 'private' or report_count + 1 >= 3
   where id = new.spot_id;
  return new;
end $$;
drop trigger if exists spot_reports_apply on public.spot_reports;
create trigger spot_reports_apply after insert on public.spot_reports
  for each row execute function public.spot_reports_apply();
revoke execute on function public.spot_reports_apply() from public, anon, authenticated;
revoke execute on function public.spots_rate_limit() from public, anon, authenticated;

drop policy if exists "upload into your folder" on storage.objects;
drop policy if exists "replace in your folder" on storage.objects;
drop policy if exists "delete from your folder" on storage.objects;
drop policy if exists "read your photos and visible public ones" on storage.objects;
create policy "upload into your folder" on storage.objects for insert to authenticated
  with check (bucket_id = 'spot-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "replace in your folder" on storage.objects for update to authenticated
  using (bucket_id = 'spot-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "delete from your folder" on storage.objects for delete to authenticated
  using (bucket_id = 'spot-photos' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "read your photos and visible public ones" on storage.objects for select
  using (bucket_id = 'spot-photos' and (
    (storage.foldername(name))[1] = (select auth.uid())::text
    or exists (select 1 from public.spots s where (s.photo_path = name or s.thumb_path = name) and s.is_public and not s.hidden)
  ));
update storage.buckets set file_size_limit = 5242880, allowed_mime_types = array['image/jpeg'] where id = 'spot-photos';
