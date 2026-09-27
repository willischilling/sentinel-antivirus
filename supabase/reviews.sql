-- Sentinel Antivirus website reviews (stars + comments).
-- Paste this whole file into Supabase: SQL Editor > New query > Run. Safe to run again.
--
-- Visitors (the public "anon" role) can only:
--   * read reviews that aren't hidden (never the network fingerprint column), and the average
--   * add a review with 1-5 stars, a name up to 40 characters and a comment up to 600
-- They can't edit or delete anything. To remove a review, open Table Editor > reviews and
-- set "hidden" to true (or delete the row).

create extension if not exists pgcrypto with schema extensions;

create table if not exists public.reviews (
  id bigint generated always as identity primary key,
  created_at timestamptz not null default now(),
  name text not null check (char_length(name) between 1 and 40),
  stars smallint not null check (stars between 1 and 5),
  comment text check (comment is null or char_length(comment) <= 600),
  hidden boolean not null default false,
  ip_hash text
);

alter table public.reviews enable row level security;

-- Column-level access: the public never sees ip_hash or can set hidden/created_at themselves.
revoke all on public.reviews from anon, authenticated;
grant select (id, created_at, name, stars, comment) on public.reviews to anon, authenticated;
grant insert (name, stars, comment) on public.reviews to anon, authenticated;

drop policy if exists "read visible reviews" on public.reviews;
create policy "read visible reviews" on public.reviews
  for select to anon, authenticated using (hidden = false);

drop policy if exists "add a review" on public.reviews;
create policy "add a review" on public.reviews
  for insert to anon, authenticated with check (hidden = false);

-- Spam limits and a basic language filter, enforced by the database itself.
create or replace function public.reviews_guard() returns trigger
language plpgsql security definer set search_path = public, extensions as $$
declare
  ip text;
  recent int;
begin
  new.name := btrim(regexp_replace(new.name, '\s+', ' ', 'g'));
  new.comment := nullif(btrim(new.comment), '');
  if new.name = '' then new.name := 'Anonymous'; end if;
  if lower(coalesce(new.name, '') || ' ' || coalesce(new.comment, '')) ~
     '(fuck|shit|bitch|cunt|nigg|fag|retard|whore|slut|dick|pussy|cock|porn|nazi|kys)' then
    raise exception 'Please keep reviews friendly.';
  end if;
  if coalesce(new.comment, '') ~* '(https?://|www\.|\.com/|discord\.gg)' then
    raise exception 'Links aren''t allowed in reviews.';
  end if;
  ip := split_part(coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', 'unknown'), ',', 1);
  new.ip_hash := encode(digest(ip || ':sentinel-reviews', 'sha256'), 'hex');
  new.hidden := false;
  new.created_at := now();
  select count(*) into recent from public.reviews
    where ip_hash = new.ip_hash and created_at > now() - interval '1 day';
  if recent >= 3 then
    raise exception 'You''ve already posted a few reviews today. Try again tomorrow.';
  end if;
  select count(*) into recent from public.reviews where created_at > now() - interval '1 minute';
  if recent >= 20 then
    raise exception 'Lots of reviews right now. Try again in a minute.';
  end if;
  return new;
end $$;

drop trigger if exists reviews_guard on public.reviews;
create trigger reviews_guard before insert on public.reviews
  for each row execute function public.reviews_guard();

-- The average and the count of each star, without downloading every review.
create or replace view public.review_stats with (security_invoker = true) as
  select count(*)::int as count,
         coalesce(round(avg(stars)::numeric, 1), 0) as average,
         count(*) filter (where stars = 5)::int as s5,
         count(*) filter (where stars = 4)::int as s4,
         count(*) filter (where stars = 3)::int as s3,
         count(*) filter (where stars = 2)::int as s2,
         count(*) filter (where stars = 1)::int as s1
  from public.reviews where hidden = false;

grant select on public.review_stats to anon, authenticated;
grant select (stars, hidden) on public.reviews to anon, authenticated;
