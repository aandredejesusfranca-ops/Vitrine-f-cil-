
-- VITRINE FACIL: estrutura inicial do banco

create extension if not exists pgcrypto;

-- 1. Perfis dos usuarios
create table if not exists public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  role text not null default 'seller'
    check (role in ('seller', 'admin')),
  created_at timestamptz not null default now()
);

-- 2. Lojas
create table if not exists public.stores (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null unique
    references public.profiles(id) on delete cascade,
  name text not null default 'Minha Loja',
  slug text not null unique,
  description text default '',
  color text not null default '#2563eb',
  whatsapp text default '',
  instagram text default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint valid_slug check (
    slug ~ '^[a-z0-9-]{3,40}$'
  )
);

-- 3. Produtos
create table if not exists public.products (
  id uuid primary key default gen_random_uuid(),
  store_id uuid not null
    references public.stores(id) on delete cascade,
  name text not null,
  description text default '',
  price numeric(12,2) not null default 0
    check (price >= 0),
  image_url text default '',
  active boolean not null default true,
  created_at timestamptz not null default now()
);

-- Indices para buscas
create index if not exists products_store_id_idx
  on public.products(store_id);

create index if not exists stores_slug_idx
  on public.stores(slug);

-- Ativar protecao RLS
alter table public.profiles enable row level security;
alter table public.stores enable row level security;
alter table public.products enable row level security;

-- Apagar politicas antigas com os mesmos nomes
drop policy if exists "Ver proprio perfil" on public.profiles;
drop policy if exists "Criar proprio perfil" on public.profiles;
drop policy if exists "Atualizar proprio perfil" on public.profiles;

drop policy if exists "Ler lojas publicas" on public.stores;
drop policy if exists "Criar propria loja" on public.stores;
drop policy if exists "Atualizar propria loja" on public.stores;
drop policy if exists "Apagar propria loja" on public.stores;

drop policy if exists "Ler produtos ativos" on public.products;
drop policy if exists "Ler produtos da propria loja" on public.products;
drop policy if exists "Gerir produtos da propria loja" on public.products;

-- Perfis: cada usuario acessa o proprio perfil
create policy "Ver proprio perfil"
on public.profiles for select
to authenticated
using ((select auth.uid()) = id);

create policy "Criar proprio perfil"
on public.profiles for insert
to authenticated
with check (
  (select auth.uid()) = id
  and role = 'seller'
);

create policy "Atualizar proprio perfil"
on public.profiles for update
to authenticated
using ((select auth.uid()) = id)
with check (
  (select auth.uid()) = id
  and role = 'seller'
);

-- Lojas: leitura publica para exibir vitrines
create policy "Ler lojas publicas"
on public.stores for select
to anon, authenticated
using (true);

create policy "Criar propria loja"
on public.stores for insert
to authenticated
with check (
  owner_id = (select auth.uid())
  and exists (
    select 1 from public.profiles p
    where p.id = (select auth.uid())
      and p.role = 'seller'
  )
);

create policy "Atualizar propria loja"
on public.stores for update
to authenticated
using (owner_id = (select auth.uid()))
with check (owner_id = (select auth.uid()));

create policy "Apagar propria loja"
on public.stores for delete
to authenticated
using (owner_id = (select auth.uid()));

-- Produtos: publico ve somente produtos ativos
create policy "Ler produtos ativos"
on public.products for select
to anon, authenticated
using (
  active = true
  or exists (
    select 1
    from public.stores s
    where s.id = store_id
      and s.owner_id = (select auth.uid())
  )
);

create policy "Ler produtos da propria loja"
on public.products for select
to authenticated
using (
  exists (
    select 1 from public.stores s
    where s.id = store_id
      and s.owner_id = (select auth.uid())
  )
);

create policy "Gerir produtos da propria loja"
on public.products for all
to authenticated
using (
  exists (
    select 1 from public.stores s
    where s.id = store_id
      and s.owner_id = (select auth.uid())
  )
)
with check (
  exists (
    select 1 from public.stores s
    where s.id = store_id
      and s.owner_id = (select auth.uid())
  )
);
