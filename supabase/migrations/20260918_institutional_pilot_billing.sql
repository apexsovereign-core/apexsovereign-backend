-- Forward-only additive migration for the existing ApexSovereign production database.
-- Existing public.tenants and compute/payment tables are intentionally untouched.
begin;

create extension if not exists pgcrypto;
create schema if not exists apex_private;
revoke all on schema apex_private from public, anon, authenticated;
grant usage on schema apex_private to authenticated;

create table if not exists apex_private.platform_admins (
  user_id uuid primary key references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
revoke all on apex_private.platform_admins from public, anon, authenticated;

create table if not exists apex_private.currency_definitions (
  code text primary key check (code ~ '^[A-Z]{3}$'),
  minor_units smallint not null check (minor_units between 0 and 3)
);
insert into apex_private.currency_definitions(code, minor_units)
values ('USD',2),('PHP',2),('EUR',2),('GBP',2),('JPY',0),('AUD',2),('CAD',2),('SGD',2)
on conflict (code) do nothing;
revoke all on apex_private.currency_definitions from public, anon, authenticated;

create table if not exists public.institutional_tenants (
  id uuid primary key default gen_random_uuid(),
  legal_name text not null check (length(legal_name) between 2 and 200),
  status text not null default 'pilot' check (status in ('pilot','active','suspended','closed')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.tenant_memberships (
  tenant_id uuid not null references public.institutional_tenants(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null check (role in ('owner','admin','billing','operator','viewer')),
  created_at timestamptz not null default now(),
  primary key (tenant_id, user_id)
);
create index if not exists tenant_memberships_user_id_idx on public.tenant_memberships(user_id);

create table if not exists public.pilot_applications (
  id uuid primary key default gen_random_uuid(),
  idempotency_key text not null unique check (length(idempotency_key) between 16 and 128),
  request_sha256 text not null check (request_sha256 ~ '^[0-9a-f]{64}$'),
  applicant_user_id uuid references auth.users(id) on delete set null,
  legal_name text not null check (length(legal_name) between 2 and 200),
  registration_country char(2) not null check (registration_country ~ '^[A-Z]{2}$'),
  registration_number text not null check (length(registration_number) between 2 and 100),
  website text,
  admin_email text not null,
  intended_workload text not null check (length(intended_workload) between 20 and 4000),
  expected_monthly_usd bigint not null check (expected_monthly_usd between 0 and 10000000),
  status text not null default 'pending' check (status in ('pending','approved','rejected')),
  tenant_id uuid unique references public.institutional_tenants(id),
  financially_cleared_at timestamptz,
  approved_at timestamptz,
  approved_by uuid references auth.users(id),
  review_reference text,
  source_ip_hash text check (source_ip_hash is null or source_ip_hash ~ '^[0-9a-f]{64}$'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index if not exists pilot_applications_applicant_idx on public.pilot_applications(applicant_user_id);
create index if not exists pilot_applications_tenant_idx on public.pilot_applications(tenant_id);

create table if not exists public.payment_intents (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.institutional_tenants(id),
  application_id uuid not null references public.pilot_applications(id),
  idempotency_key text not null check (length(idempotency_key) between 16 and 128),
  request_sha256 text not null check (request_sha256 ~ '^[0-9a-f]{64}$'),
  amount_minor bigint not null check (amount_minor > 0),
  currency text not null references apex_private.currency_definitions(code),
  status text not null default 'pending' check (status in ('pending','captured','cancelled','manual_review')),
  paypal_order_id text unique,
  paypal_capture_id text unique,
  created_by uuid not null references auth.users(id),
  captured_at timestamptz,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (application_id, idempotency_key)
);
create index if not exists payment_intents_tenant_idx on public.payment_intents(tenant_id);
create index if not exists payment_intents_application_idx on public.payment_intents(application_id);

create table if not exists public.paypal_webhook_events (
  id bigint generated always as identity primary key,
  transmission_id text not null unique,
  paypal_event_id text not null unique,
  event_type text not null,
  payload jsonb not null,
  payload_sha256 text not null check (payload_sha256 ~ '^[0-9a-f]{64}$'),
  verification_method text not null default 'paypal_local_certificate',
  processing_state text not null default 'received' check (processing_state in ('received','processed','ignored','manual_review')),
  processing_detail text,
  payment_intent_id uuid references public.payment_intents(id),
  received_at timestamptz not null default now(),
  processed_at timestamptz
);
create index if not exists paypal_events_received_idx on public.paypal_webhook_events(received_at desc);
create index if not exists paypal_events_state_idx on public.paypal_webhook_events(processing_state, received_at);

create table if not exists public.ledger_accounts (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.institutional_tenants(id),
  code text not null check (code in ('paypal_clearing','manual_clearing','customer_credit')),
  currency text not null references apex_private.currency_definitions(code),
  normal_balance text not null check (normal_balance in ('debit','credit')),
  created_at timestamptz not null default now(),
  unique (tenant_id, code, currency)
);
create index if not exists ledger_accounts_tenant_idx on public.ledger_accounts(tenant_id);

create table if not exists public.ledger_transactions (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.institutional_tenants(id),
  external_reference text not null unique,
  kind text not null check (kind in ('paypal_capture','manual_deposit','adjustment','reversal')),
  currency text not null references apex_private.currency_definitions(code),
  description text not null,
  posted_at timestamptz not null default now(),
  created_by uuid references auth.users(id)
);
create index if not exists ledger_transactions_tenant_posted_idx on public.ledger_transactions(tenant_id, posted_at desc);

create table if not exists public.ledger_entries (
  id bigint generated always as identity primary key,
  transaction_id uuid not null references public.ledger_transactions(id),
  tenant_id uuid not null references public.institutional_tenants(id),
  account_id uuid not null references public.ledger_accounts(id),
  amount_minor bigint not null check (amount_minor <> 0),
  currency text not null references apex_private.currency_definitions(code),
  created_at timestamptz not null default now()
);
create index if not exists ledger_entries_tenant_idx on public.ledger_entries(tenant_id);
create index if not exists ledger_entries_transaction_idx on public.ledger_entries(transaction_id);
create index if not exists ledger_entries_account_idx on public.ledger_entries(account_id);

create table if not exists public.manual_deposits (
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.institutional_tenants(id),
  application_id uuid not null references public.pilot_applications(id),
  external_reference text not null unique,
  amount_minor bigint not null check (amount_minor > 0),
  currency text not null references apex_private.currency_definitions(code),
  cleared_by uuid not null references auth.users(id),
  cleared_at timestamptz not null default now()
);
create index if not exists manual_deposits_tenant_idx on public.manual_deposits(tenant_id);

create table if not exists public.tenant_token_grants (
  jti uuid primary key,
  tenant_id uuid not null references public.institutional_tenants(id),
  scopes text[] not null check (cardinality(scopes) between 1 and 3),
  issued_by uuid not null references auth.users(id),
  issued_at timestamptz not null default now(),
  expires_at timestamptz not null,
  revoked_at timestamptz,
  check (expires_at > issued_at)
);
create index if not exists tenant_token_grants_tenant_idx on public.tenant_token_grants(tenant_id, issued_at desc);

create table if not exists public.audit_events (
  id bigint generated always as identity primary key,
  tenant_id uuid references public.institutional_tenants(id),
  actor_user_id uuid references auth.users(id),
  action text not null,
  object_type text not null,
  object_id text not null,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists audit_events_tenant_created_idx on public.audit_events(tenant_id, created_at desc);

create or replace function apex_private.is_platform_admin()
returns boolean language sql stable security definer set search_path = apex_private, pg_temp as $$
  select exists (select 1 from apex_private.platform_admins where user_id = (select auth.uid()));
$$;

create or replace function apex_private.has_tenant_role(p_tenant_id uuid, p_roles text[] default null)
returns boolean language sql stable security definer set search_path = public, pg_temp as $$
  select exists (
    select 1 from public.tenant_memberships
    where tenant_id = p_tenant_id
      and user_id = (select auth.uid())
      and (p_roles is null or role = any(p_roles))
  );
$$;

grant execute on function apex_private.is_platform_admin() to authenticated;
grant execute on function apex_private.has_tenant_role(uuid,text[]) to authenticated;

alter table public.institutional_tenants enable row level security;
alter table public.tenant_memberships enable row level security;
alter table public.pilot_applications enable row level security;
alter table public.payment_intents enable row level security;
alter table public.paypal_webhook_events enable row level security;
alter table public.ledger_accounts enable row level security;
alter table public.ledger_transactions enable row level security;
alter table public.ledger_entries enable row level security;
alter table public.manual_deposits enable row level security;
alter table public.tenant_token_grants enable row level security;
alter table public.audit_events enable row level security;

revoke all on public.institutional_tenants, public.tenant_memberships, public.pilot_applications,
  public.payment_intents, public.paypal_webhook_events, public.ledger_accounts,
  public.ledger_transactions, public.ledger_entries, public.manual_deposits,
  public.tenant_token_grants, public.audit_events from anon, authenticated;

grant select on public.institutional_tenants, public.tenant_memberships, public.pilot_applications,
  public.payment_intents, public.ledger_accounts, public.ledger_transactions,
  public.ledger_entries, public.manual_deposits, public.tenant_token_grants,
  public.audit_events to authenticated;

create policy tenant_member_read on public.institutional_tenants for select to authenticated
using ((select apex_private.has_tenant_role(id, null)) or (select apex_private.is_platform_admin()));

create policy membership_member_read on public.tenant_memberships for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, null)) or (select apex_private.is_platform_admin()));

create policy application_owner_or_admin_read on public.pilot_applications for select to authenticated
using (
  applicant_user_id = (select auth.uid())
  or (tenant_id is not null and (select apex_private.has_tenant_role(tenant_id, array['owner','admin','billing'])))
  or (select apex_private.is_platform_admin())
);

create policy payment_intent_tenant_read on public.payment_intents for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, array['owner','admin','billing'])) or (select apex_private.is_platform_admin()));

create policy ledger_account_tenant_read on public.ledger_accounts for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, null)) or (select apex_private.is_platform_admin()));

create policy ledger_transaction_tenant_read on public.ledger_transactions for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, null)) or (select apex_private.is_platform_admin()));

create policy ledger_entry_tenant_read on public.ledger_entries for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, null)) or (select apex_private.is_platform_admin()));

create policy manual_deposit_tenant_read on public.manual_deposits for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, array['owner','admin','billing'])) or (select apex_private.is_platform_admin()));

create policy token_grant_tenant_admin_read on public.tenant_token_grants for select to authenticated
using ((select apex_private.has_tenant_role(tenant_id, array['owner','admin'])) or (select apex_private.is_platform_admin()));

create policy audit_tenant_admin_read on public.audit_events for select to authenticated
using ((tenant_id is not null and (select apex_private.has_tenant_role(tenant_id, array['owner','admin']))) or (select apex_private.is_platform_admin()));

create policy paypal_webhook_events_no_client_access on public.paypal_webhook_events
for all to anon, authenticated using (false) with check (false);

create or replace function apex_private.amount_to_minor(p_value text, p_currency text)
returns bigint language plpgsql stable security definer set search_path = apex_private, pg_temp as $$
declare v numeric; units int; scaled numeric;
begin
  select minor_units into units from apex_private.currency_definitions where code = upper(p_currency);
  if units is null then raise exception 'unsupported currency' using errcode='22023'; end if;
  v := p_value::numeric;
  scaled := v * power(10::numeric, units);
  if v <= 0 or scaled <> trunc(scaled) or scaled > 9223372036854775807 then
    raise exception 'invalid monetary amount' using errcode='22023';
  end if;
  return scaled::bigint;
exception when invalid_text_representation or numeric_value_out_of_range then
  raise exception 'invalid monetary amount' using errcode='22023';
end $$;

create or replace function apex_private.assert_platform_admin()
returns void language plpgsql stable security definer set search_path = apex_private, pg_temp as $$
begin
  if (select auth.uid()) is null or not apex_private.is_platform_admin() then
    raise exception 'platform administrator required' using errcode='42501';
  end if;
end $$;

create or replace function apex_private.prevent_ledger_mutation()
returns trigger language plpgsql as $$
begin
  raise exception 'ledger rows are append-only; post a compensating transaction';
end $$;

create or replace function apex_private.validate_ledger_entry()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare account_row public.ledger_accounts%rowtype; transaction_row public.ledger_transactions%rowtype;
begin
  select * into account_row from public.ledger_accounts where id=new.account_id;
  select * into transaction_row from public.ledger_transactions where id=new.transaction_id;
  if account_row.tenant_id<>new.tenant_id or transaction_row.tenant_id<>new.tenant_id
     or account_row.currency<>new.currency or transaction_row.currency<>new.currency then
    raise exception 'ledger entry tenant/currency mismatch' using errcode='23514';
  end if;
  return new;
end $$;

create or replace function apex_private.assert_ledger_transaction_balanced()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare target_id uuid;
begin
  target_id := coalesce(new.transaction_id,old.transaction_id);
  if coalesce((select sum(amount_minor) from public.ledger_entries where transaction_id=target_id),0)<>0 then
    raise exception 'unbalanced ledger transaction' using errcode='23514';
  end if;
  return null;
end $$;

create or replace function apex_private.assert_ledger_transaction_complete()
returns trigger language plpgsql security definer set search_path = public, pg_temp as $$
declare entry_count bigint; entry_total bigint;
begin
  select count(*),coalesce(sum(amount_minor),0) into entry_count,entry_total
    from public.ledger_entries where transaction_id=new.id;
  if entry_count<2 or entry_total<>0 then
    raise exception 'ledger transaction must contain at least two balanced entries' using errcode='23514';
  end if;
  return null;
end $$;

drop trigger if exists ledger_transactions_immutable on public.ledger_transactions;
create trigger ledger_transactions_immutable before update or delete on public.ledger_transactions
for each row execute function apex_private.prevent_ledger_mutation();
drop trigger if exists ledger_entries_immutable on public.ledger_entries;
create trigger ledger_entries_immutable before update or delete on public.ledger_entries
for each row execute function apex_private.prevent_ledger_mutation();
drop trigger if exists ledger_entries_validate on public.ledger_entries;
create trigger ledger_entries_validate before insert on public.ledger_entries
for each row execute function apex_private.validate_ledger_entry();
drop trigger if exists ledger_entries_balanced on public.ledger_entries;
create constraint trigger ledger_entries_balanced after insert or update or delete on public.ledger_entries
deferrable initially deferred for each row execute function apex_private.assert_ledger_transaction_balanced();
drop trigger if exists ledger_transaction_complete on public.ledger_transactions;
create constraint trigger ledger_transaction_complete after insert on public.ledger_transactions
deferrable initially deferred for each row execute function apex_private.assert_ledger_transaction_complete();

create or replace function apex_private.ensure_ledger_accounts(p_tenant_id uuid, p_currency text, p_clearing_code text)
returns table(clearing_account_id uuid, credit_account_id uuid)
language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
begin
  if p_clearing_code not in ('paypal_clearing','manual_clearing') then raise exception 'invalid clearing account'; end if;
  insert into public.ledger_accounts(tenant_id,code,currency,normal_balance)
  values (p_tenant_id,p_clearing_code,p_currency,'debit'),(p_tenant_id,'customer_credit',p_currency,'credit')
  on conflict (tenant_id,code,currency) do nothing;
  return query
    select c.id, l.id from public.ledger_accounts c join public.ledger_accounts l
      on l.tenant_id=c.tenant_id and l.currency=c.currency
    where c.tenant_id=p_tenant_id and c.currency=p_currency and c.code=p_clearing_code and l.code='customer_credit';
end $$;

create or replace function public.submit_pilot_application(
  p_idempotency_key text, p_application jsonb, p_request_sha256 text, p_source_ip_hash text
) returns jsonb language plpgsql security definer set search_path = public, pg_temp as $$
declare a public.pilot_applications%rowtype;
begin
  if length(p_idempotency_key) not between 16 and 128 or p_request_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid idempotency input' using errcode='22023';
  end if;
  insert into public.pilot_applications(
    idempotency_key,request_sha256,applicant_user_id,legal_name,registration_country,
    registration_number,website,admin_email,intended_workload,expected_monthly_usd,source_ip_hash
  ) values (
    p_idempotency_key,p_request_sha256,(select auth.uid()),p_application->>'legal_name',
    upper(p_application->>'registration_country'),p_application->>'registration_number',
    nullif(p_application->>'website',''),lower(p_application->>'admin_email'),
    p_application->>'intended_workload',(p_application->>'expected_monthly_usd')::bigint,p_source_ip_hash
  ) on conflict (idempotency_key) do nothing;
  select * into a from public.pilot_applications where idempotency_key=p_idempotency_key;
  if a.request_sha256 <> p_request_sha256 then
    raise exception 'idempotency key reused with different payload' using errcode='23505';
  end if;
  return jsonb_build_object('id',a.id,'status',a.status,'created_at',a.created_at);
end $$;

create or replace function public.admin_approve_pilot_application(
  p_application_id uuid, p_owner_user_id uuid, p_review_reference text
) returns jsonb language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
declare a public.pilot_applications%rowtype; t uuid;
begin
  perform apex_private.assert_platform_admin();
  select * into a from public.pilot_applications where id=p_application_id for update;
  if not found then raise exception 'application not found' using errcode='P0002'; end if;
  if a.status='rejected' then raise exception 'rejected application cannot be approved' using errcode='23514'; end if;
  if a.tenant_id is null then
    insert into public.institutional_tenants(legal_name,status) values(a.legal_name,'pilot') returning id into t;
  else t := a.tenant_id;
  end if;
  insert into public.tenant_memberships(tenant_id,user_id,role) values(t,p_owner_user_id,'owner')
  on conflict (tenant_id,user_id) do update set role='owner';
  update public.pilot_applications set status='approved',tenant_id=t,approved_at=coalesce(approved_at,now()),
    approved_by=(select auth.uid()),review_reference=p_review_reference,updated_at=now() where id=p_application_id returning * into a;
  insert into public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  values(t,(select auth.uid()),'pilot.approved','pilot_application',a.id::text,jsonb_build_object('review_reference',p_review_reference));
  return jsonb_build_object('application_id',a.id,'tenant_id',t,'status',a.status,'financially_cleared',a.financially_cleared_at is not null);
end $$;

create or replace function public.admin_create_payment_intent(
  p_application_id uuid, p_amount_minor bigint, p_currency text, p_paypal_order_id text,
  p_idempotency_key text, p_request_sha256 text
) returns jsonb language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
declare a public.pilot_applications%rowtype; i public.payment_intents%rowtype;
begin
  perform apex_private.assert_platform_admin();
  if length(p_idempotency_key) not between 16 and 128 or p_request_sha256 !~ '^[0-9a-f]{64}$' then
    raise exception 'invalid idempotency input' using errcode='22023';
  end if;
  select * into a from public.pilot_applications where id=p_application_id and status='approved' and tenant_id is not null for update;
  if not found then raise exception 'approved application required' using errcode='23514'; end if;
  if p_amount_minor <= 0 or not exists(select 1 from apex_private.currency_definitions where code=upper(p_currency)) then
    raise exception 'invalid amount or currency' using errcode='22023';
  end if;
  insert into public.payment_intents(tenant_id,application_id,idempotency_key,request_sha256,amount_minor,currency,paypal_order_id,created_by)
  values(a.tenant_id,a.id,p_idempotency_key,p_request_sha256,p_amount_minor,upper(p_currency),p_paypal_order_id,(select auth.uid()))
  on conflict (application_id,idempotency_key) do nothing;
  select * into i from public.payment_intents where application_id=a.id and idempotency_key=p_idempotency_key;
  if i.request_sha256<>p_request_sha256 then
    raise exception 'idempotency key reused with different payload' using errcode='23505';
  end if;
  insert into public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  select a.tenant_id,(select auth.uid()),'payment_intent.created','payment_intent',i.id::text,jsonb_build_object('amount_minor',i.amount_minor,'currency',i.currency)
  where not exists(select 1 from public.audit_events where action='payment_intent.created' and object_type='payment_intent' and object_id=i.id::text);
  return jsonb_build_object('payment_intent_id',i.id,'paypal_custom_id',i.id,'amount_minor',i.amount_minor,'currency',i.currency);
end $$;

create or replace function public.ingest_verified_paypal_event(
  p_transmission_id text, p_paypal_event_id text, p_event_type text, p_payload jsonb,
  p_payload_sha256 text, p_expected_merchant_id text
) returns jsonb language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
declare
  e public.paypal_webhook_events%rowtype; i public.payment_intents%rowtype;
  ref_text text; ref_id uuid; order_id text; capture_id text; merchant_id text; event_currency text;
  amount_minor bigint; tx_id uuid; clearing_id uuid; credit_id uuid;
begin
  insert into public.paypal_webhook_events(transmission_id,paypal_event_id,event_type,payload,payload_sha256)
  values(p_transmission_id,p_paypal_event_id,p_event_type,p_payload,p_payload_sha256)
  on conflict do nothing;
  if not found then
    select * into e from public.paypal_webhook_events
      where transmission_id=p_transmission_id or paypal_event_id=p_paypal_event_id order by id limit 1;
    if e.transmission_id<>p_transmission_id or e.paypal_event_id<>p_paypal_event_id or e.payload_sha256<>p_payload_sha256 then
      return jsonb_build_object('duplicate',true,'state','collision_rejected');
    end if;
    return jsonb_build_object('duplicate',true,'state',e.processing_state);
  end if;
  select * into e from public.paypal_webhook_events where paypal_event_id=p_paypal_event_id for update;

  if p_event_type <> 'PAYMENT.CAPTURE.COMPLETED' then
    update public.paypal_webhook_events set processing_state=case when p_event_type in ('PAYMENT.CAPTURE.DENIED','PAYMENT.CAPTURE.REFUNDED','PAYMENT.CAPTURE.REVERSED','CUSTOMER.DISPUTE.CREATED') then 'manual_review' else 'ignored' end,
      processing_detail='non-credit event',processed_at=now() where id=e.id returning * into e;
    return jsonb_build_object('duplicate',false,'state',e.processing_state);
  end if;

  if coalesce(p_payload#>>'{resource,status}','') <> 'COMPLETED' then
    update public.paypal_webhook_events set processing_state='manual_review',processing_detail='capture status is not COMPLETED',processed_at=now() where id=e.id;
    return jsonb_build_object('duplicate',false,'state','manual_review');
  end if;
  merchant_id := p_payload#>>'{resource,payee,merchant_id}';
  if merchant_id is null or merchant_id <> p_expected_merchant_id then
    update public.paypal_webhook_events set processing_state='manual_review',processing_detail='merchant mismatch',processed_at=now() where id=e.id;
    return jsonb_build_object('duplicate',false,'state','manual_review');
  end if;
  ref_text := coalesce(p_payload#>>'{resource,custom_id}',p_payload#>>'{resource,invoice_id}');
  order_id := p_payload#>>'{resource,supplementary_data,related_ids,order_id}';
  begin ref_id := ref_text::uuid;
  exception when invalid_text_representation or null_value_not_allowed then ref_id := null;
  end;
  event_currency := upper(coalesce(p_payload#>>'{resource,amount,currency_code}',''));
  begin amount_minor := apex_private.amount_to_minor(p_payload#>>'{resource,amount,value}',event_currency);
  exception when others then
    update public.paypal_webhook_events set processing_state='manual_review',processing_detail='invalid amount or currency',processed_at=now() where id=e.id;
    return jsonb_build_object('duplicate',false,'state','manual_review');
  end;
  capture_id := p_payload#>>'{resource,id}';
  select * into i from public.payment_intents
    where (ref_id is not null and id=ref_id and (paypal_order_id is null or order_id is null or paypal_order_id=order_id))
       or (ref_id is null and order_id is not null and paypal_order_id=order_id)
    for update;
  if not found or i.status<>'pending' or i.amount_minor<>amount_minor or i.currency<>event_currency or capture_id is null then
    update public.paypal_webhook_events set processing_state='manual_review',processing_detail='payment intent mismatch or unavailable',payment_intent_id=case when found then i.id else null end,processed_at=now() where id=e.id;
    return jsonb_build_object('duplicate',false,'state','manual_review');
  end if;

  select clearing_account_id,credit_account_id into clearing_id,credit_id from apex_private.ensure_ledger_accounts(i.tenant_id,i.currency,'paypal_clearing');
  begin
    insert into public.ledger_transactions(tenant_id,external_reference,kind,currency,description)
    values(i.tenant_id,'paypal:capture:'||capture_id,'paypal_capture',i.currency,'Verified PayPal capture') returning id into tx_id;
  exception when unique_violation then
    update public.paypal_webhook_events set processing_state='manual_review',processing_detail='duplicate financial reference',payment_intent_id=i.id,processed_at=now() where id=e.id;
    return jsonb_build_object('duplicate',true,'state','manual_review');
  end;
  insert into public.ledger_entries(transaction_id,tenant_id,account_id,amount_minor,currency)
  values(tx_id,i.tenant_id,clearing_id,amount_minor,i.currency),(tx_id,i.tenant_id,credit_id,-amount_minor,i.currency);
  if (select sum(le.amount_minor) from public.ledger_entries le where le.transaction_id=tx_id) <> 0 then raise exception 'unbalanced ledger transaction'; end if;
  update public.payment_intents set status='captured',paypal_capture_id=capture_id,captured_at=now(),updated_at=now() where id=i.id;
  update public.pilot_applications set financially_cleared_at=coalesce(financially_cleared_at,now()),updated_at=now() where id=i.application_id;
  update public.paypal_webhook_events set processing_state='processed',processing_detail='capture posted',payment_intent_id=i.id,processed_at=now() where id=e.id;
  insert into public.audit_events(tenant_id,action,object_type,object_id,metadata)
  values(i.tenant_id,'paypal.capture_posted','payment_intent',i.id::text,jsonb_build_object('capture_id',capture_id,'amount_minor',amount_minor,'currency',i.currency));
  return jsonb_build_object('duplicate',false,'state','processed','payment_intent_id',i.id);
end $$;

create or replace function public.admin_record_manual_deposit(
  p_application_id uuid, p_external_reference text, p_amount_minor bigint, p_currency text
) returns jsonb language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
declare a public.pilot_applications%rowtype; d public.manual_deposits%rowtype; tx_id uuid; clearing_id uuid; credit_id uuid;
begin
  perform apex_private.assert_platform_admin();
  select * into a from public.pilot_applications where id=p_application_id and status='approved' and tenant_id is not null for update;
  if not found then raise exception 'approved application required' using errcode='23514'; end if;
  if p_amount_minor<=0 or not exists(select 1 from apex_private.currency_definitions where code=upper(p_currency)) then raise exception 'invalid amount or currency' using errcode='22023'; end if;
  insert into public.manual_deposits(tenant_id,application_id,external_reference,amount_minor,currency,cleared_by)
  values(a.tenant_id,a.id,p_external_reference,p_amount_minor,upper(p_currency),(select auth.uid())) returning * into d;
  select clearing_account_id,credit_account_id into clearing_id,credit_id from apex_private.ensure_ledger_accounts(a.tenant_id,d.currency,'manual_clearing');
  insert into public.ledger_transactions(tenant_id,external_reference,kind,currency,description,created_by)
  values(a.tenant_id,'manual:'||p_external_reference,'manual_deposit',d.currency,'Manually cleared institutional deposit',(select auth.uid())) returning id into tx_id;
  insert into public.ledger_entries(transaction_id,tenant_id,account_id,amount_minor,currency)
  values(tx_id,a.tenant_id,clearing_id,d.amount_minor,d.currency),(tx_id,a.tenant_id,credit_id,-d.amount_minor,d.currency);
  update public.pilot_applications set financially_cleared_at=coalesce(financially_cleared_at,now()),updated_at=now() where id=a.id;
  insert into public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  values(a.tenant_id,(select auth.uid()),'manual_deposit.cleared','manual_deposit',d.id::text,jsonb_build_object('external_reference',p_external_reference,'amount_minor',d.amount_minor,'currency',d.currency));
  return jsonb_build_object('deposit_id',d.id,'tenant_id',a.tenant_id,'status','cleared');
end $$;

create or replace function public.admin_create_tenant_token_grant(
  p_application_id uuid, p_jti uuid, p_scopes text[], p_expires_at bigint
) returns jsonb language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
declare a public.pilot_applications%rowtype; expiry timestamptz;
begin
  perform apex_private.assert_platform_admin();
  if p_scopes is null or cardinality(p_scopes) not between 1 and 3 or not (p_scopes <@ array['compute:submit','compute:read','billing:read']) then
    raise exception 'invalid scopes' using errcode='22023';
  end if;
  expiry := to_timestamp(p_expires_at);
  if expiry <= now() or expiry > now()+interval '1 hour' then raise exception 'invalid token expiry' using errcode='22023'; end if;
  select * into a from public.pilot_applications where id=p_application_id and status='approved' and tenant_id is not null and financially_cleared_at is not null for update;
  if not found then raise exception 'approved and financially cleared application required' using errcode='23514'; end if;
  insert into public.tenant_token_grants(jti,tenant_id,scopes,issued_by,expires_at)
  values(p_jti,a.tenant_id,p_scopes,(select auth.uid()),expiry);
  insert into public.audit_events(tenant_id,actor_user_id,action,object_type,object_id,metadata)
  values(a.tenant_id,(select auth.uid()),'tenant_token.created','tenant_token_grant',p_jti::text,jsonb_build_object('scopes',p_scopes,'expires_at',expiry));
  return jsonb_build_object('tenant_id',a.tenant_id,'jti',p_jti,'expires_at',extract(epoch from expiry)::bigint);
end $$;

create or replace function public.admin_revoke_tenant_token_grant(p_jti uuid)
returns void language plpgsql security definer set search_path = public, apex_private, pg_temp as $$
declare g public.tenant_token_grants%rowtype;
begin
  perform apex_private.assert_platform_admin();
  update public.tenant_token_grants set revoked_at=coalesce(revoked_at,now()) where jti=p_jti returning * into g;
  if found then insert into public.audit_events(tenant_id,actor_user_id,action,object_type,object_id)
    values(g.tenant_id,(select auth.uid()),'tenant_token.revoked','tenant_token_grant',g.jti::text); end if;
end $$;

create or replace function public.is_tenant_token_active(p_jti uuid, p_tenant_id uuid)
returns boolean language sql stable security definer set search_path = public, pg_temp as $$
  select exists(select 1 from public.tenant_token_grants where jti=p_jti and tenant_id=p_tenant_id and revoked_at is null and expires_at>now());
$$;

revoke execute on function public.submit_pilot_application(text,jsonb,text,text) from public, anon, authenticated, service_role;
revoke execute on function public.admin_approve_pilot_application(uuid,uuid,text) from public, anon, authenticated, service_role;
revoke execute on function public.admin_create_payment_intent(uuid,bigint,text,text,text,text) from public, anon, authenticated, service_role;
revoke execute on function public.ingest_verified_paypal_event(text,text,text,jsonb,text,text) from public, anon, authenticated, service_role;
revoke execute on function public.admin_record_manual_deposit(uuid,text,bigint,text) from public, anon, authenticated, service_role;
revoke execute on function public.admin_create_tenant_token_grant(uuid,uuid,text[],bigint) from public, anon, authenticated, service_role;
revoke execute on function public.admin_revoke_tenant_token_grant(uuid) from public, anon, authenticated, service_role;
revoke execute on function public.is_tenant_token_active(uuid,uuid) from public, anon, authenticated, service_role;

revoke all on function apex_private.is_platform_admin() from public, anon, authenticated;
revoke all on function apex_private.has_tenant_role(uuid,text[]) from public, anon, authenticated;
revoke all on function apex_private.amount_to_minor(text,text) from public, anon, authenticated;
revoke all on function apex_private.assert_platform_admin() from public, anon, authenticated;
revoke all on function apex_private.prevent_ledger_mutation() from public, anon, authenticated;
revoke all on function apex_private.validate_ledger_entry() from public, anon, authenticated;
revoke all on function apex_private.assert_ledger_transaction_balanced() from public, anon, authenticated;
revoke all on function apex_private.assert_ledger_transaction_complete() from public, anon, authenticated;
revoke all on function apex_private.ensure_ledger_accounts(uuid,text,text) from public, anon, authenticated;

grant execute on function apex_private.is_platform_admin() to authenticated;
grant execute on function apex_private.has_tenant_role(uuid,text[]) to authenticated;
grant execute on function public.submit_pilot_application(text,jsonb,text,text) to service_role;
grant execute on function public.admin_approve_pilot_application(uuid,uuid,text) to authenticated;
grant execute on function public.admin_create_payment_intent(uuid,bigint,text,text,text,text) to authenticated;
grant execute on function public.admin_record_manual_deposit(uuid,text,bigint,text) to authenticated;
grant execute on function public.admin_create_tenant_token_grant(uuid,uuid,text[],bigint) to authenticated;
grant execute on function public.admin_revoke_tenant_token_grant(uuid) to authenticated;
grant execute on function public.ingest_verified_paypal_event(text,text,text,jsonb,text,text) to service_role;
grant execute on function public.is_tenant_token_active(uuid,uuid) to service_role;

create or replace function public.apex_healthcheck()
returns boolean language sql stable security invoker set search_path = pg_catalog as $$
  select true;
$$;
revoke execute on function public.apex_healthcheck() from public, anon, authenticated, service_role;
grant execute on function public.apex_healthcheck() to service_role;

create or replace view public.tenant_credit_balances with (security_invoker=true) as
select a.tenant_id,a.currency,coalesce(-sum(e.amount_minor),0)::bigint as available_credit_minor
from public.ledger_accounts a left join public.ledger_entries e on e.account_id=a.id
where a.code='customer_credit' group by a.tenant_id,a.currency;
revoke all on public.tenant_credit_balances from anon, authenticated;
grant select on public.tenant_credit_balances to authenticated;

commit;
