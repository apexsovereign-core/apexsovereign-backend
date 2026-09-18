begin;

alter function apex_private.prevent_ledger_mutation() set search_path = pg_catalog;
alter function public.apex_healthcheck() security invoker;

revoke all on function public.submit_pilot_application(text,jsonb,text,text) from public, anon, authenticated, service_role;
revoke all on function public.admin_approve_pilot_application(uuid,uuid,text) from public, anon, authenticated, service_role;
revoke all on function public.admin_create_payment_intent(uuid,bigint,text,text,text,text) from public, anon, authenticated, service_role;
revoke all on function public.ingest_verified_paypal_event(text,text,text,jsonb,text,text) from public, anon, authenticated, service_role;
revoke all on function public.admin_record_manual_deposit(uuid,text,bigint,text) from public, anon, authenticated, service_role;
revoke all on function public.admin_create_tenant_token_grant(uuid,uuid,text[],bigint) from public, anon, authenticated, service_role;
revoke all on function public.admin_revoke_tenant_token_grant(uuid) from public, anon, authenticated, service_role;
revoke all on function public.is_tenant_token_active(uuid,uuid) from public, anon, authenticated, service_role;
revoke all on function public.apex_healthcheck() from public, anon, authenticated, service_role;

grant execute on function public.submit_pilot_application(text,jsonb,text,text) to service_role;
grant execute on function public.admin_approve_pilot_application(uuid,uuid,text) to authenticated;
grant execute on function public.admin_create_payment_intent(uuid,bigint,text,text,text,text) to authenticated;
grant execute on function public.admin_record_manual_deposit(uuid,text,bigint,text) to authenticated;
grant execute on function public.admin_create_tenant_token_grant(uuid,uuid,text[],bigint) to authenticated;
grant execute on function public.admin_revoke_tenant_token_grant(uuid) to authenticated;
grant execute on function public.ingest_verified_paypal_event(text,text,text,jsonb,text,text) to service_role;
grant execute on function public.is_tenant_token_active(uuid,uuid) to service_role;
grant execute on function public.apex_healthcheck() to service_role;

drop policy if exists paypal_webhook_events_no_client_access on public.paypal_webhook_events;
create policy paypal_webhook_events_no_client_access on public.paypal_webhook_events
for all to anon, authenticated using (false) with check (false);

commit;
