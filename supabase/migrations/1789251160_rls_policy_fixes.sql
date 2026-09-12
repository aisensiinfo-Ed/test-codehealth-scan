-- Migration: Enable RLS and create policies for multi-tenant data isolation
-- Purpose: Fix security findings by implementing row-level security on all
-- tables containing workspace/client data, and establish clear access patterns.

-- Enable RLS on tables that don't have it yet
alter table workspaces enable row level security;
alter table clients enable row level security;
alter table routing_rules enable row level security;
alter table industry_rule_packs enable row level security;

-- ============================================================================
-- WORKSPACES POLICIES
-- ============================================================================

-- Workspace owners can view their own workspace
create policy "workspace_owner_select"
  on workspaces for select
  using (auth.uid() = owner_user_id);

-- Workspace owners can update their own workspace
create policy "workspace_owner_update"
  on workspaces for update
  using (auth.uid() = owner_user_id)
  with check (auth.uid() = owner_user_id);

-- Workspace owners can delete their own workspace
create policy "workspace_owner_delete"
  on workspaces for delete
  using (auth.uid() = owner_user_id);

-- Authenticated users can insert new workspaces (they become the owner)
create policy "workspace_owner_insert"
  on workspaces for insert
  with check (auth.uid() = owner_user_id);

-- ============================================================================
-- CLIENTS POLICIES
-- ============================================================================

-- Users can view clients belonging to their workspaces
create policy "client_select_via_workspace"
  on clients for select
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can insert clients into their workspaces
create policy "client_insert_via_workspace"
  on clients for insert
  with check (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can update clients in their workspaces
create policy "client_update_via_workspace"
  on clients for update
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  )
  with check (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can delete clients from their workspaces
create policy "client_delete_via_workspace"
  on clients for delete
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- ============================================================================
-- ROUTING_RULES POLICIES
-- ============================================================================

-- Users can view routing rules for their workspaces and clients
create policy "routing_rules_select_via_workspace"
  on routing_rules for select
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can insert routing rules into their workspaces and clients
create policy "routing_rules_insert_via_workspace"
  on routing_rules for insert
  with check (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can update routing rules in their workspaces and clients
create policy "routing_rules_update_via_workspace"
  on routing_rules for update
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  )
  with check (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can delete routing rules from their workspaces and clients
create policy "routing_rules_delete_via_workspace"
  on routing_rules for delete
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- ============================================================================
-- INDUSTRY_RULE_PACKS POLICIES
-- ============================================================================

-- All authenticated users can view industry rule packs (shared templates)
create policy "industry_rule_packs_select_authenticated"
  on industry_rule_packs for select
  using (auth.role() = 'authenticated');

-- Only service role (backend) can insert/update/delete rule packs
-- (These are managed by the platform, not by individual agencies)
create policy "industry_rule_packs_insert_service_role"
  on industry_rule_packs for insert
  with check (auth.role() = 'service_role');

create policy "industry_rule_packs_update_service_role"
  on industry_rule_packs for update
  using (auth.role() = 'service_role')
  with check (auth.role() = 'service_role');

create policy "industry_rule_packs_delete_service_role"
  on industry_rule_packs for delete
  using (auth.role() = 'service_role');

-- ============================================================================
-- REQUEST_LOGS POLICIES
-- ============================================================================

-- Users can view request logs for their workspaces and clients
create policy "request_logs_select_via_workspace"
  on request_logs for select
  using (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- Users can insert request logs for their workspaces and clients
create policy "request_logs_insert_via_workspace"
  on request_logs for insert
  with check (
    workspace_id in (
      select id from workspaces where owner_user_id = auth.uid()
    )
  );

-- ============================================================================
-- CLIENT_APPLIED_PACKS POLICIES
-- ============================================================================

-- Users can view applied packs for clients in their workspaces
create policy "client_applied_packs_select_via_workspace"
  on client_applied_packs for select
  using (
    client_id in (
      select id from clients
      where workspace_id in (
        select id from workspaces where owner_user_id = auth.uid()
      )
    )
  );

-- Users can insert applied packs for clients in their workspaces
create policy "client_applied_packs_insert_via_workspace"
  on client_applied_packs for insert
  with check (
    client_id in (
      select id from clients
      where workspace_id in (
        select id from workspaces where owner_user_id = auth.uid()
      )
    )
  );

-- Users can delete applied packs for clients in their workspaces
create policy "client_applied_packs_delete_via_workspace"
  on client_applied_packs for delete
  using (
    client_id in (
      select id from clients
      where workspace_id in (
        select id from workspaces where owner_user_id = auth.uid()
      )
    )
  );
