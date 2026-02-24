const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');

const {
  parseArgs,
  resolveRollbackVersion,
  shouldRunStatementsInTransaction
} = require('../scripts/migrate-baseline');

test('parseArgs defaults to up mode without version', () => {
  const parsed = parseArgs([]);
  assert.deepEqual(parsed, {
    mode: 'up',
    version: null
  });
});

test('parseArgs resolves down mode and version from argv', () => {
  const parsed = parseArgs(['--down', '--version=0007_sample']);
  assert.deepEqual(parsed, {
    mode: 'down',
    version: '0007_sample'
  });
});

test('resolveRollbackVersion returns empty value when no migrations are applied', () => {
  const resolved = resolveRollbackVersion({
    existingRows: [],
    targetVersion: null
  });
  assert.equal(resolved, '');
});

test('resolveRollbackVersion defaults to latest applied version', () => {
  const resolved = resolveRollbackVersion({
    existingRows: [
      { id: 1, version: '0004_auth_session_domain_tenant_context' },
      { id: 2, version: '0005_auth_domain_tenant_membership' },
      { id: 3, version: '0006_auth_platform_permission_snapshot' },
      { id: 4, version: '0007_auth_platform_role_facts' }
    ],
    targetVersion: null
  });
  assert.equal(resolved, '0007_auth_platform_role_facts');
});

test('resolveRollbackVersion accepts explicit latest applied version', () => {
  const resolved = resolveRollbackVersion({
    existingRows: [
      { id: 10, version: '0008_latest' },
      { id: 9, version: '0007_prev' }
    ],
    targetVersion: '0008_latest'
  });
  assert.equal(resolved, '0008_latest');
});

test('resolveRollbackVersion rejects explicit non-latest applied version', () => {
  assert.throws(
    () =>
      resolveRollbackVersion({
        existingRows: [
          { id: 1, version: '0004_auth_session_domain_tenant_context' },
          { id: 2, version: '0005_auth_domain_tenant_membership' }
        ],
        targetVersion: '0004_auth_session_domain_tenant_context'
      }),
    /Only latest applied migration can be rolled back/
  );
});

test('resolveRollbackVersion rejects version that is not currently applied', () => {
  assert.throws(
    () =>
      resolveRollbackVersion({
        existingRows: [
          { id: 1, version: '0004_auth_session_domain_tenant_context' },
          { id: 2, version: '0005_auth_domain_tenant_membership' }
        ],
        targetVersion: '9999_not_applied'
      }),
    /is not currently applied/
  );
});

test('0005 migration defines tenant permission columns required by runtime preflight', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0005_auth_domain_tenant_membership.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /can_view_user_management/i);
  assert.match(sql, /can_operate_user_management/i);
  assert.match(sql, /can_view_organization_management/i);
  assert.match(sql, /can_operate_organization_management/i);
});

test('0006 migration defines guarded platform permission snapshot DDL on auth_user_domain_access', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0006_auth_platform_permission_snapshot.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /table_name = 'auth_user_domain_access'/i);
  assert.match(sql, /column_name = 'can_view_user_management'/i);
  assert.match(sql, /column_name = 'can_operate_user_management'/i);
  assert.match(sql, /column_name = 'can_view_organization_management'/i);
  assert.match(sql, /column_name = 'can_operate_organization_management'/i);
  assert.match(sql, /PREPARE migration_stmt FROM @ddl_sql/i);
  assert.match(sql, /ADD COLUMN can_view_user_management/i);
  assert.match(sql, /ADD COLUMN can_operate_user_management/i);
  assert.match(sql, /ADD COLUMN can_view_organization_management/i);
  assert.match(sql, /ADD COLUMN can_operate_organization_management/i);
});

test('0006 down migration defines guarded rollback DDL for platform permission snapshot', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0006_auth_platform_permission_snapshot.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /table_name = 'auth_user_domain_access'/i);
  assert.match(sql, /column_name = 'can_operate_organization_management'/i);
  assert.match(sql, /column_name = 'can_view_organization_management'/i);
  assert.match(sql, /column_name = 'can_operate_user_management'/i);
  assert.match(sql, /column_name = 'can_view_user_management'/i);
  assert.match(sql, /PREPARE migration_stmt FROM @ddl_sql/i);
  assert.match(sql, /DROP COLUMN can_operate_organization_management/i);
  assert.match(sql, /DROP COLUMN can_view_organization_management/i);
  assert.match(sql, /DROP COLUMN can_operate_user_management/i);
  assert.match(sql, /DROP COLUMN can_view_user_management/i);
});

test('0007 migration defines platform role fact table and reserved legacy snapshot backfill', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0007_auth_platform_role_facts.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS auth_user_platform_roles/i);
  assert.match(sql, /role_id/i);
  assert.match(sql, /can_view_user_management/i);
  assert.match(sql, /can_operate_user_management/i);
  assert.match(sql, /can_view_organization_management/i);
  assert.match(sql, /can_operate_organization_management/i);
  assert.match(sql, /INSERT INTO auth_user_platform_roles/i);
  assert.match(sql, /__migr_0007_legacy_snapshot__/i);
  assert.match(sql, /FROM auth_user_domain_access/i);
  assert.match(sql, /domain = 'platform'/i);
  assert.match(sql, /status IN \('active', 'enabled'\)/i);
  assert.match(sql, /ON DUPLICATE KEY UPDATE/i);
  assert.doesNotMatch(sql, /status\s*=\s*VALUES\s*\(\s*status\s*\)/i);
});

test('0008 migration defines org bootstrap tables and owner relationship constraints', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0008_platform_org_bootstrap.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS orgs/i);
  assert.match(sql, /owner_user_id/i);
  assert.match(sql, /UNIQUE KEY uk_orgs_name/i);
  assert.match(sql, /FOREIGN KEY .*owner_user_id.*REFERENCES users \(id\)/is);
  assert.match(sql, /CREATE TABLE IF NOT EXISTS memberships/i);
  assert.match(sql, /UNIQUE KEY uk_memberships_org_user/i);
  assert.match(sql, /FOREIGN KEY .*org_id.*REFERENCES orgs \(id\)/is);
  assert.match(sql, /FOREIGN KEY .*user_id.*REFERENCES users \(id\)/is);
});

test('0008 down migration drops memberships and orgs tables in dependency-safe order', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0008_platform_org_bootstrap.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  const dropMembershipsIndex = sql.search(/DROP TABLE IF EXISTS memberships/i);
  const dropOrgsIndex = sql.search(/DROP TABLE IF EXISTS orgs/i);

  assert.ok(dropMembershipsIndex >= 0);
  assert.ok(dropOrgsIndex >= 0);
  assert.ok(
    dropMembershipsIndex < dropOrgsIndex,
    'expected memberships to be dropped before orgs'
  );
});

test('0009 migration defines platform role catalog table, unique code guard, and sys_admin seed', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0009_platform_role_catalog.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS platform_role_catalog/i);
  assert.match(sql, /code_normalized/i);
  assert.match(sql, /UNIQUE KEY uk_platform_role_catalog_code_normalized/i);
  assert.match(sql, /scope ENUM\('platform', 'tenant'\)/i);
  assert.match(sql, /is_system/i);
  assert.match(sql, /INSERT INTO platform_role_catalog/i);
  assert.match(sql, /'sys_admin'/i);
  assert.match(sql, /ON DUPLICATE KEY UPDATE/i);
});

test('0009 down migration drops platform role catalog table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0009_platform_role_catalog.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP TABLE IF EXISTS platform_role_catalog/i);
});

test('0010 migration defines platform role permission grants table and sys_admin seed', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0010_platform_role_permission_grants.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS platform_role_permission_grants/i);
  assert.match(sql, /PRIMARY KEY \(role_id, permission_code\)/i);
  assert.match(sql, /FOREIGN KEY \(role_id\) REFERENCES platform_role_catalog \(role_id\)/i);
  assert.match(sql, /INSERT INTO platform_role_permission_grants/i);
  assert.match(sql, /'sys_admin'/i);
  assert.match(sql, /ON DUPLICATE KEY UPDATE/i);
});

test('0011 migration adds role_id leading index for auth_user_platform_roles lookup', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0011_auth_user_platform_roles_role_id_index.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /ALTER TABLE auth_user_platform_roles/i);
  assert.match(sql, /ADD KEY idx_auth_user_platform_roles_role_id_user_id/i);
});

test('0011 down migration drops role_id leading index for auth_user_platform_roles lookup', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0011_auth_user_platform_roles_role_id_index.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /ALTER TABLE auth_user_platform_roles/i);
  assert.match(sql, /DROP INDEX idx_auth_user_platform_roles_role_id_user_id/i);
});

test('0013 migration adds tenant isolation fields and scoped unique key for role catalog', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0013_platform_role_catalog_tenant_isolation.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /table_name = 'platform_role_catalog'/i);
  assert.match(sql, /column_name = 'tenant_id'/i);
  assert.match(sql, /ADD COLUMN tenant_id VARCHAR\(64\) NOT NULL DEFAULT ''/i);
  assert.match(sql, /DROP INDEX uk_platform_role_catalog_code_normalized/i);
  assert.match(sql, /uk_platform_role_catalog_scope_tenant_code_normalized/i);
  assert.match(
    sql,
    /ADD UNIQUE KEY uk_platform_role_catalog_scope_tenant_code_normalized \(scope, tenant_id, code_normalized\)/i
  );
});

test('0013 down migration drops tenant scoped role catalog indexes and tenant_id column', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0013_platform_role_catalog_tenant_isolation.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP INDEX uk_platform_role_catalog_scope_tenant_code_normalized/i);
  assert.match(sql, /DROP INDEX idx_platform_role_catalog_scope_tenant_status/i);
  assert.match(sql, /DELETE FROM platform_role_catalog\s+WHERE scope = 'tenant'/i);
  assert.match(sql, /ADD UNIQUE KEY uk_platform_role_catalog_code_normalized/i);
  assert.match(sql, /DROP COLUMN IF EXISTS tenant_id/i);
});

test('0014 migration defines tenant role permission grants table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0014_tenant_role_permission_grants.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS tenant_role_permission_grants/i);
  assert.match(sql, /PRIMARY KEY \(role_id, permission_code\)/i);
  assert.match(sql, /FOREIGN KEY \(role_id\) REFERENCES platform_role_catalog \(role_id\)/i);
  assert.match(sql, /idx_tenant_role_permission_grants_permission_code/i);
});

test('0015 migration defines tenant membership role bindings table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0015_auth_tenant_membership_roles.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS auth_tenant_membership_roles/i);
  assert.match(sql, /PRIMARY KEY \(membership_id, role_id\)/i);
  assert.match(sql, /FOREIGN KEY \(membership_id\) REFERENCES auth_user_tenants \(membership_id\)/i);
  assert.match(sql, /FOREIGN KEY \(role_id\) REFERENCES platform_role_catalog \(role_id\)/i);
  assert.match(sql, /ON DELETE CASCADE/i);
});

test('0016 migration adds tenant member profile columns with information_schema guards', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0016_auth_tenant_member_profile_fields.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /table_name = 'auth_user_tenants'/i);
  assert.match(sql, /column_name = 'display_name'/i);
  assert.match(sql, /column_name = 'department_name'/i);
  assert.match(sql, /ADD COLUMN display_name VARCHAR\(64\) NULL/i);
  assert.match(sql, /ADD COLUMN department_name VARCHAR\(128\) NULL/i);
  assert.match(sql, /PREPARE auth_user_tenants_display_name_stmt/i);
  assert.match(sql, /PREPARE auth_user_tenants_department_name_stmt/i);
});

test('0016 down migration drops tenant member profile columns', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0016_auth_tenant_member_profile_fields.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /ALTER TABLE auth_user_tenants/i);
  assert.match(sql, /DROP COLUMN IF EXISTS department_name/i);
  assert.match(sql, /DROP COLUMN IF EXISTS display_name/i);
});

test('0017 migration migrates legacy tenant_owner bindings to tenant-scoped takeover role ids and cleans stale legacy rows', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0017_owner_transfer_takeover_role_cleanup.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_membership_targets/i);
  assert.match(sql, /DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_tenants/i);
  assert.match(sql, /DROP TEMPORARY TABLE IF EXISTS tmp_owner_takeover_legacy_memberships/i);
  assert.match(sql, /tmp_owner_takeover_legacy_memberships/i);
  assert.match(sql, /tmp_owner_takeover_legacy_tenants/i);
  assert.match(sql, /CONCAT\('sys_admin__', SUBSTRING\(SHA2\(legacy\.tenant_id, 256\), 1, 24\)\)/i);
  assert.match(sql, /SIGNAL SQLSTATE '45000'/i);
  assert.match(sql, /owner_takeover_tenant_code_collision_count/i);
  assert.match(sql, /tenant code collision detected/i);
  assert.match(sql, /INSERT INTO platform_role_catalog/i);
  assert.match(sql, /INSERT IGNORE INTO tenant_role_permission_grants/i);
  assert.match(sql, /LOWER\(TRIM\(permission_code\)\) IN/i);
  assert.match(sql, /tenant\.organization_management\.view/i);
  assert.match(sql, /tenant\.organization_management\.operate/i);
  assert.match(sql, /INSERT IGNORE INTO auth_tenant_membership_roles/i);
  assert.match(sql, /DELETE mr\s+FROM auth_tenant_membership_roles/i);
  assert.match(sql, /UPDATE auth_user_tenants ut/i);
  assert.match(sql, /DELETE FROM platform_role_catalog/i);
  assert.match(sql, /role_id = 'tenant_owner'/i);
});

test('0017 down migration is an explicit no-op rollback marker', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0017_owner_transfer_takeover_role_cleanup.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /rollback is intentionally no-op/i);
  assert.match(sql, /SELECT/i);
});

test('0018 migration defines audit_events table with required query indexes', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0018_audit_events.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS audit_events/i);
  assert.match(sql, /event_id/i);
  assert.match(sql, /domain/i);
  assert.match(sql, /tenant_id/i);
  assert.match(sql, /request_id/i);
  assert.match(sql, /traceparent/i);
  assert.match(sql, /event_type/i);
  assert.match(sql, /actor_user_id/i);
  assert.match(sql, /actor_session_id/i);
  assert.match(sql, /target_type/i);
  assert.match(sql, /target_id/i);
  assert.match(sql, /result/i);
  assert.match(sql, /before_state/i);
  assert.match(sql, /after_state/i);
  assert.match(sql, /metadata/i);
  assert.match(sql, /occurred_at/i);
  assert.match(sql, /idx_audit_events_domain_occurred_at/i);
  assert.match(sql, /idx_audit_events_request_id/i);
  assert.match(sql, /idx_audit_events_tenant_occurred_at/i);
});

test('0018 down migration drops audit_events table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0018_audit_events.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP TABLE IF EXISTS audit_events/i);
});

test('0019 migration defines system_sensitive_configs table and seeds sys_admin permissions', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0019_system_sensitive_configs.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS system_sensitive_configs/i);
  assert.match(sql, /config_key/i);
  assert.match(sql, /encrypted_value/i);
  assert.match(sql, /version/i);
  assert.match(sql, /updated_by_user_id/i);
  assert.match(sql, /updated_at/i);
  assert.match(sql, /status/i);
  assert.match(sql, /CHECK \(config_key IN \('auth\.default_password'\)\)/i);
  assert.match(sql, /INSERT INTO platform_role_permission_grants/i);
  assert.match(sql, /platform\.system_config\.view/i);
  assert.match(sql, /platform\.system_config\.operate/i);
});

test('0019 down migration drops system_sensitive_configs and removes sys_admin seeded permissions', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0019_system_sensitive_configs.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DELETE FROM platform_role_permission_grants/i);
  assert.match(sql, /platform\.system_config\.view/i);
  assert.match(sql, /platform\.system_config\.operate/i);
  assert.match(sql, /DROP TABLE IF EXISTS system_sensitive_configs/i);
});

test('0020 migration normalizes and prunes role permission grants to final authorization set', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0020_permission_grants_final_authorization_cleanup.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TEMPORARY TABLE tmp_platform_role_permission_grants_final_authorization/i);
  assert.match(sql, /LOWER\(TRIM\(grants\.permission_code\)\)/i);
  assert.match(sql, /GROUP_CONCAT\(\s*NULLIF\(TRIM\(grants\.created_by_user_id\), ''\)/i);
  assert.match(sql, /GROUP_CONCAT\(\s*NULLIF\(TRIM\(grants\.updated_by_user_id\), ''\)/i);
  assert.match(sql, /SUBSTRING_INDEX\(/i);
  assert.match(sql, /catalog\.scope = 'platform'/i);
  assert.match(sql, /platform\.system_config\.view/i);
  assert.match(sql, /platform\.system_config\.operate/i);
  assert.match(sql, /DELETE\s+grants\s+FROM\s+platform_role_permission_grants/i);
  assert.match(
    sql,
    /LOWER\(TRIM\(grants\.permission_code\)\)\s+NOT IN\s*\(\s*'platform\.user_management\.view'[\s\S]*'platform\.system_config\.operate'\s*\)/i
  );
  const binaryNormalizedComparisonMatches = sql.match(
    /BINARY\s+grants\.permission_code\s*<>\s*BINARY\s+LOWER\(TRIM\(grants\.permission_code\)\)/ig
  ) || [];
  assert.equal(binaryNormalizedComparisonMatches.length, 2);
  assert.match(sql, /INSERT INTO platform_role_permission_grants/i);
  assert.match(sql, /ON DUPLICATE KEY UPDATE/i);
  assert.match(sql, /CREATE TEMPORARY TABLE tmp_tenant_role_permission_grants_final_authorization/i);
  assert.match(sql, /catalog\.scope = 'tenant'/i);
  assert.match(sql, /tenant\.user_management\.view/i);
  assert.match(sql, /tenant\.user_management\.operate/i);
  assert.match(sql, /tenant\.organization_management\.view/i);
  assert.match(sql, /tenant\.organization_management\.operate/i);
  assert.match(sql, /DELETE\s+grants\s+FROM\s+tenant_role_permission_grants/i);
  assert.match(
    sql,
    /LOWER\(TRIM\(grants\.permission_code\)\)\s+NOT IN\s*\(\s*'tenant\.user_management\.view'[\s\S]*'tenant\.organization_management\.operate'\s*\)/i
  );
  assert.match(sql, /INSERT INTO tenant_role_permission_grants/i);
});

test('0020 down migration is an explicit no-op rollback marker', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0020_permission_grants_final_authorization_cleanup.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /rollback is intentionally no-op/i);
  assert.match(sql, /SELECT/i);
});

test('0021 migration defines platform integration catalog table and lifecycle governance indexes', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0021_platform_integration_catalog.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS platform_integration_catalog/i);
  assert.match(sql, /integration_id VARCHAR\(64\) NOT NULL/i);
  assert.match(sql, /code_normalized VARCHAR\(64\) NOT NULL/i);
  assert.match(sql, /direction ENUM\('inbound', 'outbound', 'bidirectional'\)/i);
  assert.match(sql, /auth_mode VARCHAR\(64\) NOT NULL/i);
  assert.match(sql, /retry_policy JSON NULL/i);
  assert.match(sql, /idempotency_policy JSON NULL/i);
  assert.match(sql, /lifecycle_status ENUM\('draft', 'active', 'paused', 'retired'\)/i);
  assert.match(sql, /UNIQUE KEY uk_platform_integration_catalog_code_normalized/i);
  assert.match(sql, /idx_platform_integration_catalog_lifecycle_status/i);
  assert.match(sql, /idx_platform_integration_catalog_direction_protocol/i);
});

test('0021 down migration drops platform integration catalog table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0021_platform_integration_catalog.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP TABLE IF EXISTS platform_integration_catalog/i);
});

test('0022 migration defines integration contract version and compatibility check tables', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0022_platform_integration_contract_versions.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS platform_integration_contract_versions/i);
  assert.match(sql, /contract_type ENUM\('openapi', 'event'\)/i);
  assert.match(sql, /contract_version VARCHAR\(64\) NOT NULL/i);
  assert.match(sql, /status ENUM\('candidate', 'active', 'deprecated', 'retired'\)/i);
  assert.match(
    sql,
    /UNIQUE KEY uk_platform_integration_contract_version\s*\(\s*integration_id,\s*contract_type,\s*contract_version\s*\)/i
  );
  assert.match(
    sql,
    /KEY idx_platform_integration_contract_active_lookup\s*\(\s*integration_id,\s*contract_type,\s*status,\s*updated_at,\s*contract_id\s*\)/i
  );

  assert.match(
    sql,
    /CREATE TABLE IF NOT EXISTS platform_integration_contract_compatibility_checks/i
  );
  assert.match(sql, /evaluation_result ENUM\('compatible', 'incompatible'\)/i);
  assert.match(sql, /breaking_change_count INT UNSIGNED NOT NULL DEFAULT 0/i);
  assert.match(sql, /request_id VARCHAR\(128\) NOT NULL/i);
  assert.match(
    sql,
    /KEY idx_platform_integration_contract_checks_lookup\s*\(\s*integration_id,\s*contract_type,\s*baseline_version,\s*candidate_version,\s*checked_at,\s*check_id\s*\)/i
  );
});

test('0022 down migration drops compatibility checks before contract versions', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0022_platform_integration_contract_versions.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  const dropChecksIndex = sql.search(
    /DROP TABLE IF EXISTS platform_integration_contract_compatibility_checks/i
  );
  const dropVersionsIndex = sql.search(
    /DROP TABLE IF EXISTS platform_integration_contract_versions/i
  );

  assert.ok(dropChecksIndex >= 0);
  assert.ok(dropVersionsIndex >= 0);
  assert.ok(
    dropChecksIndex < dropVersionsIndex,
    'expected compatibility checks table to be dropped before contract versions table'
  );
});

test('0023 migration defines integration retry recovery queue table with dedup and scheduling indexes', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0023_platform_integration_retry_recovery.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS platform_integration_retry_recovery_queue/i);
  assert.match(sql, /recovery_id VARCHAR\(64\) NOT NULL/i);
  assert.match(sql, /contract_type ENUM\('openapi', 'event'\) NOT NULL/i);
  assert.match(sql, /request_id VARCHAR\(128\) NOT NULL/i);
  assert.match(sql, /idempotency_key VARCHAR\(128\) NOT NULL DEFAULT ''/i);
  assert.match(sql, /attempt_count INT UNSIGNED NOT NULL DEFAULT 0/i);
  assert.match(sql, /max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 5/i);
  assert.match(
    sql,
    /status ENUM\('pending', 'retrying', 'succeeded', 'failed', 'dlq', 'replayed'\)\s+NOT NULL DEFAULT 'pending'/i
  );
  assert.match(
    sql,
    /UNIQUE KEY uk_platform_integration_recovery_dedup\s*\(\s*integration_id,\s*contract_type,\s*contract_version,\s*request_id,\s*idempotency_key\s*\)/i
  );
  assert.match(
    sql,
    /KEY idx_platform_integration_recovery_status_next_retry_at\s*\(\s*status,\s*next_retry_at\s*\)/i
  );
  assert.match(
    sql,
    /KEY idx_platform_integration_recovery_integration_status\s*\(\s*integration_id,\s*status\s*\)/i
  );
  assert.match(sql, /KEY idx_platform_integration_recovery_request_id\s*\(\s*request_id\s*\)/i);
});

test('0023 down migration drops platform integration retry recovery queue table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0023_platform_integration_retry_recovery.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP TABLE IF EXISTS platform_integration_retry_recovery_queue/i);
});

test('0024 migration defines integration freeze control table with single active window constraint', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0024_platform_integration_freeze_control.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /CREATE TABLE IF NOT EXISTS platform_integration_freeze_control/i);
  assert.match(sql, /freeze_id VARCHAR\(64\) NOT NULL/i);
  assert.match(sql, /status ENUM\('active', 'released'\) NOT NULL DEFAULT 'active'/i);
  assert.match(sql, /freeze_reason VARCHAR\(256\) NOT NULL/i);
  assert.match(sql, /rollback_reason VARCHAR\(256\) NULL/i);
  assert.match(sql, /frozen_at TIMESTAMP\(3\) NOT NULL DEFAULT CURRENT_TIMESTAMP\(3\)/i);
  assert.match(sql, /released_at TIMESTAMP\(3\) NULL/i);
  assert.match(sql, /request_id VARCHAR\(128\) NOT NULL/i);
  assert.match(sql, /traceparent VARCHAR\(128\) NULL/i);
  assert.match(
    sql,
    /active_window_slot TINYINT\s+GENERATED ALWAYS AS \(CASE WHEN status = 'active' THEN 1 ELSE NULL END\) STORED/i
  );
  assert.match(
    sql,
    /UNIQUE KEY uk_platform_integration_freeze_active_window\s*\(\s*active_window_slot\s*\)/i
  );
  assert.match(
    sql,
    /KEY idx_platform_integration_freeze_status_frozen_at\s*\(\s*status,\s*frozen_at\s*\)/i
  );
  assert.match(sql, /KEY idx_platform_integration_freeze_request_id\s*\(\s*request_id\s*\)/i);
});

test('0024 down migration drops integration freeze control table', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0024_platform_integration_freeze_control.down.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /DROP TABLE IF EXISTS platform_integration_freeze_control/i);
});

test('0004 migration uses information_schema guards for auth_sessions context columns', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0004_auth_session_domain_tenant_context.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /table_name = 'auth_sessions'/i);
  assert.match(sql, /column_name = 'entry_domain'/i);
  assert.match(sql, /column_name = 'active_tenant_id'/i);
  assert.doesNotMatch(sql, /ADD COLUMN IF NOT EXISTS/i);
});

test('0005 migration backfills tenant domain access rows from tenant memberships', () => {
  const sqlPath = resolve(
    __dirname,
    '..',
    'migrations',
    '0005_auth_domain_tenant_membership.sql'
  );
  const sql = readFileSync(sqlPath, 'utf8');

  assert.match(sql, /INSERT INTO auth_user_domain_access/i);
  assert.match(sql, /'tenant'/i);
  assert.match(sql, /FROM auth_user_tenants/i);
});

test('shouldRunStatementsInTransaction disables transaction mode when DDL statements are present', () => {
  const ddlStatements = [
    'CREATE TABLE sample_table (id INT PRIMARY KEY)',
    "INSERT INTO sample_table (id) VALUES (1)"
  ];
  const dmlStatements = [
    "UPDATE users SET status = 'active' WHERE id = 'u-1'",
    'DELETE FROM users WHERE id = \"u-2\"'
  ];

  assert.equal(shouldRunStatementsInTransaction(ddlStatements), false);
  assert.equal(shouldRunStatementsInTransaction(dmlStatements), true);
});
