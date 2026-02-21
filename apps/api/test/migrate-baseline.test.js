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

  assert.match(sql, /can_view_member_admin/i);
  assert.match(sql, /can_operate_member_admin/i);
  assert.match(sql, /can_view_billing/i);
  assert.match(sql, /can_operate_billing/i);
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
  assert.match(sql, /column_name = 'can_view_member_admin'/i);
  assert.match(sql, /column_name = 'can_operate_member_admin'/i);
  assert.match(sql, /column_name = 'can_view_billing'/i);
  assert.match(sql, /column_name = 'can_operate_billing'/i);
  assert.match(sql, /PREPARE migration_stmt FROM @ddl_sql/i);
  assert.match(sql, /ADD COLUMN can_view_member_admin/i);
  assert.match(sql, /ADD COLUMN can_operate_member_admin/i);
  assert.match(sql, /ADD COLUMN can_view_billing/i);
  assert.match(sql, /ADD COLUMN can_operate_billing/i);
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
  assert.match(sql, /column_name = 'can_operate_billing'/i);
  assert.match(sql, /column_name = 'can_view_billing'/i);
  assert.match(sql, /column_name = 'can_operate_member_admin'/i);
  assert.match(sql, /column_name = 'can_view_member_admin'/i);
  assert.match(sql, /PREPARE migration_stmt FROM @ddl_sql/i);
  assert.match(sql, /DROP COLUMN can_operate_billing/i);
  assert.match(sql, /DROP COLUMN can_view_billing/i);
  assert.match(sql, /DROP COLUMN can_operate_member_admin/i);
  assert.match(sql, /DROP COLUMN can_view_member_admin/i);
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
  assert.match(sql, /can_view_member_admin/i);
  assert.match(sql, /can_operate_member_admin/i);
  assert.match(sql, /can_view_billing/i);
  assert.match(sql, /can_operate_billing/i);
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
  assert.match(sql, /CONCAT\('tenant_owner__', SUBSTRING\(SHA2\(legacy\.tenant_id, 256\), 1, 24\)\)/i);
  assert.match(sql, /SIGNAL SQLSTATE '45000'/i);
  assert.match(sql, /owner_takeover_tenant_code_collision_count/i);
  assert.match(sql, /tenant code collision detected/i);
  assert.match(sql, /INSERT INTO platform_role_catalog/i);
  assert.match(sql, /INSERT IGNORE INTO tenant_role_permission_grants/i);
  assert.match(sql, /LOWER\(TRIM\(permission_code\)\) IN/i);
  assert.match(sql, /tenant\.billing\.view/i);
  assert.match(sql, /tenant\.billing\.operate/i);
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
