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
