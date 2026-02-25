const test = require('node:test');
const assert = require('node:assert/strict');
const {
  PLATFORM_ROUTE_MANIFEST
} = require('../../src/route-manifests/platform.route-manifest');
const {
  TENANT_ROUTE_MANIFEST
} = require('../../src/route-manifests/tenant.route-manifest');
const {
  PLATFORM_AUDIT_EVENTS_PATH,
  TENANT_AUDIT_EVENTS_PATH,
  PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
  TENANT_AUDIT_VIEW_PERMISSION_CODE,
  PLATFORM_AUDIT_SCOPE,
  TENANT_AUDIT_SCOPE
} = require('../../src/modules/audit/audit.constants');

const findManifestEntry = (manifest = [], { method, path }) =>
  manifest.find(
    (entry = {}) =>
      String(entry.method || '').toUpperCase() === String(method || '').toUpperCase()
      && String(entry.path || '') === String(path || '')
  ) || null;

test('platform audit route declaration keeps stable permission + scope chain', () => {
  const entry = findManifestEntry(PLATFORM_ROUTE_MANIFEST, {
    method: 'GET',
    path: PLATFORM_AUDIT_EVENTS_PATH
  });
  assert.ok(entry, 'platform audit route declaration missing');
  assert.equal(entry.access, 'protected');
  assert.equal(entry.permission_code, PLATFORM_AUDIT_VIEW_PERMISSION_CODE);
  assert.equal(entry.scope, PLATFORM_AUDIT_SCOPE);
  assert.ok(
    String(entry.permission_code || '').endsWith('.view'),
    'platform audit permission must keep read-only semantic'
  );
});

test('tenant audit route declaration keeps stable permission + scope chain', () => {
  const entry = findManifestEntry(TENANT_ROUTE_MANIFEST, {
    method: 'GET',
    path: TENANT_AUDIT_EVENTS_PATH
  });
  assert.ok(entry, 'tenant audit route declaration missing');
  assert.equal(entry.access, 'protected');
  assert.equal(entry.permission_code, TENANT_AUDIT_VIEW_PERMISSION_CODE);
  assert.equal(entry.scope, TENANT_AUDIT_SCOPE);
  assert.ok(
    String(entry.permission_code || '').endsWith('.view'),
    'tenant audit permission must keep read-only semantic'
  );
});
