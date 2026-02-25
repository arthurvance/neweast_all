const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const {
  TENANT_ROUTE_MANIFEST
} = require('../../src/route-manifests/tenant.route-manifest');

const TENANT_ROUTE_MANIFEST_SNAPSHOT = JSON.parse(
  readFileSync(
    resolve(__dirname, './tenant.route-manifest.snapshot.json'),
    'utf8'
  )
);

const toRouteKey = (routeDefinition = {}) =>
  `${String(routeDefinition.method || '').toUpperCase()} ${String(routeDefinition.path || '')}`;

test('tenant route manifest matches approved contract snapshot', () => {
  assert.deepEqual(TENANT_ROUTE_MANIFEST, TENANT_ROUTE_MANIFEST_SNAPSHOT);
});

test('tenant route contract snapshot has unique method/path keys', () => {
  const routeKeys = TENANT_ROUTE_MANIFEST_SNAPSHOT.map(toRouteKey);
  const uniqueRouteKeys = new Set(routeKeys);
  assert.equal(uniqueRouteKeys.size, routeKeys.length);
});
