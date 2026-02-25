const test = require('node:test');
const assert = require('node:assert/strict');
const { readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const {
  PLATFORM_ROUTE_MANIFEST
} = require('../../src/route-manifests/platform.route-manifest');

const PLATFORM_ROUTE_MANIFEST_SNAPSHOT = JSON.parse(
  readFileSync(
    resolve(__dirname, './platform.route-manifest.snapshot.json'),
    'utf8'
  )
);

const toRouteKey = (routeDefinition = {}) =>
  `${String(routeDefinition.method || '').toUpperCase()} ${String(routeDefinition.path || '')}`;

test('platform route manifest matches approved contract snapshot', () => {
  assert.deepEqual(PLATFORM_ROUTE_MANIFEST, PLATFORM_ROUTE_MANIFEST_SNAPSHOT);
});

test('platform route contract snapshot has unique method/path keys', () => {
  const routeKeys = PLATFORM_ROUTE_MANIFEST_SNAPSHOT.map(toRouteKey);
  const uniqueRouteKeys = new Set(routeKeys);
  assert.equal(uniqueRouteKeys.size, routeKeys.length);
});
