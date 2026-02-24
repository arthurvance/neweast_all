const { IAM_ROUTE_MANIFEST } = require('./iam.route-manifest');
const { PLATFORM_ROUTE_MANIFEST } = require('./platform.route-manifest');
const { TENANT_ROUTE_MANIFEST } = require('./tenant.route-manifest');

const cloneRouteDefinition = (route = {}) => ({
  method: String(route.method || 'GET').trim().toUpperCase(),
  path: String(route.path || ''),
  access: String(route.access || '').trim().toLowerCase(),
  permission_code: String(route.permission_code || '').trim(),
  scope: String(route.scope || '').trim().toLowerCase()
});

const ROUTE_MANIFESTS = Object.freeze({
  iam: IAM_ROUTE_MANIFEST,
  platform: PLATFORM_ROUTE_MANIFEST,
  tenant: TENANT_ROUTE_MANIFEST
});

const listRouteDefinitionsFromManifests = () =>
  Object.freeze([
    ...ROUTE_MANIFESTS.iam.map(cloneRouteDefinition),
    ...ROUTE_MANIFESTS.tenant.map(cloneRouteDefinition),
    ...ROUTE_MANIFESTS.platform.map(cloneRouteDefinition)
  ]);

module.exports = {
  IAM_ROUTE_MANIFEST,
  PLATFORM_ROUTE_MANIFEST,
  TENANT_ROUTE_MANIFEST,
  ROUTE_MANIFESTS,
  listRouteDefinitionsFromManifests
};
