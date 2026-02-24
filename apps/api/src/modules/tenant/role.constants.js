const TENANT_ROLE_BASE_PATH = '/tenant/roles';
const TENANT_ROLE_ITEM_PATH = '/tenant/roles/:role_id';
const TENANT_ROLE_PERMISSION_PATH = '/tenant/roles/:role_id/permissions';

const TENANT_ROLE_LIST_ROUTE_KEY = 'GET /tenant/roles';
const TENANT_ROLE_CREATE_ROUTE_KEY = 'POST /tenant/roles';
const TENANT_ROLE_UPDATE_ROUTE_KEY = 'PATCH /tenant/roles/:role_id';
const TENANT_ROLE_DELETE_ROUTE_KEY = 'DELETE /tenant/roles/:role_id';
const TENANT_ROLE_PERMISSION_GET_ROUTE_KEY = 'GET /tenant/roles/:role_id/permissions';
const TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY = 'PUT /tenant/roles/:role_id/permissions';

const TENANT_ROLE_VIEW_PERMISSION_CODE = 'tenant.role_management.view';
const TENANT_ROLE_OPERATE_PERMISSION_CODE = 'tenant.role_management.operate';
const TENANT_ROLE_SCOPE = 'tenant';

const PROTECTED_TENANT_ROLE_IDS = Object.freeze([
  'tenant_owner',
  'tenant_admin',
  'tenant_member'
]);

module.exports = {
  TENANT_ROLE_BASE_PATH,
  TENANT_ROLE_ITEM_PATH,
  TENANT_ROLE_PERMISSION_PATH,
  TENANT_ROLE_LIST_ROUTE_KEY,
  TENANT_ROLE_CREATE_ROUTE_KEY,
  TENANT_ROLE_UPDATE_ROUTE_KEY,
  TENANT_ROLE_DELETE_ROUTE_KEY,
  TENANT_ROLE_PERMISSION_GET_ROUTE_KEY,
  TENANT_ROLE_PERMISSION_PUT_ROUTE_KEY,
  TENANT_ROLE_VIEW_PERMISSION_CODE,
  TENANT_ROLE_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_SCOPE,
  PROTECTED_TENANT_ROLE_IDS
};
