const TENANT_USER_LIST_PATH = '/tenant/users';
const TENANT_USER_CREATE_PATH = '/tenant/users';
const TENANT_USER_DETAIL_PATH = '/tenant/users/:membership_id';
const TENANT_USER_STATUS_PATH = '/tenant/users/:membership_id/status';
const TENANT_USER_PROFILE_PATH = '/tenant/users/:membership_id/profile';
const TENANT_USER_ROLE_BINDING_PATH = '/tenant/users/:membership_id/roles';

const TENANT_USER_LIST_ROUTE_KEY = 'GET /tenant/users';
const TENANT_USER_CREATE_ROUTE_KEY = 'POST /tenant/users';
const TENANT_USER_DETAIL_ROUTE_KEY = 'GET /tenant/users/:membership_id';
const TENANT_USER_STATUS_ROUTE_KEY = 'PATCH /tenant/users/:membership_id/status';
const TENANT_USER_PROFILE_ROUTE_KEY = 'PATCH /tenant/users/:membership_id/profile';
const TENANT_USER_ROLE_BINDING_GET_ROUTE_KEY = 'GET /tenant/users/:membership_id/roles';
const TENANT_USER_ROLE_BINDING_PUT_ROUTE_KEY = 'PUT /tenant/users/:membership_id/roles';

const TENANT_USER_VIEW_PERMISSION_CODE = 'tenant.user_management.view';
const TENANT_USER_OPERATE_PERMISSION_CODE = 'tenant.user_management.operate';
const TENANT_USER_SCOPE = 'tenant';

module.exports = {
  TENANT_USER_LIST_PATH,
  TENANT_USER_CREATE_PATH,
  TENANT_USER_DETAIL_PATH,
  TENANT_USER_STATUS_PATH,
  TENANT_USER_PROFILE_PATH,
  TENANT_USER_ROLE_BINDING_PATH,
  TENANT_USER_LIST_ROUTE_KEY,
  TENANT_USER_CREATE_ROUTE_KEY,
  TENANT_USER_DETAIL_ROUTE_KEY,
  TENANT_USER_STATUS_ROUTE_KEY,
  TENANT_USER_PROFILE_ROUTE_KEY,
  TENANT_USER_ROLE_BINDING_GET_ROUTE_KEY,
  TENANT_USER_ROLE_BINDING_PUT_ROUTE_KEY,
  TENANT_USER_VIEW_PERMISSION_CODE,
  TENANT_USER_OPERATE_PERMISSION_CODE,
  TENANT_USER_SCOPE
};
