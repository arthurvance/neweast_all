const TENANT_MEMBER_LIST_PATH = '/tenant/members';
const TENANT_MEMBER_CREATE_PATH = '/tenant/members';
const TENANT_MEMBER_DETAIL_PATH = '/tenant/members/:membership_id';
const TENANT_MEMBER_STATUS_PATH = '/tenant/members/:membership_id/status';
const TENANT_MEMBER_PROFILE_PATH = '/tenant/members/:membership_id/profile';
const TENANT_MEMBER_ROLE_BINDING_PATH = '/tenant/members/:membership_id/roles';

const TENANT_MEMBER_LIST_ROUTE_KEY = 'GET /tenant/members';
const TENANT_MEMBER_CREATE_ROUTE_KEY = 'POST /tenant/members';
const TENANT_MEMBER_DETAIL_ROUTE_KEY = 'GET /tenant/members/:membership_id';
const TENANT_MEMBER_STATUS_ROUTE_KEY = 'PATCH /tenant/members/:membership_id/status';
const TENANT_MEMBER_PROFILE_ROUTE_KEY = 'PATCH /tenant/members/:membership_id/profile';
const TENANT_MEMBER_ROLE_BINDING_GET_ROUTE_KEY = 'GET /tenant/members/:membership_id/roles';
const TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY = 'PUT /tenant/members/:membership_id/roles';

const TENANT_MEMBER_VIEW_PERMISSION_CODE = 'tenant.user_management.view';
const TENANT_MEMBER_OPERATE_PERMISSION_CODE = 'tenant.user_management.operate';
const TENANT_MEMBER_SCOPE = 'tenant';

module.exports = {
  TENANT_MEMBER_LIST_PATH,
  TENANT_MEMBER_CREATE_PATH,
  TENANT_MEMBER_DETAIL_PATH,
  TENANT_MEMBER_STATUS_PATH,
  TENANT_MEMBER_PROFILE_PATH,
  TENANT_MEMBER_ROLE_BINDING_PATH,
  TENANT_MEMBER_LIST_ROUTE_KEY,
  TENANT_MEMBER_CREATE_ROUTE_KEY,
  TENANT_MEMBER_DETAIL_ROUTE_KEY,
  TENANT_MEMBER_STATUS_ROUTE_KEY,
  TENANT_MEMBER_PROFILE_ROUTE_KEY,
  TENANT_MEMBER_ROLE_BINDING_GET_ROUTE_KEY,
  TENANT_MEMBER_ROLE_BINDING_PUT_ROUTE_KEY,
  TENANT_MEMBER_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_OPERATE_PERMISSION_CODE,
  TENANT_MEMBER_SCOPE
};
