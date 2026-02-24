const {
  TENANT_AUDIT_EVENTS_PATH,
  TENANT_AUDIT_VIEW_PERMISSION_CODE,
  TENANT_AUDIT_SCOPE
} = require('../modules/audit/audit.constants');
const {
  TENANT_MEMBER_LIST_PATH,
  TENANT_MEMBER_CREATE_PATH,
  TENANT_MEMBER_DETAIL_PATH,
  TENANT_MEMBER_STATUS_PATH,
  TENANT_MEMBER_PROFILE_PATH,
  TENANT_MEMBER_ROLE_BINDING_PATH,
  TENANT_MEMBER_VIEW_PERMISSION_CODE,
  TENANT_MEMBER_OPERATE_PERMISSION_CODE,
  TENANT_MEMBER_SCOPE
} = require('../modules/tenant/member.constants');
const {
  TENANT_ROLE_BASE_PATH,
  TENANT_ROLE_ITEM_PATH,
  TENANT_ROLE_PERMISSION_PATH,
  TENANT_ROLE_VIEW_PERMISSION_CODE,
  TENANT_ROLE_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_SCOPE
} = require('../modules/tenant/role.constants');

const TENANT_ROUTE_MANIFEST = Object.freeze([
  {
    method: 'GET',
    path: '/auth/tenant/options',
    access: 'protected',
    permission_code: 'tenant.context.read',
    scope: 'tenant'
  },
  {
    method: 'POST',
    path: '/auth/tenant/select',
    access: 'protected',
    permission_code: 'tenant.context.switch',
    scope: 'tenant'
  },
  {
    method: 'POST',
    path: '/auth/tenant/switch',
    access: 'protected',
    permission_code: 'tenant.context.switch',
    scope: 'tenant'
  },
  {
    method: 'GET',
    path: '/auth/tenant/user-management/probe',
    access: 'protected',
    permission_code: 'tenant.user_management.operate',
    scope: 'tenant'
  },
  {
    method: 'POST',
    path: '/auth/tenant/user-management/provision-user',
    access: 'protected',
    permission_code: 'tenant.user_management.operate',
    scope: 'tenant'
  },
  {
    method: 'GET',
    path: TENANT_MEMBER_LIST_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_VIEW_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_MEMBER_CREATE_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_OPERATE_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_MEMBER_DETAIL_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_VIEW_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_MEMBER_STATUS_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_OPERATE_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_MEMBER_PROFILE_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_OPERATE_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_MEMBER_ROLE_BINDING_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_VIEW_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'PUT',
    path: TENANT_MEMBER_ROLE_BINDING_PATH,
    access: 'protected',
    permission_code: TENANT_MEMBER_OPERATE_PERMISSION_CODE,
    scope: TENANT_MEMBER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_VIEW_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'DELETE',
    path: TENANT_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_ROLE_PERMISSION_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_VIEW_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'PUT',
    path: TENANT_ROLE_PERMISSION_PATH,
    access: 'protected',
    permission_code: TENANT_ROLE_OPERATE_PERMISSION_CODE,
    scope: TENANT_ROLE_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_AUDIT_EVENTS_PATH,
    access: 'protected',
    permission_code: TENANT_AUDIT_VIEW_PERMISSION_CODE,
    scope: TENANT_AUDIT_SCOPE
  }
]);

module.exports = {
  TENANT_ROUTE_MANIFEST
};
