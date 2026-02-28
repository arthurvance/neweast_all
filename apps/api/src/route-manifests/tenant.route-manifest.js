const {
  TENANT_AUDIT_EVENTS_PATH,
  TENANT_AUDIT_VIEW_PERMISSION_CODE,
  TENANT_AUDIT_SCOPE
} = require('../modules/audit/audit.constants');
const {
  TENANT_USER_LIST_PATH,
  TENANT_USER_CREATE_PATH,
  TENANT_USER_DETAIL_PATH,
  TENANT_USER_STATUS_PATH,
  TENANT_USER_PROFILE_PATH,
  TENANT_USER_ROLE_BINDING_PATH,
  TENANT_USER_VIEW_PERMISSION_CODE,
  TENANT_USER_OPERATE_PERMISSION_CODE,
  TENANT_USER_SCOPE,
  TENANT_ROLE_BASE_PATH,
  TENANT_ROLE_ITEM_PATH,
  TENANT_ROLE_PERMISSION_PATH,
  TENANT_ROLE_VIEW_PERMISSION_CODE,
  TENANT_ROLE_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_SCOPE,
  TENANT_ACCOUNT_BASE_PATH,
  TENANT_ACCOUNT_ITEM_PATH,
  TENANT_ACCOUNT_STATUS_PATH,
  TENANT_ACCOUNT_OPERATION_LOG_PATH,
  TENANT_ACCOUNT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_OPERATE_PERMISSION_CODE,
  TENANT_ACCOUNT_SCOPE,
  TENANT_CUSTOMER_BASE_PATH,
  TENANT_CUSTOMER_UPDATE_BY_ACCOUNT_NICKNAME_PATH,
  TENANT_CUSTOMER_ITEM_PATH,
  TENANT_CUSTOMER_UPDATE_PATH,
  TENANT_CUSTOMER_OPERATION_LOG_PATH,
  TENANT_CUSTOMER_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE,
  TENANT_SESSION_CONVERSATION_INGEST_PATH,
  TENANT_SESSION_HISTORY_INGEST_PATH,
  TENANT_SESSION_CHAT_LIST_PATH,
  TENANT_SESSION_CHAT_MESSAGES_PATH,
  TENANT_SESSION_ACCOUNT_OPTIONS_PATH,
  TENANT_SESSION_MESSAGE_CREATE_PATH,
  TENANT_SESSION_OUTBOUND_PULL_PATH,
  TENANT_SESSION_OUTBOUND_STATUS_PATH,
  TENANT_SESSION_VIEW_PERMISSION_CODE,
  TENANT_SESSION_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_SCOPE
} = require('../domains/tenant');

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
    path: TENANT_USER_LIST_PATH,
    access: 'protected',
    permission_code: TENANT_USER_VIEW_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_USER_CREATE_PATH,
    access: 'protected',
    permission_code: TENANT_USER_OPERATE_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_USER_DETAIL_PATH,
    access: 'protected',
    permission_code: TENANT_USER_VIEW_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_USER_STATUS_PATH,
    access: 'protected',
    permission_code: TENANT_USER_OPERATE_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_USER_PROFILE_PATH,
    access: 'protected',
    permission_code: TENANT_USER_OPERATE_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_USER_ROLE_BINDING_PATH,
    access: 'protected',
    permission_code: TENANT_USER_VIEW_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
  },
  {
    method: 'PUT',
    path: TENANT_USER_ROLE_BINDING_PATH,
    access: 'protected',
    permission_code: TENANT_USER_OPERATE_PERMISSION_CODE,
    scope: TENANT_USER_SCOPE
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
    path: TENANT_ACCOUNT_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_ACCOUNT_VIEW_PERMISSION_CODE,
    scope: TENANT_ACCOUNT_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_ACCOUNT_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE,
    scope: TENANT_ACCOUNT_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_ACCOUNT_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_ACCOUNT_VIEW_PERMISSION_CODE,
    scope: TENANT_ACCOUNT_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_ACCOUNT_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE,
    scope: TENANT_ACCOUNT_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_ACCOUNT_STATUS_PATH,
    access: 'protected',
    permission_code: TENANT_ACCOUNT_OPERATE_PERMISSION_CODE,
    scope: TENANT_ACCOUNT_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_ACCOUNT_OPERATION_LOG_PATH,
    access: 'protected',
    permission_code: TENANT_ACCOUNT_VIEW_PERMISSION_CODE,
    scope: TENANT_ACCOUNT_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_CUSTOMER_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_CUSTOMER_VIEW_PERMISSION_CODE,
    scope: TENANT_CUSTOMER_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_CUSTOMER_BASE_PATH,
    access: 'protected',
    permission_code: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE,
    scope: TENANT_CUSTOMER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_CUSTOMER_UPDATE_BY_ACCOUNT_NICKNAME_PATH,
    access: 'protected',
    permission_code: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE,
    scope: TENANT_CUSTOMER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_CUSTOMER_ITEM_PATH,
    access: 'protected',
    permission_code: TENANT_CUSTOMER_VIEW_PERMISSION_CODE,
    scope: TENANT_CUSTOMER_SCOPE
  },
  {
    method: 'PATCH',
    path: TENANT_CUSTOMER_UPDATE_PATH,
    access: 'protected',
    permission_code: TENANT_CUSTOMER_OPERATE_PERMISSION_CODE,
    scope: TENANT_CUSTOMER_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_CUSTOMER_OPERATION_LOG_PATH,
    access: 'protected',
    permission_code: TENANT_CUSTOMER_VIEW_PERMISSION_CODE,
    scope: TENANT_CUSTOMER_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_SESSION_CONVERSATION_INGEST_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_OPERATE_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_SESSION_HISTORY_INGEST_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_OPERATE_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_SESSION_CHAT_LIST_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_VIEW_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_SESSION_CHAT_MESSAGES_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_VIEW_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_SESSION_ACCOUNT_OPTIONS_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_VIEW_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_SESSION_MESSAGE_CREATE_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_OPERATE_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'GET',
    path: TENANT_SESSION_OUTBOUND_PULL_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_OPERATE_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
  },
  {
    method: 'POST',
    path: TENANT_SESSION_OUTBOUND_STATUS_PATH,
    access: 'protected',
    permission_code: TENANT_SESSION_OPERATE_PERMISSION_CODE,
    scope: TENANT_SESSION_SCOPE
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
