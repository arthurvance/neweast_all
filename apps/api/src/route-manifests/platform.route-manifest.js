const {
  PLATFORM_AUDIT_EVENTS_PATH,
  PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
  PLATFORM_AUDIT_SCOPE
} = require('../modules/audit/audit.constants');
const {
  PLATFORM_ORG_LIST_PATH,
  PLATFORM_ORG_CREATE_PATH,
  PLATFORM_ORG_STATUS_PATH,
  PLATFORM_ORG_OWNER_TRANSFER_PATH,
  PLATFORM_ORG_VIEW_PERMISSION_CODE,
  PLATFORM_ORG_CREATE_PERMISSION_CODE,
  PLATFORM_ORG_SCOPE
} = require('../modules/platform/org.constants');
const {
  PLATFORM_ROLE_BASE_PATH,
  PLATFORM_ROLE_ITEM_PATH,
  PLATFORM_ROLE_PERMISSION_PATH,
  PLATFORM_ROLE_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
  PLATFORM_ROLE_SCOPE
} = require('../modules/platform/role.constants');
const {
  PLATFORM_USER_LIST_PATH,
  PLATFORM_USER_GET_PATH,
  PLATFORM_USER_CREATE_PATH,
  PLATFORM_USER_UPDATE_PATH,
  PLATFORM_USER_SOFT_DELETE_PATH,
  PLATFORM_USER_STATUS_PATH,
  PLATFORM_USER_VIEW_PERMISSION_CODE,
  PLATFORM_USER_OPERATE_PERMISSION_CODE,
  PLATFORM_USER_SCOPE
} = require('../modules/platform/user.constants');
const {
  PLATFORM_SYSTEM_CONFIG_ITEM_PATH,
  PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
  PLATFORM_SYSTEM_CONFIG_SCOPE
} = require('../modules/platform/system-config.constants');
const {
  PLATFORM_INTEGRATION_BASE_PATH,
  PLATFORM_INTEGRATION_ITEM_PATH,
  PLATFORM_INTEGRATION_LIFECYCLE_PATH,
  PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_SCOPE
} = require('../modules/platform/integration.constants');
const {
  PLATFORM_INTEGRATION_CONTRACT_BASE_PATH,
  PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_CHECK_PATH,
  PLATFORM_INTEGRATION_CONTRACT_CONSISTENCY_CHECK_PATH,
  PLATFORM_INTEGRATION_CONTRACT_ACTIVATE_PATH,
  PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_CONTRACT_SCOPE
} = require('../modules/platform/integration-contract.constants');
const {
  PLATFORM_INTEGRATION_RECOVERY_QUEUE_PATH,
  PLATFORM_INTEGRATION_RECOVERY_REPLAY_PATH,
  PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_RECOVERY_SCOPE
} = require('../modules/platform/integration-recovery.constants');
const {
  PLATFORM_INTEGRATION_FREEZE_STATUS_PATH,
  PLATFORM_INTEGRATION_FREEZE_RELEASE_PATH,
  PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_FREEZE_SCOPE
} = require('../modules/platform/integration-freeze.constants');

const PLATFORM_ROUTE_MANIFEST = Object.freeze([
  {
    method: 'GET',
    path: '/auth/platform/options',
    access: 'protected',
    permission_code: PLATFORM_USER_VIEW_PERMISSION_CODE,
    scope: 'platform'
  },
  {
    method: 'GET',
    path: '/auth/platform/user-management/probe',
    access: 'protected',
    permission_code: PLATFORM_USER_VIEW_PERMISSION_CODE,
    scope: 'platform'
  },
  {
    method: 'POST',
    path: '/auth/platform/user-management/provision-user',
    access: 'protected',
    permission_code: PLATFORM_USER_OPERATE_PERMISSION_CODE,
    scope: 'platform'
  },
  {
    method: 'GET',
    path: PLATFORM_ORG_LIST_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_VIEW_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ORG_CREATE_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_CREATE_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ORG_STATUS_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_CREATE_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ORG_OWNER_TRANSFER_PATH,
    access: 'protected',
    permission_code: PLATFORM_ORG_CREATE_PERMISSION_CODE,
    scope: PLATFORM_ORG_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_AUDIT_EVENTS_PATH,
    access: 'protected',
    permission_code: PLATFORM_AUDIT_VIEW_PERMISSION_CODE,
    scope: PLATFORM_AUDIT_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_SYSTEM_CONFIG_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_SYSTEM_CONFIG_VIEW_PERMISSION_CODE,
    scope: PLATFORM_SYSTEM_CONFIG_SCOPE
  },
  {
    method: 'PUT',
    path: PLATFORM_SYSTEM_CONFIG_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_SYSTEM_CONFIG_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_SYSTEM_CONFIG_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_INTEGRATION_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_INTEGRATION_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_SCOPE
  },
  {
    method: 'PATCH',
    path: PLATFORM_INTEGRATION_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_LIFECYCLE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_INTEGRATION_CONTRACT_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_CONTRACT_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_CONTRACT_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_CONTRACT_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_CHECK_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_CONTRACT_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_CONTRACT_CONSISTENCY_CHECK_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_CONTRACT_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_CONTRACT_ACTIVATE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_CONTRACT_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_INTEGRATION_RECOVERY_QUEUE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_RECOVERY_VIEW_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_RECOVERY_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_RECOVERY_REPLAY_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_RECOVERY_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_RECOVERY_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_INTEGRATION_FREEZE_STATUS_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_FREEZE_VIEW_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_FREEZE_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_FREEZE_STATUS_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_FREEZE_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_INTEGRATION_FREEZE_RELEASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_INTEGRATION_FREEZE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_INTEGRATION_FREEZE_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_VIEW_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_ROLE_BASE_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'PATCH',
    path: PLATFORM_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'DELETE',
    path: PLATFORM_ROLE_ITEM_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_ROLE_PERMISSION_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_VIEW_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'PUT',
    path: PLATFORM_ROLE_PERMISSION_PATH,
    access: 'protected',
    permission_code: PLATFORM_ROLE_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_ROLE_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_USER_LIST_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_VIEW_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'GET',
    path: PLATFORM_USER_GET_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_VIEW_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_USER_CREATE_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'PATCH',
    path: PLATFORM_USER_UPDATE_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'DELETE',
    path: PLATFORM_USER_SOFT_DELETE_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'POST',
    path: PLATFORM_USER_STATUS_PATH,
    access: 'protected',
    permission_code: PLATFORM_USER_OPERATE_PERMISSION_CODE,
    scope: PLATFORM_USER_SCOPE
  },
  {
    method: 'POST',
    path: '/auth/platform/role-facts/replace',
    access: 'protected',
    permission_code: PLATFORM_USER_OPERATE_PERMISSION_CODE,
    scope: 'platform'
  }
]);

module.exports = {
  PLATFORM_ROUTE_MANIFEST
};
