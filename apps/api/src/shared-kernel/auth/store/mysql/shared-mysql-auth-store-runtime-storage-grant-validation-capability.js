'use strict';

const {
  toPlatformPermissionSnapshotFromCodes,
  toTenantPermissionSnapshotFromCodes
} = require('../../../../modules/auth/permission-catalog');
const {
  ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  CONTROL_CHAR_PATTERN,
  KNOWN_PLATFORM_PERMISSION_CODE_SET,
  KNOWN_TENANT_PERMISSION_CODE_SET,
  MYSQL_DUP_ENTRY_ERRNO,
  ROLE_ID_ADDRESSABLE_PATTERN,
  VALID_SYSTEM_SENSITIVE_CONFIG_STATUS
} = require('./shared-mysql-auth-store-runtime-domain-constraint-constants');
const {
  normalizePlatformRoleCatalogRoleId
} = require('./shared-mysql-auth-store-runtime-domain-normalization-guard-capability');
const {
  isSamePlatformPermissionSnapshot,
  toPlatformPermissionSnapshot
} = require('./shared-mysql-auth-store-runtime-platform-permission-aggregation-capability');

const isTableMissingError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_NO_SUCH_TABLE'
  || Number(error?.errno || 0) === 1146;

const isDeadlockError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_LOCK_DEADLOCK'
  || Number(error?.errno || 0) === 1213
  || String(error?.sqlState || '').trim() === '40001';
const isDuplicateEntryError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;
const isMissingTenantUsershipHistoryTableError = (error) =>
  isTableMissingError(error)
  && /auth_user_tenant_membership_history/i.test(String(error?.message || ''));
const isMissingTenantsTableError = (error) =>
  isTableMissingError(error)
  && /\btenants\b/i.test(String(error?.message || ''));
const TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE =
  'AUTH-503-TENANT-MEMBER-HISTORY-UNAVAILABLE';
const createTenantUsershipHistoryUnavailableError = () => {
  const error = new Error(
    'tenant usership history table is required but unavailable'
  );
  error.code = TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE;
  return error;
};
const buildSqlInPlaceholders = (count) =>
  new Array(Math.max(0, Number(count) || 0)).fill('?').join(', ');
const normalizeSystemSensitiveConfigKey = (configKey) =>
  String(configKey || '').trim().toLowerCase();
const normalizeSystemSensitiveConfigStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  if (normalizedStatus === 'enabled') {
    return 'active';
  }
  return VALID_SYSTEM_SENSITIVE_CONFIG_STATUS.has(normalizedStatus)
    ? normalizedStatus
    : '';
};
const createSystemSensitiveConfigVersionConflictError = ({
  configKey = '',
  expectedVersion = 0,
  currentVersion = 0
} = {}) => {
  const error = new Error('system sensitive config version conflict');
  error.code = 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
  error.configKey = normalizeSystemSensitiveConfigKey(configKey);
  error.expectedVersion = Number(expectedVersion);
  error.currentVersion = Number(currentVersion);
  return error;
};
const toSystemSensitiveConfigRecord = (row) => {
  if (!row) {
    return null;
  }
  const configKey = normalizeSystemSensitiveConfigKey(
    row.key ?? row.config_key ?? row.configKey
  );
  if (!configKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(configKey)) {
    return null;
  }
  const updatedAtValue = row.updated_at ?? row.updatedAt;
  const createdAtValue = row.created_at ?? row.createdAt;
  return {
    configKey,
    encryptedValue: String(
      row.value ?? row.encrypted_value ?? row.encryptedValue ?? ''
    ).trim(),
    remark: String(row.remark || '').trim() || null,
    version: Number(row.version || 0),
    previousVersion: Number(row.previous_version || row.previousVersion || 0),
    status: normalizeSystemSensitiveConfigStatus(row.status || 'active') || 'active',
    updatedByUserId: String(row.updated_by_user_id ?? row.updatedByUserId ?? '').trim() || null,
    updatedAt: updatedAtValue instanceof Date
      ? updatedAtValue.toISOString()
      : String(updatedAtValue || ''),
    createdByUserId: String(row.created_by_user_id ?? row.createdByUserId ?? '').trim() || null,
    createdAt: createdAtValue instanceof Date
      ? createdAtValue.toISOString()
      : String(createdAtValue || '')
  };
};
const normalizePlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const toPlatformPermissionCodeKey = (permissionCode) =>
  normalizePlatformPermissionCode(permissionCode).toLowerCase();
const normalizePlatformPermissionCodes = (permissionCodes = []) => {
  const deduped = new Map();
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    const normalizedCode = normalizePlatformPermissionCode(permissionCode);
    if (!normalizedCode) {
      continue;
    }
    const permissionCodeKey = normalizedCode.toLowerCase();
    deduped.set(permissionCodeKey, permissionCodeKey);
  }
  return [...deduped.values()];
};
const createPlatformRolePermissionGrantDataError = (
  reason = 'platform-role-permission-grants-invalid'
) => {
  const error = new Error('platform role permission grants invalid');
  error.code = 'ERR_PLATFORM_ROLE_PERMISSION_GRANTS_INVALID';
  error.reason = String(reason || 'platform-role-permission-grants-invalid')
    .trim()
    .toLowerCase();
  return error;
};
const normalizeStrictPlatformPermissionCodeFromGrantRow = (
  permissionCode,
  reason = 'platform-role-permission-grants-invalid'
) => {
  if (typeof permissionCode !== 'string') {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
  const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
  if (
    permissionCode !== normalizedPermissionCode
    || !normalizedPermissionCode
    || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
    || !KNOWN_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
  ) {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  return permissionCodeKey;
};
const normalizeStrictRoleIdFromPlatformGrantRow = (
  roleId,
  reason = 'platform-role-permission-grants-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || roleId !== normalizedRoleId
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createPlatformRolePermissionGrantDataError(reason);
  }
  return normalizedRoleId;
};
const toPlatformPermissionSnapshotFromGrantCodes = (permissionCodes = []) => {
  const snapshot = toPlatformPermissionSnapshotFromCodes(
    normalizePlatformPermissionCodes(permissionCodes)
  );
  return toPlatformPermissionSnapshot({
    canViewUserManagement: snapshot.canViewUserManagement,
    canOperateUserManagement: snapshot.canOperateUserManagement,
    canViewTenantManagement: snapshot.canViewTenantManagement,
    canOperateTenantManagement: snapshot.canOperateTenantManagement,
    canViewRoleManagement: snapshot.canViewRoleManagement,
    canOperateRoleManagement: snapshot.canOperateRoleManagement
  });
};
const normalizeTenantPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const normalizeTenantPermissionCodes = (permissionCodes = []) => {
  const deduped = new Map();
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    const normalizedCode = normalizeTenantPermissionCode(permissionCode);
    if (!normalizedCode) {
      continue;
    }
    const permissionCodeKey = normalizedCode.toLowerCase();
    deduped.set(permissionCodeKey, permissionCodeKey);
  }
  return [...deduped.values()];
};
const createTenantRolePermissionGrantDataError = (
  reason = 'tenant-role-permission-grants-invalid'
) => {
  const error = new Error('tenant role permission grants invalid');
  error.code = 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID';
  error.reason = String(reason || 'tenant-role-permission-grants-invalid')
    .trim()
    .toLowerCase();
  return error;
};
const normalizeStrictTenantPermissionCodeFromGrantRow = (
  permissionCode,
  reason = 'tenant-role-permission-grants-invalid'
) => {
  if (typeof permissionCode !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedPermissionCode = normalizeTenantPermissionCode(permissionCode);
  const permissionCodeKey = normalizedPermissionCode.toLowerCase();
  if (
    permissionCode !== normalizedPermissionCode
    || !normalizedPermissionCode
    || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
    || !KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return permissionCodeKey;
};
const normalizeStrictTenantRolePermissionGrantIdentity = (
  identityValue,
  reason = 'tenant-role-permission-grants-invalid-identity'
) => {
  if (typeof identityValue !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedIdentity = identityValue.trim();
  if (
    !normalizedIdentity
    || identityValue !== normalizedIdentity
    || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return normalizedIdentity;
};
const normalizeStrictRoleIdFromTenantGrantRow = (
  roleId,
  reason = 'tenant-role-permission-grants-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || roleId !== normalizedRoleId
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return normalizedRoleId;
};
const createTenantUsershipRoleBindingDataError = (
  reason = 'tenant-membership-role-bindings-invalid'
) => {
  const error = new Error('tenant usership role bindings invalid');
  error.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID';
  error.reason = String(reason || 'tenant-membership-role-bindings-invalid')
    .trim()
    .toLowerCase();
  return error;
};
const normalizeStrictTenantUsershipRoleIdFromBindingRow = (
  roleId,
  reason = 'tenant-membership-role-bindings-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || roleId !== normalizedRoleId
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  return normalizedRoleId;
};
const normalizeStrictTenantUsershipRoleBindingIdentity = (
  identityValue,
  reason = 'tenant-membership-role-bindings-invalid-identity'
) => {
  if (typeof identityValue !== 'string') {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  const normalizedIdentity = identityValue.trim();
  if (
    !normalizedIdentity
    || identityValue !== normalizedIdentity
    || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
  ) {
    throw createTenantUsershipRoleBindingDataError(reason);
  }
  return normalizedIdentity;
};
const toTenantPermissionSnapshotFromGrantCodes = (permissionCodes = []) => {
  const snapshot = toTenantPermissionSnapshotFromCodes(
    normalizeTenantPermissionCodes(permissionCodes)
  );
  return toPlatformPermissionSnapshot({
    canViewUserManagement: snapshot.canViewUserManagement,
    canOperateUserManagement: snapshot.canOperateUserManagement,
    canViewRoleManagement: snapshot.canViewRoleManagement,
    canOperateRoleManagement: snapshot.canOperateRoleManagement
  }, '组织权限（角色并集）');
};
const toTenantPermissionSnapshotFromRow = (row, scopeLabel = '组织权限（角色并集）') =>
  toPlatformPermissionSnapshot(
    {
      canViewUserManagement: row?.can_view_user_management ?? row?.canViewUserManagement,
      canOperateUserManagement: row?.can_operate_user_management ?? row?.canOperateUserManagement,
      canViewRoleManagement:
        row?.can_view_role_management
        ?? row?.canViewRoleManagement,
      canOperateRoleManagement:
        row?.can_operate_role_management
        ?? row?.canOperateRoleManagement
    },
    scopeLabel
  );
const isSameTenantPermissionSnapshot = (left, right) =>
  isSamePlatformPermissionSnapshot(
    toPlatformPermissionSnapshot(
      {
        canViewUserManagement: left?.canViewUserManagement,
        canOperateUserManagement: left?.canOperateUserManagement,
        canViewRoleManagement: left?.canViewRoleManagement,
        canOperateRoleManagement: left?.canOperateRoleManagement
      },
      '组织权限（角色并集）'
    ),
    toPlatformPermissionSnapshot(
      {
        canViewUserManagement: right?.canViewUserManagement,
        canOperateUserManagement: right?.canOperateUserManagement,
        canViewRoleManagement: right?.canViewRoleManagement,
        canOperateRoleManagement: right?.canOperateRoleManagement
      },
      '组织权限（角色并集）'
    )
  );

module.exports = {
  isTableMissingError,
  isDeadlockError,
  isDuplicateEntryError,
  isMissingTenantUsershipHistoryTableError,
  isMissingTenantsTableError,
  TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE,
  createTenantUsershipHistoryUnavailableError,
  buildSqlInPlaceholders,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  createSystemSensitiveConfigVersionConflictError,
  toSystemSensitiveConfigRecord,
  normalizePlatformPermissionCode,
  toPlatformPermissionCodeKey,
  normalizePlatformPermissionCodes,
  createPlatformRolePermissionGrantDataError,
  normalizeStrictPlatformPermissionCodeFromGrantRow,
  normalizeStrictRoleIdFromPlatformGrantRow,
  toPlatformPermissionSnapshotFromGrantCodes,
  normalizeTenantPermissionCode,
  normalizeTenantPermissionCodes,
  createTenantRolePermissionGrantDataError,
  normalizeStrictTenantPermissionCodeFromGrantRow,
  normalizeStrictTenantRolePermissionGrantIdentity,
  normalizeStrictRoleIdFromTenantGrantRow,
  createTenantUsershipRoleBindingDataError,
  normalizeStrictTenantUsershipRoleIdFromBindingRow,
  normalizeStrictTenantUsershipRoleBindingIdentity,
  toTenantPermissionSnapshotFromGrantCodes,
  toTenantPermissionSnapshotFromRow,
  isSameTenantPermissionSnapshot
};
