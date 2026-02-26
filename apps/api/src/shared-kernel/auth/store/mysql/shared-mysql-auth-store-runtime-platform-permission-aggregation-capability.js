'use strict';

const {
  toBoolean
} = require('./shared-mysql-auth-store-runtime-audit-normalization-capability');

const isActiveLikeStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  return normalizedStatus === 'active' || normalizedStatus === 'enabled';
};
const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);

const toPlatformPermissionSnapshot = ({
  canViewUserManagement = false,
  canOperateUserManagement = false,
  canViewTenantManagement = false,
  canOperateTenantManagement = false,
  canViewRoleManagement = false,
  canOperateRoleManagement = false
} = {}, scopeLabel = '平台权限（角色并集）') => ({
  scopeLabel,
  canViewUserManagement: Boolean(canViewUserManagement),
  canOperateUserManagement: Boolean(canOperateUserManagement),
  canViewTenantManagement: Boolean(canViewTenantManagement),
  canOperateTenantManagement: Boolean(canOperateTenantManagement),
  canViewRoleManagement: Boolean(canViewRoleManagement),
  canOperateRoleManagement: Boolean(canOperateRoleManagement)
});

const isSamePlatformPermissionSnapshot = (left, right) => {
  const normalizedLeft = left || toPlatformPermissionSnapshot();
  const normalizedRight = right || toPlatformPermissionSnapshot();
  return (
    Boolean(normalizedLeft.canViewUserManagement) === Boolean(normalizedRight.canViewUserManagement)
    && Boolean(normalizedLeft.canOperateUserManagement) === Boolean(normalizedRight.canOperateUserManagement)
    && Boolean(normalizedLeft.canViewTenantManagement) === Boolean(normalizedRight.canViewTenantManagement)
    && Boolean(normalizedLeft.canOperateTenantManagement) === Boolean(normalizedRight.canOperateTenantManagement)
    && Boolean(normalizedLeft.canViewRoleManagement) === Boolean(normalizedRight.canViewRoleManagement)
    && Boolean(normalizedLeft.canOperateRoleManagement) === Boolean(normalizedRight.canOperateRoleManagement)
  );
};

const normalizePlatformRoleStatus = (status) => {
  if (status === null || status === undefined) {
    return 'active';
  }
  if (typeof status !== 'string') {
    throw new Error(`invalid platform role status: ${String(status)}`);
  }
  const normalizedStatus = status.trim().toLowerCase();
  if (!normalizedStatus) {
    throw new Error('invalid platform role status:');
  }
  if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedStatus)) {
    throw new Error(`invalid platform role status: ${normalizedStatus}`);
  }
  return normalizedStatus;
};

const aggregatePlatformPermissionFromRoleRows = (rows) => {
  const normalizedRows = Array.isArray(rows) ? rows : [];
  const activeRows = normalizedRows.filter((row) =>
    isActiveLikeStatus(row?.status)
  );

  return {
    hasRoleFacts: normalizedRows.length > 0,
    hasActiveRoleFacts: activeRows.length > 0,
    permission: toPlatformPermissionSnapshot({
      canViewUserManagement: activeRows.some((row) =>
        toBoolean(row?.can_view_user_management ?? row?.canViewUserManagement)
      ),
      canOperateUserManagement: activeRows.some((row) =>
        toBoolean(row?.can_operate_user_management ?? row?.canOperateUserManagement)
      ),
      canViewTenantManagement: activeRows.some((row) =>
        toBoolean(row?.can_view_tenant_management ?? row?.canViewTenantManagement)
      ),
      canOperateTenantManagement: activeRows.some((row) =>
        toBoolean(row?.can_operate_tenant_management ?? row?.canOperateTenantManagement)
      )
    })
  };
};

const normalizePlatformRoleFactPayload = (role) => {
  const roleId = String(role?.roleId || role?.role_id || '').trim();
  if (!roleId) {
    return null;
  }
  const permissionSource = role?.permission || role;
  return {
    roleId,
    status: normalizePlatformRoleStatus(role?.status),
    canViewUserManagement: toBoolean(
      permissionSource?.canViewUserManagement ?? permissionSource?.can_view_user_management
    ),
    canOperateUserManagement: toBoolean(
      permissionSource?.canOperateUserManagement ?? permissionSource?.can_operate_user_management
    ),
    canViewTenantManagement: toBoolean(
      permissionSource?.canViewTenantManagement ?? permissionSource?.can_view_tenant_management
    ),
    canOperateTenantManagement: toBoolean(
      permissionSource?.canOperateTenantManagement ?? permissionSource?.can_operate_tenant_management
    )
  };
};

const dedupePlatformRoleFacts = (roles = []) => {
  const dedupedByRoleId = new Map();
  for (const role of Array.isArray(roles) ? roles : []) {
    const normalizedRole = normalizePlatformRoleFactPayload(role);
    if (!normalizedRole) {
      continue;
    }
    const dedupeKey = String(normalizedRole.roleId || '').trim().toLowerCase();
    if (!dedupeKey) {
      continue;
    }
    dedupedByRoleId.set(dedupeKey, normalizedRole);
  }
  return [...dedupedByRoleId.values()];
};

module.exports = {
  isActiveLikeStatus,
  VALID_PLATFORM_ROLE_FACT_STATUS,
  toPlatformPermissionSnapshot,
  isSamePlatformPermissionSnapshot,
  normalizePlatformRoleStatus,
  aggregatePlatformPermissionFromRoleRows,
  normalizePlatformRoleFactPayload,
  dedupePlatformRoleFacts
};
