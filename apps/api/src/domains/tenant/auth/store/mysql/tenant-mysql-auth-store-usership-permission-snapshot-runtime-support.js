'use strict';

const createTenantMysqlAuthStoreUsershipPermissionSnapshotRuntimeSupport = ({
  buildSqlInPlaceholders,
  normalizePlatformRoleCatalogRoleId,
  normalizeStrictTenantUsershipRoleIdFromBindingRow,
  createTenantUsershipRoleBindingDataError,
  normalizeStrictRoleIdFromTenantGrantRow,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantId,
  normalizePlatformRoleCatalogStatus,
  isActiveLikeStatus,
  createTenantRolePermissionGrantDataError,
  normalizeStrictTenantPermissionCodeFromGrantRow,
  normalizeTenantUsershipStatusForRead,
  toTenantPermissionSnapshotFromGrantCodes,
  toTenantPermissionSnapshotFromRow,
  isSameTenantPermissionSnapshot
} = {}) => {
  const normalizeTenantUsershipRoleIds = (roleIds = []) =>
    [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
        .filter((roleId) => roleId.length > 0)
    )].sort((left, right) => left.localeCompare(right));

  const revokeTenantSessionsForUserTx = async ({
    txClient,
    userId,
    tenantId,
    reason = 'tenant-membership-permission-changed'
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedUserId || !normalizedTenantId) {
      return;
    }
    await txClient.query(
      `
        UPDATE auth_sessions
        SET status = 'revoked',
            revoked_reason = ?,
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE user_id = ?
          AND entry_domain = 'tenant'
          AND active_tenant_id = ?
          AND status = 'active'
      `,
      [reason, normalizedUserId, normalizedTenantId]
    );
    await txClient.query(
      `
        UPDATE auth_refresh_tokens
        SET status = 'revoked',
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE status = 'active'
          AND session_id IN (
            SELECT session_id
            FROM auth_sessions
            WHERE user_id = ?
              AND entry_domain = 'tenant'
              AND active_tenant_id = ?
          )
      `,
      [normalizedUserId, normalizedTenantId]
    );
  };

  const listTenantUsershipRoleBindingsTx = async ({
    txClient,
    membershipId
  }) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return [];
    }
    const roleRows = await txClient.query(
      `
        SELECT role_id
        FROM tenant_membership_roles
        WHERE membership_id = ?
        ORDER BY role_id ASC
        FOR UPDATE
      `,
      [normalizedMembershipId]
    );
    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const row of Array.isArray(roleRows) ? roleRows : []) {
      const normalizedRoleId = normalizeStrictTenantUsershipRoleIdFromBindingRow(
        row?.role_id,
        'tenant-membership-role-bindings-invalid-role-id'
      );
      if (seenRoleIds.has(normalizedRoleId)) {
        throw createTenantUsershipRoleBindingDataError(
          'tenant-membership-role-bindings-duplicate-role-id'
        );
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const loadActiveTenantRoleGrantCodesByRoleIdsTx = async ({
    txClient,
    tenantId,
    roleIds = []
  }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
    const grantsByRoleId = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleId.set(roleId, []);
    }
    const seenGrantPermissionCodeKeysByRoleId = new Map(
      normalizedRoleIds.map((roleId) => [roleId, new Set()])
    );
    if (!normalizedTenantId || normalizedRoleIds.length === 0) {
      return grantsByRoleId;
    }
    const rolePlaceholders = buildSqlInPlaceholders(normalizedRoleIds.length);
    const roleRows = await txClient.query(
      `
        SELECT role_id, status, scope, tenant_id
        FROM platform_roles
        WHERE role_id IN (${rolePlaceholders})
        ORDER BY role_id ASC
        FOR UPDATE
      `,
      normalizedRoleIds
    );
    const activeRoleIds = new Set();
    for (const row of Array.isArray(roleRows) ? roleRows : []) {
      const roleId = normalizeStrictRoleIdFromTenantGrantRow(
        row?.role_id,
        'tenant-role-permission-grants-invalid-role-id'
      );
      if (!roleId || !grantsByRoleId.has(roleId)) {
        continue;
      }
      const roleScope = normalizePlatformRoleCatalogScope(row?.scope);
      const roleTenantId = normalizePlatformRoleCatalogTenantId(row?.tenant_id);
      const roleStatus = normalizePlatformRoleCatalogStatus(row?.status || 'disabled');
      if (
        roleScope === 'tenant'
        && roleTenantId === normalizedTenantId
        && isActiveLikeStatus(roleStatus)
      ) {
        activeRoleIds.add(roleId);
      }
    }
    if (activeRoleIds.size === 0) {
      return grantsByRoleId;
    }
    const grantRoleIds = [...activeRoleIds];
    const grantPlaceholders = buildSqlInPlaceholders(grantRoleIds.length);
    const grantRows = await txClient.query(
      `
        SELECT role_id, permission_code
        FROM tenant_role_permission_grants
        WHERE role_id IN (${grantPlaceholders})
        ORDER BY role_id ASC, permission_code ASC
        FOR UPDATE
      `,
      grantRoleIds
    );
    for (const row of Array.isArray(grantRows) ? grantRows : []) {
      const roleId = normalizeStrictRoleIdFromTenantGrantRow(
        row?.role_id,
        'tenant-role-permission-grants-invalid-role-id'
      );
      if (!activeRoleIds.has(roleId)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-unexpected-role-id'
        );
      }
      if (!grantsByRoleId.has(roleId)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-invalid-role-id'
        );
      }
      const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
        row?.permission_code,
        'tenant-role-permission-grants-invalid-permission-code'
      );
      const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
      if (seenPermissionCodeKeys.has(permissionCodeKey)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-duplicate-permission-code'
        );
      }
      seenPermissionCodeKeys.add(permissionCodeKey);
      grantsByRoleId.get(roleId).push(permissionCodeKey);
    }
    for (const roleId of grantsByRoleId.keys()) {
      if (!activeRoleIds.has(roleId)) {
        grantsByRoleId.set(roleId, []);
        continue;
      }
      grantsByRoleId.set(roleId, [...grantsByRoleId.get(roleId)]);
    }
    return grantsByRoleId;
  };

  const resolveTenantPermissionSnapshotForMembershipTx = async ({
    txClient,
    membership = null,
    tenantId,
    roleIds = []
  }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    const membershipStatus = normalizeTenantUsershipStatusForRead(
      membership?.status
    );
    if (!isActiveLikeStatus(membershipStatus)) {
      return toTenantPermissionSnapshotFromGrantCodes([]);
    }
    const normalizedRoleIds = normalizeTenantUsershipRoleIds(roleIds);
    if (normalizedRoleIds.length === 0) {
      return toTenantPermissionSnapshotFromGrantCodes([]);
    }
    const grantsByRoleId = await loadActiveTenantRoleGrantCodesByRoleIdsTx({
      txClient,
      tenantId: normalizedTenantId,
      roleIds: normalizedRoleIds
    });
    const mergedGrantCodes = [];
    for (const roleId of normalizedRoleIds) {
      mergedGrantCodes.push(...(grantsByRoleId.get(roleId) || []));
    }
    return toTenantPermissionSnapshotFromGrantCodes(mergedGrantCodes);
  };

  const syncTenantUsershipPermissionSnapshotInTx = async ({
    txClient,
    membershipId,
    tenantId,
    roleIds = null,
    revokeReason = 'tenant-membership-permission-changed'
  }) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedMembershipId || !normalizedTenantId) {
      return {
        synced: false,
        reason: 'invalid-membership-reference',
        changed: false,
        permission: null
      };
    }

    const membershipRows = await txClient.query(
      `
        SELECT membership_id,
               user_id,
               tenant_id,
               status,
               can_view_user_management,
               can_operate_user_management,
               can_view_role_management,
               can_operate_role_management
        FROM tenant_memberships
        WHERE membership_id = ? AND tenant_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [normalizedMembershipId, normalizedTenantId]
    );
    const membership = membershipRows?.[0] || null;
    if (!membership) {
      return {
        synced: false,
        reason: 'membership-not-found',
        changed: false,
        permission: null
      };
    }

    const previousSnapshot = toTenantPermissionSnapshotFromRow(
      membership,
      '组织权限（角色并集）'
    );
    const resolvedRoleIds = Array.isArray(roleIds)
      ? normalizeTenantUsershipRoleIds(roleIds)
      : await listTenantUsershipRoleBindingsTx({
        txClient,
        membershipId: normalizedMembershipId
      });
    const nextSnapshot = await resolveTenantPermissionSnapshotForMembershipTx({
      txClient,
      membership,
      tenantId: normalizedTenantId,
      roleIds: resolvedRoleIds
    });
    const changed = !isSameTenantPermissionSnapshot(previousSnapshot, nextSnapshot);
    if (changed) {
      await txClient.query(
        `
          UPDATE tenant_memberships
          SET can_view_user_management = ?,
              can_operate_user_management = ?,
              can_view_role_management = ?,
              can_operate_role_management = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE membership_id = ? AND tenant_id = ?
        `,
        [
          nextSnapshot.canViewUserManagement ? 1 : 0,
          nextSnapshot.canOperateUserManagement ? 1 : 0,
          nextSnapshot.canViewRoleManagement ? 1 : 0,
          nextSnapshot.canOperateRoleManagement ? 1 : 0,
          normalizedMembershipId,
          normalizedTenantId
        ]
      );
      await revokeTenantSessionsForUserTx({
        txClient,
        userId: membership.user_id,
        tenantId: normalizedTenantId,
        reason: revokeReason
      });
    }

    return {
      synced: true,
      reason: 'ok',
      changed,
      permission: {
        canViewUserManagement: nextSnapshot.canViewUserManagement,
        canOperateUserManagement: nextSnapshot.canOperateUserManagement,
        canViewRoleManagement: nextSnapshot.canViewRoleManagement,
        canOperateRoleManagement: nextSnapshot.canOperateRoleManagement
      },
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId,
      userId: String(membership.user_id || '').trim(),
      roleIds: resolvedRoleIds
    };
  };

  return {
    normalizeTenantUsershipRoleIds,
    revokeTenantSessionsForUserTx,
    listTenantUsershipRoleBindingsTx,
    loadActiveTenantRoleGrantCodesByRoleIdsTx,
    resolveTenantPermissionSnapshotForMembershipTx,
    syncTenantUsershipPermissionSnapshotInTx
  };
};

module.exports = {
  createTenantMysqlAuthStoreUsershipPermissionSnapshotRuntimeSupport
};
