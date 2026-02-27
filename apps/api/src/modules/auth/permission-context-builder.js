const buildPlatformPermissionContext = () => ({
  scope_label: '平台入口（无组织侧权限上下文）',
  can_view_user_management: false,
  can_operate_user_management: false,
  can_view_tenant_management: false,
  can_operate_tenant_management: false,
  can_view_role_management: false,
  can_operate_role_management: false
});

const buildTenantUnselectedPermissionContext = () => ({
  scope_label: '组织未选择（无可操作权限）',
  can_view_user_management: false,
  can_operate_user_management: false,
  can_view_account_management: false,
  can_operate_account_management: false,
  can_view_role_management: false,
  can_operate_role_management: false
});

const buildTenantPlatformEntryPermissionContext = () => ({
  scope_label: '平台入口（无组织侧权限上下文）',
  can_view_user_management: false,
  can_operate_user_management: false,
  can_view_account_management: false,
  can_operate_account_management: false,
  can_view_role_management: false,
  can_operate_role_management: false
});

const readPermissionCodeSet = (permissionContext) => {
  const permissionCodeSet = permissionContext?.permission_code_set
    ?? permissionContext?.permissionCodeSet;
  if (permissionCodeSet instanceof Set) {
    return permissionCodeSet;
  }
  if (Array.isArray(permissionCodeSet)) {
    return new Set(
      permissionCodeSet
        .map((permissionCode) => String(permissionCode || '').trim().toLowerCase())
        .filter((permissionCode) => permissionCode.length > 0)
    );
  }
  return null;
};

const attachPermissionCodeSet = ({ source, target }) => {
  const permissionCodeSet = readPermissionCodeSet(source);
  if (!(permissionCodeSet instanceof Set) || permissionCodeSet.size < 1) {
    return target;
  }
  Object.defineProperty(target, 'permission_code_set', {
    value: permissionCodeSet,
    enumerable: false,
    configurable: true
  });
  Object.defineProperty(target, 'permissionCodeSet', {
    value: permissionCodeSet,
    enumerable: false,
    configurable: true
  });
  return target;
};

const normalizeTenantPermissionContext = (permissionContext, fallbackScopeLabel) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return null;
  }
  return attachPermissionCodeSet({
    source: permissionContext,
    target: {
    scope_label: permissionContext.scopeLabel
      || permissionContext.scope_label
      || fallbackScopeLabel
      || '组织权限快照（默认）',
    can_view_user_management: Boolean(
      permissionContext.canViewUserManagement ?? permissionContext.can_view_user_management
    ),
    can_operate_user_management: Boolean(
      permissionContext.canOperateUserManagement ?? permissionContext.can_operate_user_management
    ),
    can_view_account_management: Boolean(
      permissionContext.canViewAccountManagement ?? permissionContext.can_view_account_management
    ),
    can_operate_account_management: Boolean(
      permissionContext.canOperateAccountManagement ?? permissionContext.can_operate_account_management
    ),
    can_view_role_management: Boolean(
      permissionContext.canViewRoleManagement ?? permissionContext.can_view_role_management
    ),
    can_operate_role_management: Boolean(
      permissionContext.canOperateRoleManagement ?? permissionContext.can_operate_role_management
    )
  }
  });
};

const normalizePlatformPermissionContext = (permissionContext, fallbackScopeLabel) => {
  if (!permissionContext || typeof permissionContext !== 'object') {
    return null;
  }
  return {
    scope_label: permissionContext.scopeLabel
      || permissionContext.scope_label
      || fallbackScopeLabel
      || '平台权限快照（默认）',
    can_view_user_management: Boolean(
      permissionContext.canViewUserManagement ?? permissionContext.can_view_user_management
    ),
    can_operate_user_management: Boolean(
      permissionContext.canOperateUserManagement ?? permissionContext.can_operate_user_management
    ),
    can_view_tenant_management: Boolean(
      permissionContext.canViewTenantManagement ?? permissionContext.can_view_tenant_management
    ),
    can_operate_tenant_management: Boolean(
      permissionContext.canOperateTenantManagement ?? permissionContext.can_operate_tenant_management
    ),
    can_view_role_management: Boolean(
      permissionContext.canViewRoleManagement ?? permissionContext.can_view_role_management
    ),
    can_operate_role_management: Boolean(
      permissionContext.canOperateRoleManagement ?? permissionContext.can_operate_role_management
    )
  };
};

const createPermissionContextBuilder = ({
  permissionRepository,
  errors,
  addAuditEvent,
  rejectNoDomainAccess,
  getDomainAccessForUser,
  normalizeTenantId,
  toPlatformPermissionCodeKey,
  platformRoleManagementOperatePermissionCode,
  AuthProblemError
} = {}) => {
  const resolveSystemConfigPermissionGrant = async ({
    requestId,
    userId,
    sessionId,
    entryDomain,
    permissionCode
  }) => {
    if (entryDomain !== 'platform') {
      return {
        can_view_role_management: false,
        can_operate_role_management: false,
        granted: false
      };
    }

    if (typeof permissionRepository.hasPlatformPermissionByUserId !== 'function') {
      addAuditEvent({
        type: 'auth.platform.snapshot.degraded',
        requestId,
        userId,
        sessionId,
        detail: 'platform permission grant lookup unavailable',
        metadata: {
          permission_code: permissionCode,
          entry_domain: entryDomain,
          tenant_id: null,
          degradation_reason: 'platform-permission-grant-lookup-unsupported'
        }
      });
      throw errors.platformSnapshotDegraded({
        reason: 'platform-permission-grant-lookup-unsupported'
      });
    }

    let lookupResult = null;
    try {
      lookupResult = await permissionRepository.hasPlatformPermissionByUserId({
        userId: String(userId || '').trim(),
        permissionCode
      });
    } catch (_error) {
      addAuditEvent({
        type: 'auth.platform.snapshot.degraded',
        requestId,
        userId,
        sessionId,
        detail: 'platform permission grant lookup failed',
        metadata: {
          permission_code: permissionCode,
          entry_domain: entryDomain,
          tenant_id: null,
          degradation_reason: 'platform-permission-grant-lookup-failed'
        }
      });
      throw errors.platformSnapshotDegraded({
        reason: 'platform-permission-grant-lookup-failed'
      });
    }

    if (typeof lookupResult === 'boolean') {
      return {
        can_view_role_management: lookupResult,
        can_operate_role_management: lookupResult,
        granted: lookupResult
      };
    }

    const canViewRoleManagement = Boolean(lookupResult?.canViewRoleManagement);
    const canOperateRoleManagement =
      canViewRoleManagement && Boolean(lookupResult?.canOperateRoleManagement);
    const normalizedPermissionCodeKey = toPlatformPermissionCodeKey(permissionCode);
    const granted =
      normalizedPermissionCodeKey === platformRoleManagementOperatePermissionCode
        ? canOperateRoleManagement
        : canViewRoleManagement;
    return {
      can_view_role_management: canViewRoleManagement,
      can_operate_role_management: canOperateRoleManagement,
      granted
    };
  };

  const getTenantPermissionContext = async ({
    requestId,
    userId,
    sessionId,
    entryDomain,
    activeTenantId
  }) => {
    if (entryDomain !== 'tenant') {
      return buildTenantPlatformEntryPermissionContext();
    }

    const normalizedTenantId = normalizeTenantId(activeTenantId);
    if (!normalizedTenantId) {
      return buildTenantUnselectedPermissionContext();
    }

    if (
      typeof permissionRepository.findTenantPermissionByUserAndTenantId !== 'function'
    ) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: normalizedTenantId,
        detail: `tenant permission lookup unavailable: ${normalizedTenantId}`
      });
    }

    const permissionContext =
      await permissionRepository.findTenantPermissionByUserAndTenantId({
      userId: String(userId),
      tenantId: normalizedTenantId
    });
    const normalized = normalizeTenantPermissionContext(
      permissionContext,
      `组织权限（${normalizedTenantId}）`
    );
    if (!normalized) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: normalizedTenantId,
        detail: `tenant permission missing: ${normalizedTenantId}`
      });
    }
    return normalized;
  };

  const getPlatformPermissionContext = async ({
    requestId,
    userId,
    sessionId,
    entryDomain,
    permissionCode = null
  }) => {
    if (entryDomain !== 'platform') {
      return null;
    }

    const access = await getDomainAccessForUser(userId);
    if (!access.platform) {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: null,
        detail: 'platform domain access denied',
        permissionCode
      });
    }

    if (typeof permissionRepository.syncPlatformPermissionSnapshotByUserId === 'function') {
      let syncResult = await permissionRepository.syncPlatformPermissionSnapshotByUserId({
        userId: String(userId),
        forceWhenNoRoleFacts: true
      });
      if (syncResult?.reason === 'concurrent-role-facts-update') {
        syncResult = await permissionRepository.syncPlatformPermissionSnapshotByUserId({
          userId: String(userId),
          forceWhenNoRoleFacts: true
        });
      }
      if (syncResult?.reason === 'concurrent-role-facts-update') {
        addAuditEvent({
          type: 'auth.platform.snapshot.degraded',
          requestId,
          userId,
          sessionId,
          detail: 'platform snapshot sync degraded: concurrent-role-facts-update',
          metadata: {
            permission_code: permissionCode,
            entry_domain: entryDomain,
            tenant_id: null,
            degradation_reason: 'concurrent-role-facts-update'
          }
        });
        throw errors.platformSnapshotDegraded({
          reason: 'concurrent-role-facts-update'
        });
      }
      if (syncResult?.reason === 'db-deadlock') {
        addAuditEvent({
          type: 'auth.platform.snapshot.degraded',
          requestId,
          userId,
          sessionId,
          detail: 'platform snapshot sync degraded: db-deadlock',
          metadata: {
            permission_code: permissionCode,
            entry_domain: entryDomain,
            tenant_id: null,
            degradation_reason: 'db-deadlock'
          }
        });
        throw errors.platformSnapshotDegraded({
          reason: 'db-deadlock'
        });
      }
      if (syncResult?.reason === 'role-facts-table-missing') {
        rejectNoDomainAccess({
          requestId,
          userId,
          sessionId,
          entryDomain,
          tenantId: null,
          detail: 'platform role facts unavailable',
          permissionCode
        });
      }

      const normalizedSyncReason = String(syncResult?.reason || '').trim();
      const acceptedSyncReasons = new Set([
        'ok',
        'up-to-date',
        'already-empty'
      ]);
      if (!acceptedSyncReasons.has(normalizedSyncReason)) {
        addAuditEvent({
          type: 'auth.platform.snapshot.degraded',
          requestId,
          userId,
          sessionId,
          detail: `platform snapshot sync degraded: ${normalizedSyncReason || 'unknown'}`,
          metadata: {
            permission_code: permissionCode,
            entry_domain: entryDomain,
            tenant_id: null,
            degradation_reason: normalizedSyncReason || 'unknown'
          }
        });
        throw errors.platformSnapshotDegraded({
          reason: normalizedSyncReason || 'unknown'
        });
      }
    }

    if (typeof permissionRepository.findPlatformPermissionByUserId !== 'function') {
      rejectNoDomainAccess({
        requestId,
        userId,
        sessionId,
        entryDomain,
        tenantId: null,
        detail: 'platform permission lookup unavailable',
        permissionCode
      });
    }

    const permissionContext = await permissionRepository.findPlatformPermissionByUserId({
      userId: String(userId)
    });
    const normalized = normalizePlatformPermissionContext(permissionContext);
    if (!normalized) {
      addAuditEvent({
        type: 'auth.route.forbidden',
        requestId,
        userId,
        sessionId,
        detail: 'platform permission missing',
        metadata: {
          permission_code: permissionCode,
          entry_domain: entryDomain,
          tenant_id: null
        }
      });
      throw errors.forbidden();
    }
    if (typeof permissionRepository.hasPlatformPermissionByUserId === 'function') {
      try {
        const systemConfigGrant = await resolveSystemConfigPermissionGrant({
          requestId,
          userId,
          sessionId,
          entryDomain,
          permissionCode: platformRoleManagementOperatePermissionCode
        });
        normalized.can_view_role_management = Boolean(
          systemConfigGrant?.can_view_role_management
        );
        normalized.can_operate_role_management = Boolean(
          systemConfigGrant?.can_operate_role_management
        );
      } catch (error) {
        if (
          !(error instanceof AuthProblemError)
          || error.errorCode !== 'AUTH-503-PLATFORM-SNAPSHOT-DEGRADED'
        ) {
          throw error;
        }
      }
    }
    return normalized;
  };

  return {
    resolveSystemConfigPermissionGrant,
    getTenantPermissionContext,
    getPlatformPermissionContext
  };
};

module.exports = {
  buildPlatformPermissionContext,
  buildTenantUnselectedPermissionContext,
  buildTenantPlatformEntryPermissionContext,
  normalizeTenantPermissionContext,
  normalizePlatformPermissionContext,
  createPermissionContextBuilder
};
