const { randomUUID } = require('node:crypto');

const createInMemoryAuthStore = ({ seedUsers = [], hashPassword }) => {
  const usersByPhone = new Map();
  const usersById = new Map();
  const sessionsById = new Map();
  const refreshTokensByHash = new Map();
  const domainsByUserId = new Map();
  const platformDomainKnownByUserId = new Set();
  const tenantsByUserId = new Map();
  const platformRolesByUserId = new Map();
  const platformPermissionsByUserId = new Map();
  const orgsById = new Map();
  const orgIdByName = new Map();
  const membershipsByOrgId = new Map();
  const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);
  const VALID_ORG_STATUS = new Set(['active', 'disabled']);
  const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
  const MAX_ORG_NAME_LENGTH = 128;

  const isActiveLikeStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    return normalizedStatus === 'active' || normalizedStatus === 'enabled';
  };
  const normalizeOrgStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return normalizedStatus;
  };
  const isTenantMembershipActiveForAuth = (tenantMembership) => {
    if (!isActiveLikeStatus(tenantMembership?.status)) {
      return false;
    }
    const tenantId = String(
      tenantMembership?.tenantId || tenantMembership?.tenant_id || ''
    ).trim();
    if (!tenantId) {
      return false;
    }
    const org = orgsById.get(tenantId);
    if (!org) {
      return orgsById.size === 0;
    }
    return isActiveLikeStatus(normalizeOrgStatus(org.status));
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

  const normalizePlatformPermission = (
    permission,
    fallbackScopeLabel = '平台权限快照（服务端）'
  ) => {
    if (!permission || typeof permission !== 'object') {
      return null;
    }
    return {
      scopeLabel: permission.scopeLabel || permission.scope_label || fallbackScopeLabel,
      canViewMemberAdmin: Boolean(
        permission.canViewMemberAdmin ?? permission.can_view_member_admin
      ),
      canOperateMemberAdmin: Boolean(
        permission.canOperateMemberAdmin ?? permission.can_operate_member_admin
      ),
      canViewBilling: Boolean(permission.canViewBilling ?? permission.can_view_billing),
      canOperateBilling: Boolean(
        permission.canOperateBilling ?? permission.can_operate_billing
      )
    };
  };

  const mergePlatformPermission = (left, right) => {
    if (!left && !right) {
      return null;
    }
    if (!left) {
      return { ...right };
    }
    if (!right) {
      return { ...left };
    }
    return {
      scopeLabel: left.scopeLabel || right.scopeLabel || '平台权限快照（服务端）',
      canViewMemberAdmin:
        Boolean(left.canViewMemberAdmin) || Boolean(right.canViewMemberAdmin),
      canOperateMemberAdmin:
        Boolean(left.canOperateMemberAdmin) || Boolean(right.canOperateMemberAdmin),
      canViewBilling: Boolean(left.canViewBilling) || Boolean(right.canViewBilling),
      canOperateBilling:
        Boolean(left.canOperateBilling) || Boolean(right.canOperateBilling)
    };
  };

  const buildEmptyPlatformPermission = (scopeLabel = '平台权限（角色并集）') => ({
    scopeLabel,
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });

  const isSamePlatformPermission = (left, right) => {
    const normalizedLeft = left || buildEmptyPlatformPermission();
    const normalizedRight = right || buildEmptyPlatformPermission();
    return (
      Boolean(normalizedLeft.canViewMemberAdmin) === Boolean(normalizedRight.canViewMemberAdmin)
      && Boolean(normalizedLeft.canOperateMemberAdmin) === Boolean(normalizedRight.canOperateMemberAdmin)
      && Boolean(normalizedLeft.canViewBilling) === Boolean(normalizedRight.canViewBilling)
      && Boolean(normalizedLeft.canOperateBilling) === Boolean(normalizedRight.canOperateBilling)
    );
  };

  const normalizePlatformRole = (role) => {
    const roleId = String(role?.roleId || role?.role_id || '').trim();
    if (!roleId) {
      return null;
    }
    const permissionSource = role?.permission || role;
    return {
      roleId,
      status: normalizePlatformRoleStatus(role?.status),
      permission: normalizePlatformPermission(permissionSource, '平台权限（角色并集）')
    };
  };

  const dedupePlatformRolesByRoleId = (roles = []) => {
    const dedupedByRoleId = new Map();
    for (const role of Array.isArray(roles) ? roles : []) {
      const roleId = String(role?.roleId || '').trim();
      const dedupeKey = roleId.toLowerCase();
      if (!dedupeKey) {
        continue;
      }
      dedupedByRoleId.set(dedupeKey, role);
    }
    return [...dedupedByRoleId.values()];
  };

  const mergePlatformPermissionFromRoles = (roles) => {
    let merged = null;
    const normalizedRoles = Array.isArray(roles) ? roles : [];
    for (const role of normalizedRoles) {
      if (!role || !isActiveLikeStatus(role.status)) {
        continue;
      }
      merged = mergePlatformPermission(merged, role.permission);
    }
    return merged;
  };

  const syncPlatformPermissionFromRoleFacts = ({
    userId,
    forceWhenNoRoleFacts = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId || !usersById.has(normalizedUserId)) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const roles = platformRolesByUserId.get(normalizedUserId) || [];
    if (roles.length === 0 && !forceWhenNoRoleFacts) {
      return {
        synced: false,
        reason: 'no-role-facts',
        permission: null
      };
    }

    let permission = mergePlatformPermissionFromRoles(roles);
    if (!permission) {
      permission = buildEmptyPlatformPermission();
    }
    platformPermissionsByUserId.set(normalizedUserId, { ...permission });

    return {
      synced: true,
      reason: 'ok',
      permission: { ...permission }
    };
  };

  for (const user of seedUsers) {
    const normalizedUser = {
      id: String(user.id),
      phone: user.phone,
      status: (user.status || 'active').toLowerCase(),
      sessionVersion: Number(user.sessionVersion || 1),
      passwordHash: user.passwordHash || hashPassword(user.password)
    };

    usersByPhone.set(normalizedUser.phone, normalizedUser);
    usersById.set(normalizedUser.id, normalizedUser);

    const rawDomains = Array.isArray(user.domains) ? user.domains : ['platform', 'tenant'];
    const domainSet = new Set(
      rawDomains
        .map((domain) => String(domain || '').trim().toLowerCase())
        .filter((domain) => domain === 'platform' || domain === 'tenant')
    );
    domainsByUserId.set(normalizedUser.id, domainSet);
    if (domainSet.has('platform')) {
      platformDomainKnownByUserId.add(normalizedUser.id);
    }

    const rawTenants = Array.isArray(user.tenants) ? user.tenants : [];
    tenantsByUserId.set(
      normalizedUser.id,
      rawTenants
        .filter((tenant) => tenant && tenant.tenantId)
        .map((tenant) => ({
          tenantId: String(tenant.tenantId),
          tenantName: tenant.tenantName ? String(tenant.tenantName) : null,
          status: String(tenant.status || 'active').toLowerCase(),
          permission: tenant.permission
            ? {
              scopeLabel: tenant.permission.scopeLabel || null,
              canViewMemberAdmin: Boolean(tenant.permission.canViewMemberAdmin),
              canOperateMemberAdmin: Boolean(tenant.permission.canOperateMemberAdmin),
              canViewBilling: Boolean(tenant.permission.canViewBilling),
              canOperateBilling: Boolean(tenant.permission.canOperateBilling)
            }
            : null
        }))
    );

    const rawPlatformRoles = Array.isArray(user.platformRoles) ? user.platformRoles : [];
    const normalizedPlatformRoles = dedupePlatformRolesByRoleId(
      rawPlatformRoles
        .map((role) => normalizePlatformRole(role))
        .filter(Boolean)
    );
    platformRolesByUserId.set(normalizedUser.id, normalizedPlatformRoles);

    let platformPermission = normalizePlatformPermission(user.platformPermission);
    platformPermission = mergePlatformPermission(
      platformPermission,
      mergePlatformPermissionFromRoles(normalizedPlatformRoles)
    );

    if (platformPermission) {
      platformPermissionsByUserId.set(normalizedUser.id, { ...platformPermission });
    }
  }

  const clone = (value) => (value ? { ...value } : null);

  const bumpSessionVersionAndConvergeSessions = ({
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const user = usersById.get(String(userId));
    if (!user) {
      return null;
    }

    if (passwordHash !== null && passwordHash !== undefined) {
      user.passwordHash = passwordHash;
    }
    user.sessionVersion += 1;
    usersByPhone.set(user.phone, user);
    usersById.set(user.id, user);

    if (revokeAuthSessions) {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }
    }

    if (revokeRefreshTokens) {
      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    }

    return clone(user);
  };

  const revokeSessionsForUserByEntryDomain = ({
    userId,
    entryDomain,
    reason
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedEntryDomain = String(entryDomain || '').trim().toLowerCase();
    if (!normalizedUserId) {
      return;
    }
    if (!normalizedEntryDomain) {
      return;
    }

    const revokedSessionIds = new Set();
    for (const session of sessionsById.values()) {
      if (
        session.userId === normalizedUserId
        && session.status === 'active'
        && String(session.entryDomain || '').trim().toLowerCase() === normalizedEntryDomain
      ) {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
        revokedSessionIds.add(String(session.sessionId || '').trim());
      }
    }

    if (revokedSessionIds.size === 0) {
      return;
    }

    for (const refreshRecord of refreshTokensByHash.values()) {
      if (
        refreshRecord.status === 'active'
        && revokedSessionIds.has(String(refreshRecord.sessionId || '').trim())
      ) {
        refreshRecord.status = 'revoked';
        refreshRecord.updatedAt = Date.now();
      }
    }
  };

  const revokePlatformSessionsForUser = ({
    userId,
    reason = 'platform-user-status-changed'
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'platform',
      reason
    });

  const revokeTenantSessionsForUser = ({
    userId,
    reason = 'org-status-changed'
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'tenant',
      reason
    });

  const createForeignKeyConstraintError = () => {
    const error = new Error('Cannot delete or update a parent row: a foreign key constraint fails');
    error.code = 'ER_ROW_IS_REFERENCED_2';
    error.errno = 1451;
    return error;
  };

  const createDataTooLongError = () => {
    const error = new Error('Data too long for column');
    error.code = 'ER_DATA_TOO_LONG';
    error.errno = 1406;
    return error;
  };

  const hasOrgReferenceForUser = (userId) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return false;
    }

    for (const org of orgsById.values()) {
      if (
        String(org?.ownerUserId || '').trim() === normalizedUserId
        || String(org?.createdByUserId || '').trim() === normalizedUserId
      ) {
        return true;
      }
    }
    for (const memberships of membershipsByOrgId.values()) {
      if (!Array.isArray(memberships)) {
        continue;
      }
      if (
        memberships.some(
          (membership) => String(membership?.userId || '').trim() === normalizedUserId
        )
      ) {
        return true;
      }
    }
    return false;
  };

  return {
    findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

    findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

    createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      if (usersByPhone.has(normalizedPhone)) {
        return null;
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const user = {
        id: randomUUID(),
        phone: normalizedPhone,
        passwordHash: normalizedPasswordHash,
        status: normalizedStatus,
        sessionVersion: 1
      };
      usersByPhone.set(normalizedPhone, user);
      usersById.set(user.id, user);
      if (!domainsByUserId.has(user.id)) {
        domainsByUserId.set(user.id, new Set());
      }
      if (!tenantsByUserId.has(user.id)) {
        tenantsByUserId.set(user.id, []);
      }
      return clone(user);
    },

    createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerUserId,
      operatorUserId
    }) => {
      const normalizedOrgId = String(orgId || '').trim() || randomUUID();
      const normalizedOrgName = String(orgName || '').trim();
      const normalizedOwnerUserId = String(ownerUserId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      if (
        !normalizedOrgName
        || !normalizedOwnerUserId
        || !normalizedOperatorUserId
      ) {
        throw new Error(
          'createOrganizationWithOwner requires orgName, ownerUserId, and operatorUserId'
        );
      }
      if (!usersById.has(normalizedOwnerUserId) || !usersById.has(normalizedOperatorUserId)) {
        throw new Error('createOrganizationWithOwner requires existing owner and operator users');
      }
      if (normalizedOrgName.length > MAX_ORG_NAME_LENGTH) {
        throw createDataTooLongError();
      }

      const orgNameDedupeKey = normalizedOrgName.toLowerCase();
      if (orgIdByName.has(orgNameDedupeKey)) {
        const duplicateError = new Error('duplicate org name');
        duplicateError.code = 'ER_DUP_ENTRY';
        duplicateError.errno = 1062;
        throw duplicateError;
      }
      if (orgsById.has(normalizedOrgId)) {
        const duplicateError = new Error('duplicate org id');
        duplicateError.code = 'ER_DUP_ENTRY';
        duplicateError.errno = 1062;
        throw duplicateError;
      }

      orgsById.set(normalizedOrgId, {
        id: normalizedOrgId,
        name: normalizedOrgName,
        ownerUserId: normalizedOwnerUserId,
        createdByUserId: normalizedOperatorUserId,
        status: 'active'
      });
      orgIdByName.set(orgNameDedupeKey, normalizedOrgId);
      membershipsByOrgId.set(normalizedOrgId, [
        {
          orgId: normalizedOrgId,
          userId: normalizedOwnerUserId,
          membershipRole: 'owner',
          status: 'active'
        }
      ]);

      return {
        org_id: normalizedOrgId,
        owner_user_id: normalizedOwnerUserId
      };
    },

    updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedOrgId
        || !normalizedOperatorUserId
        || !VALID_ORG_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
        );
      }
      const existingOrg = orgsById.get(normalizedOrgId);
      if (!existingOrg) {
        return null;
      }

      const previousStatus = normalizeOrgStatus(existingOrg.status);
      if (previousStatus !== normalizedNextStatus) {
        existingOrg.status = normalizedNextStatus;
        existingOrg.updatedAt = Date.now();
        orgsById.set(normalizedOrgId, existingOrg);

        if (normalizedNextStatus === 'disabled') {
          const affectedUserIds = new Set();
          const orgMemberships = membershipsByOrgId.get(normalizedOrgId) || [];
          for (const membership of orgMemberships) {
            const membershipUserId = String(membership?.userId || '').trim();
            if (!membershipUserId || !isActiveLikeStatus(membership?.status)) {
              continue;
            }
            affectedUserIds.add(membershipUserId);
          }
          const ownerUserId = String(existingOrg.ownerUserId || '').trim();
          if (ownerUserId) {
            affectedUserIds.add(ownerUserId);
          }
          for (const userId of affectedUserIds) {
            revokeTenantSessionsForUser({
              userId,
              reason: 'org-status-changed'
            });
          }
        }
      }

      return {
        org_id: normalizedOrgId,
        previous_status: previousStatus,
        current_status: normalizedNextStatus
      };
    },

    updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId
    }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedUserId
        || !normalizedOperatorUserId
        || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
        );
      }
      const existingUser = usersById.get(normalizedUserId);
      if (
        !existingUser
        || !platformDomainKnownByUserId.has(normalizedUserId)
      ) {
        return null;
      }

      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      const previousStatus = userDomains.has('platform') ? 'active' : 'disabled';
      if (previousStatus !== normalizedNextStatus) {
        if (normalizedNextStatus === 'active') {
          userDomains.add('platform');
        } else {
          userDomains.delete('platform');
          revokePlatformSessionsForUser({
            userId: normalizedUserId,
            reason: 'platform-user-status-changed'
          });
        }
        domainsByUserId.set(normalizedUserId, userDomains);
      }

      return {
        user_id: normalizedUserId,
        previous_status: previousStatus,
        current_status: normalizedNextStatus
      };
    },

    deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return { deleted: false };
      }
      if (hasOrgReferenceForUser(normalizedUserId)) {
        throw createForeignKeyConstraintError();
      }

      usersById.delete(normalizedUserId);
      usersByPhone.delete(String(existingUser.phone || ''));
      domainsByUserId.delete(normalizedUserId);
      platformDomainKnownByUserId.delete(normalizedUserId);
      tenantsByUserId.delete(normalizedUserId);
      platformRolesByUserId.delete(normalizedUserId);
      platformPermissionsByUserId.delete(normalizedUserId);

      for (const [sessionId, session] of sessionsById.entries()) {
        if (session.userId === normalizedUserId) {
          sessionsById.delete(sessionId);
        }
      }
      for (const [tokenHash, refreshToken] of refreshTokensByHash.entries()) {
        if (refreshToken.userId === normalizedUserId) {
          refreshTokensByHash.delete(tokenHash);
        }
      }

      return { deleted: true };
    },

    createTenantMembershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantMembershipForUser requires userId and tenantId');
      }
      if (!usersById.has(normalizedUserId)) {
        return { created: false };
      }

      const tenantMemberships = tenantsByUserId.get(normalizedUserId) || [];
      const relationshipExists = tenantMemberships.some(
        (tenant) => String(tenant?.tenantId || '').trim() === normalizedTenantId
      );
      if (relationshipExists) {
        return { created: false };
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;

      tenantMemberships.push({
        tenantId: normalizedTenantId,
        tenantName: normalizedTenantName,
        status: 'active',
        permission: {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      });
      tenantsByUserId.set(normalizedUserId, tenantMemberships);
      return { created: true };
    },

    removeTenantMembershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantMembershipForUser requires userId and tenantId');
      }
      const tenantMemberships = tenantsByUserId.get(normalizedUserId);
      if (!Array.isArray(tenantMemberships) || tenantMemberships.length === 0) {
        return { removed: false };
      }
      const retainedMemberships = tenantMemberships.filter(
        (tenant) => String(tenant?.tenantId || '').trim() !== normalizedTenantId
      );
      const removed = retainedMemberships.length !== tenantMemberships.length;
      if (removed) {
        tenantsByUserId.set(normalizedUserId, retainedMemberships);
      }
      return { removed };
    },

    removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (!userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      const hasActiveTenantMembership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantMembershipActiveForAuth(tenant)
      );
      if (hasActiveTenantMembership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      userDomains.delete('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { removed: true };
    },

    createSession: async ({ sessionId, userId, sessionVersion, entryDomain = 'platform', activeTenantId = null }) => {
      sessionsById.set(sessionId, {
        sessionId,
        userId: String(userId),
        sessionVersion: Number(sessionVersion),
        entryDomain: String(entryDomain || 'platform').toLowerCase(),
        activeTenantId: activeTenantId ? String(activeTenantId) : null,
        status: 'active',
        revokedReason: null,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findSessionById: async (sessionId) => clone(sessionsById.get(sessionId) || null),

    updateSessionContext: async ({ sessionId, entryDomain, activeTenantId }) => {
      const session = sessionsById.get(sessionId);
      if (!session) {
        return false;
      }

      if (entryDomain !== undefined) {
        session.entryDomain = String(entryDomain || 'platform').toLowerCase();
      }
      if (activeTenantId !== undefined) {
        session.activeTenantId = activeTenantId ? String(activeTenantId) : null;
      }
      session.updatedAt = Date.now();
      sessionsById.set(sessionId, session);
      return true;
    },

    findDomainAccessByUserId: async (userId) => {
      const userDomains = domainsByUserId.get(String(userId)) || new Set();
      return {
        platform: userDomains.has('platform'),
        tenant: userDomains.has('tenant')
      };
    },

    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (userDomains.has('platform')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        platformDomainKnownByUserId.add(normalizedUserId);
        return { inserted: false };
      }
      if (platformDomainKnownByUserId.has(normalizedUserId)) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }
      userDomains.add('platform');
      domainsByUserId.set(normalizedUserId, userDomains);
      platformDomainKnownByUserId.add(normalizedUserId);
      return { inserted: true };
    },

    ensureTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      const hasActiveTenantMembership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantMembershipActiveForAuth(tenant)
      );
      if (!hasActiveTenantMembership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      userDomains.add('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: true };
    },

    listTenantOptionsByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || [])
        .filter((tenant) => isTenantMembershipActiveForAuth(tenant))
        .map((tenant) => ({ ...tenant })),

    hasAnyTenantRelationshipByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || []).length > 0,

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      const tenant = (tenantsByUserId.get(String(userId)) || []).find(
        (item) =>
          String(item.tenantId) === normalizedTenantId &&
          isTenantMembershipActiveForAuth(item)
      );
      if (!tenant) {
        return null;
      }
      if (tenant.permission) {
        return {
          scopeLabel: tenant.permission.scopeLabel || `组织权限（${tenant.tenantName || tenant.tenantId}）`,
          canViewMemberAdmin: Boolean(tenant.permission.canViewMemberAdmin),
          canOperateMemberAdmin: Boolean(tenant.permission.canOperateMemberAdmin),
          canViewBilling: Boolean(tenant.permission.canViewBilling),
          canOperateBilling: Boolean(tenant.permission.canOperateBilling)
        };
      }
      return null;
    },

    findPlatformPermissionByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }
      const permission = platformPermissionsByUserId.get(normalizedUserId);
      return permission ? { ...permission } : null;
    },

    syncPlatformPermissionSnapshotByUserId: async ({
      userId,
      forceWhenNoRoleFacts = false
    }) =>
      syncPlatformPermissionFromRoleFacts({
        userId,
        forceWhenNoRoleFacts
      }),

    replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId || !usersById.has(normalizedUserId)) {
        return {
          synced: false,
          reason: 'invalid-user-id',
          permission: null
        };
      }

      const previousRoles = platformRolesByUserId.get(normalizedUserId) || [];
      const previousPermission = platformPermissionsByUserId.get(normalizedUserId)
        || mergePlatformPermissionFromRoles(previousRoles)
        || buildEmptyPlatformPermission();

      const normalizedRoles = dedupePlatformRolesByRoleId(
        (Array.isArray(roles) ? roles : [])
          .map((role) => normalizePlatformRole(role))
          .filter(Boolean)
      );
      platformRolesByUserId.set(normalizedUserId, normalizedRoles);
      const syncResult = syncPlatformPermissionFromRoleFacts({
        userId: normalizedUserId,
        forceWhenNoRoleFacts: true
      });

      const nextPermission = syncResult?.permission || buildEmptyPlatformPermission();
      if (!isSamePlatformPermission(previousPermission, nextPermission)) {
        bumpSessionVersionAndConvergeSessions({
          userId: normalizedUserId,
          reason: 'platform-role-facts-changed',
          revokeRefreshTokens: true,
          revokeAuthSessions: true
        });
      }

      return syncResult;
    },

    revokeSession: async ({ sessionId, reason }) => {
      const session = sessionsById.get(sessionId);
      if (session && session.status === 'active') {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.sessionId === sessionId && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    revokeAllUserSessions: async ({ userId, reason }) => {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      refreshTokensByHash.set(tokenHash, {
        tokenHash,
        sessionId,
        userId: String(userId),
        status: 'active',
        rotatedFrom: null,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findRefreshTokenByHash: async (tokenHash) => clone(refreshTokensByHash.get(tokenHash) || null),

    markRefreshTokenStatus: async ({ tokenHash, status }) => {
      const token = refreshTokensByHash.get(tokenHash);
      if (!token) {
        return;
      }

      token.status = status;
      token.updatedAt = Date.now();
    },

    linkRefreshRotation: async ({ previousTokenHash, nextTokenHash }) => {
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (previous) {
        previous.rotatedTo = nextTokenHash;
        previous.updatedAt = Date.now();
      }

      const next = refreshTokensByHash.get(nextTokenHash);
      if (next) {
        next.rotatedFrom = previousTokenHash;
        next.updatedAt = Date.now();
      }
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) => {
      const normalizedSessionId = String(sessionId);
      const normalizedUserId = String(userId);
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (
        !previous
        || previous.status !== 'active'
        || String(previous.sessionId || '') !== normalizedSessionId
        || String(previous.userId || '') !== normalizedUserId
      ) {
        return { ok: false };
      }

      previous.status = 'rotated';
      previous.rotatedTo = nextTokenHash;
      previous.updatedAt = Date.now();

      refreshTokensByHash.set(nextTokenHash, {
        tokenHash: nextTokenHash,
        sessionId: normalizedSessionId,
        userId: normalizedUserId,
        status: 'active',
        rotatedFrom: previousTokenHash,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });

      return { ok: true };
    },

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: 'password-changed',
        revokeRefreshTokens: false,
        revokeAuthSessions: false
      });
      return clone(user);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: reason || 'password-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
      return clone(user);
    }
  };
};

module.exports = { createInMemoryAuthStore };
