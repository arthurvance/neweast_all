const createInMemoryAuthStore = ({ seedUsers = [], hashPassword }) => {
  const usersByPhone = new Map();
  const usersById = new Map();
  const sessionsById = new Map();
  const refreshTokensByHash = new Map();
  const domainsByUserId = new Map();
  const tenantsByUserId = new Map();

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
    domainsByUserId.set(
      normalizedUser.id,
      new Set(
        rawDomains
          .map((domain) => String(domain || '').trim().toLowerCase())
          .filter((domain) => domain === 'platform' || domain === 'tenant')
      )
    );

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
  }

  const clone = (value) => (value ? { ...value } : null);

  return {
    findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

    findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

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
      if (userDomains.size > 0 || userDomains.has('platform')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }
      userDomains.add('platform');
      domainsByUserId.set(normalizedUserId, userDomains);
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
        (tenant) => String(tenant?.status || 'active').toLowerCase() === 'active'
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
        .filter((tenant) => String(tenant?.status || 'active').toLowerCase() === 'active')
        .map((tenant) => ({ ...tenant })),

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      const tenant = (tenantsByUserId.get(String(userId)) || []).find(
        (item) =>
          String(item.tenantId) === normalizedTenantId &&
          String(item?.status || 'active').toLowerCase() === 'active'
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
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (!previous || previous.status !== 'active') {
        return { ok: false };
      }

      previous.status = 'rotated';
      previous.rotatedTo = nextTokenHash;
      previous.updatedAt = Date.now();

      refreshTokensByHash.set(nextTokenHash, {
        tokenHash: nextTokenHash,
        sessionId,
        userId: String(userId),
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
      const user = usersById.get(String(userId));
      if (!user) {
        return null;
      }

      user.passwordHash = passwordHash;
      user.sessionVersion += 1;
      usersByPhone.set(user.phone, user);
      usersById.set(user.id, user);
      return clone(user);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) => {
      const user = usersById.get(String(userId));
      if (!user) {
        return null;
      }

      user.passwordHash = passwordHash;
      user.sessionVersion += 1;
      usersByPhone.set(user.phone, user);
      usersById.set(user.id, user);

      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason || 'password-changed';
          session.updatedAt = Date.now();
        }
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }

      return clone(user);
    }
  };
};

module.exports = { createInMemoryAuthStore };
