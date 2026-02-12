const createInMemoryAuthStore = ({ seedUsers = [], hashPassword }) => {
  const usersByPhone = new Map();
  const usersById = new Map();
  const sessionsById = new Map();
  const refreshTokensByHash = new Map();

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
  }

  const clone = (value) => (value ? { ...value } : null);

  return {
    findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

    findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

    createSession: async ({ sessionId, userId, sessionVersion }) => {
      sessionsById.set(sessionId, {
        sessionId,
        userId: String(userId),
        sessionVersion: Number(sessionVersion),
        status: 'active',
        revokedReason: null,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findSessionById: async (sessionId) => clone(sessionsById.get(sessionId) || null),

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
