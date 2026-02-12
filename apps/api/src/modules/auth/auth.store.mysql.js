const normalizeUserStatus = (status) => {
  if (typeof status !== 'string') {
    return 'disabled';
  }
  const value = status.trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};

const toSessionRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    sessionId: row.session_id,
    userId: String(row.user_id),
    sessionVersion: Number(row.session_version),
    entryDomain: row.entry_domain ? String(row.entry_domain) : 'platform',
    activeTenantId: row.active_tenant_id ? String(row.active_tenant_id) : null,
    status: row.status,
    revokedReason: row.revoked_reason || null
  };
};

const toRefreshRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    tokenHash: row.token_hash,
    sessionId: row.session_id,
    userId: String(row.user_id),
    status: row.status,
    rotatedFrom: row.rotated_from_token_hash || null,
    rotatedTo: row.rotated_to_token_hash || null,
    expiresAt: Number(row.expires_at_epoch_ms)
  };
};

const toUserRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    id: String(row.id),
    phone: row.phone,
    passwordHash: row.password_hash,
    status: normalizeUserStatus(row.status),
    sessionVersion: Number(row.session_version)
  };
};

const toBoolean = (value) =>
  value === true || value === 1 || value === '1' || String(value || '').toLowerCase() === 'true';

const createMySqlAuthStore = ({ dbClient }) => {
  if (!dbClient || typeof dbClient.query !== 'function') {
    throw new Error('createMySqlAuthStore requires dbClient.query');
  }
  if (typeof dbClient.inTransaction !== 'function') {
    throw new Error('createMySqlAuthStore requires dbClient.inTransaction');
  }

  return {
    findUserByPhone: async (phone) => {
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM users
          WHERE phone = ?
          LIMIT 1
        `,
        [phone]
      );
      return toUserRecord(rows[0]);
    },

    findUserById: async (userId) => {
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM users
          WHERE id = ?
          LIMIT 1
        `,
        [userId]
      );
      return toUserRecord(rows[0]);
    },

    createSession: async ({
      sessionId,
      userId,
      sessionVersion,
      entryDomain = 'platform',
      activeTenantId = null
    }) => {
      await dbClient.query(
        `
          INSERT INTO auth_sessions (session_id, user_id, session_version, entry_domain, active_tenant_id, status)
          VALUES (?, ?, ?, ?, ?, 'active')
        `,
        [
          sessionId,
          String(userId),
          Number(sessionVersion),
          String(entryDomain || 'platform').toLowerCase(),
          activeTenantId ? String(activeTenantId) : null
        ]
      );
    },

    findSessionById: async (sessionId) => {
      const rows = await dbClient.query(
        `
          SELECT session_id, user_id, session_version, entry_domain, active_tenant_id, status, revoked_reason
          FROM auth_sessions
          WHERE session_id = ?
          LIMIT 1
        `,
        [sessionId]
      );
      return toSessionRecord(rows[0]);
    },

    updateSessionContext: async ({ sessionId, entryDomain, activeTenantId }) => {
      await dbClient.query(
        `
          UPDATE auth_sessions
          SET entry_domain = COALESCE(?, entry_domain),
              active_tenant_id = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE session_id = ?
        `,
        [
          entryDomain === undefined ? null : String(entryDomain || 'platform').toLowerCase(),
          activeTenantId ? String(activeTenantId) : null,
          String(sessionId)
        ]
      );
      return true;
    },

    findDomainAccessByUserId: async (userId) => {
      const normalizedUserId = String(userId);
      try {
        const rows = await dbClient.query(
          `
            SELECT domain, status
            FROM auth_user_domain_access
            WHERE user_id = ?
          `,
          [normalizedUserId]
        );

        const domainRows = Array.isArray(rows) ? rows : [];
        const activeDomains = new Set();
        let hasAnyTenantDomainRecord = false;
        for (const row of domainRows) {
          const domain = String(row?.domain || '').trim().toLowerCase();
          if (!domain) {
            continue;
          }
          if (domain === 'tenant') {
            hasAnyTenantDomainRecord = true;
          }
          const status = String(row?.status || '').trim().toLowerCase();
          if (!status || status === 'active') {
            activeDomains.add(domain);
          }
        }

        let tenantFromMembership = false;
        if (!activeDomains.has('tenant') && !hasAnyTenantDomainRecord) {
          const tenantRows = await dbClient.query(
            `
              SELECT COUNT(*) AS tenant_count
              FROM auth_user_tenants
              WHERE user_id = ? AND status = 'active'
            `,
            [normalizedUserId]
          );
          const tenantCount = Number(tenantRows?.[0]?.tenant_count || 0);
          tenantFromMembership = tenantCount > 0;
        }

        return {
          platform: activeDomains.has('platform'),
          tenant: activeDomains.has('tenant') || tenantFromMembership
        };
      } catch (error) {
        throw error;
      }
    },

    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const countRows = await dbClient.query(
        `
          SELECT COUNT(*) AS domain_count
          FROM auth_user_domain_access
          WHERE user_id = ?
        `,
        [normalizedUserId]
      );
      const domainCount = Number(countRows?.[0]?.domain_count || 0);
      if (domainCount > 0) {
        return { inserted: false };
      }

      const result = await dbClient.query(
        `
          INSERT INTO auth_user_domain_access (user_id, domain, status)
          VALUES (?, 'platform', 'active')
          ON DUPLICATE KEY UPDATE
            status = VALUES(status),
            updated_at = CURRENT_TIMESTAMP(3)
        `,
        [normalizedUserId]
      );

      return { inserted: Number(result?.affectedRows || 0) > 0 };
    },

    ensureTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);

      const tenantDomainRows = await dbClient.query(
        `
          SELECT status
          FROM auth_user_domain_access
          WHERE user_id = ? AND domain = 'tenant'
          LIMIT 1
        `,
        [normalizedUserId]
      );
      if (Array.isArray(tenantDomainRows) && tenantDomainRows.length > 0) {
        return { inserted: false };
      }

      const tenantCountRows = await dbClient.query(
        `
          SELECT COUNT(*) AS tenant_count
          FROM auth_user_tenants
          WHERE user_id = ? AND status = 'active'
        `,
        [normalizedUserId]
      );
      const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
      if (tenantCount <= 0) {
        return { inserted: false };
      }

      const result = await dbClient.query(
        `
          INSERT IGNORE INTO auth_user_domain_access (user_id, domain, status)
          VALUES (?, 'tenant', 'active')
        `,
        [normalizedUserId]
      );
      return { inserted: Number(result?.affectedRows || 0) > 0 };
    },

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId);
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      try {
        const rows = await dbClient.query(
          `
            SELECT tenant_id,
                   tenant_name,
                   can_view_member_admin,
                   can_operate_member_admin,
                   can_view_billing,
                   can_operate_billing
            FROM auth_user_tenants
            WHERE user_id = ? AND tenant_id = ? AND status = 'active'
            LIMIT 1
          `,
          [normalizedUserId, normalizedTenantId]
        );
        const row = rows?.[0];
        if (!row) {
          return null;
        }
        return {
          scopeLabel: `组织权限（${String(row.tenant_name || normalizedTenantId)}）`,
          canViewMemberAdmin: toBoolean(row.can_view_member_admin),
          canOperateMemberAdmin: toBoolean(row.can_operate_member_admin),
          canViewBilling: toBoolean(row.can_view_billing),
          canOperateBilling: toBoolean(row.can_operate_billing)
        };
      } catch (error) {
        throw error;
      }
    },

    listTenantOptionsByUserId: async (userId) => {
      const normalizedUserId = String(userId);
      try {
        const rows = await dbClient.query(
          `
            SELECT tenant_id, tenant_name
            FROM auth_user_tenants
            WHERE user_id = ? AND status = 'active'
            ORDER BY tenant_id ASC
          `,
          [normalizedUserId]
        );

        return (Array.isArray(rows) ? rows : [])
          .map((row) => ({
            tenantId: String(row.tenant_id || '').trim(),
            tenantName: row.tenant_name ? String(row.tenant_name) : null
          }))
          .filter((row) => row.tenantId.length > 0);
      } catch (error) {
        throw error;
      }
    },

    revokeSession: async ({ sessionId, reason }) => {
      await dbClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE session_id = ? AND status = 'active'
        `,
        [reason || null, sessionId]
      );

      await dbClient.query(
        `
          UPDATE refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE session_id = ? AND status = 'active'
        `,
        [sessionId]
      );
    },

    revokeAllUserSessions: async ({ userId, reason }) => {
      await dbClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [reason || null, String(userId)]
      );

      await dbClient.query(
        `
          UPDATE refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [String(userId)]
      );
    },

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      await dbClient.query(
        `
          INSERT INTO refresh_tokens (token_hash, session_id, user_id, status, expires_at)
          VALUES (?, ?, ?, 'active', FROM_UNIXTIME(? / 1000.0))
        `,
        [tokenHash, sessionId, String(userId), Number(expiresAt)]
      );
    },

    findRefreshTokenByHash: async (tokenHash) => {
      const rows = await dbClient.query(
        `
          SELECT token_hash,
                 session_id,
                 user_id,
                 status,
                 rotated_from_token_hash,
                 rotated_to_token_hash,
                 CAST(ROUND(UNIX_TIMESTAMP(expires_at) * 1000) AS UNSIGNED) AS expires_at_epoch_ms
          FROM refresh_tokens
          WHERE token_hash = ?
          LIMIT 1
        `,
        [tokenHash]
      );
      return toRefreshRecord(rows[0]);
    },

    markRefreshTokenStatus: async ({ tokenHash, status }) => {
      await dbClient.query(
        `
          UPDATE refresh_tokens
          SET status = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [status, tokenHash]
      );
    },

    linkRefreshRotation: async ({ previousTokenHash, nextTokenHash }) => {
      await dbClient.query(
        `
          UPDATE refresh_tokens
          SET rotated_to_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [nextTokenHash, previousTokenHash]
      );

      await dbClient.query(
        `
          UPDATE refresh_tokens
          SET rotated_from_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [previousTokenHash, nextTokenHash]
      );
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) =>
      dbClient.inTransaction(async (tx) => {
        const rows = await tx.query(
          `
            SELECT token_hash, status
            FROM refresh_tokens
            WHERE token_hash = ?
            LIMIT 1
            FOR UPDATE
          `,
          [previousTokenHash]
        );
        const previous = rows[0];

        if (!previous || String(previous.status).toLowerCase() !== 'active') {
          return { ok: false };
        }

        const updated = await tx.query(
          `
            UPDATE refresh_tokens
            SET status = 'rotated',
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ? AND status = 'active'
          `,
          [previousTokenHash]
        );

        if (!updated || Number(updated.affectedRows || 0) !== 1) {
          return { ok: false };
        }

        await tx.query(
          `
            INSERT INTO refresh_tokens (token_hash, session_id, user_id, status, expires_at, rotated_from_token_hash)
            VALUES (?, ?, ?, 'active', FROM_UNIXTIME(? / 1000.0), ?)
          `,
          [nextTokenHash, sessionId, String(userId), Number(expiresAt), previousTokenHash]
        );

        await tx.query(
          `
            UPDATE refresh_tokens
            SET rotated_to_token_hash = ?,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ?
          `,
          [nextTokenHash, previousTokenHash]
        );

        return { ok: true };
      }),

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) => {
      await dbClient.query(
        `
          UPDATE users
          SET password_hash = ?,
              session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [passwordHash, String(userId)]
      );

      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM users
          WHERE id = ?
          LIMIT 1
        `,
        [String(userId)]
      );
      return toUserRecord(rows[0]);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) =>
      dbClient.inTransaction(async (tx) => {
        const updated = await tx.query(
          `
            UPDATE users
            SET password_hash = ?,
                session_version = session_version + 1,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE id = ?
          `,
          [passwordHash, String(userId)]
        );

        if (!updated || Number(updated.affectedRows || 0) !== 1) {
          return null;
        }

        await tx.query(
          `
            UPDATE auth_sessions
            SET status = 'revoked',
                revoked_reason = ?,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE user_id = ? AND status = 'active'
          `,
          [reason || 'password-changed', String(userId)]
        );

        await tx.query(
          `
            UPDATE refresh_tokens
            SET status = 'revoked',
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE user_id = ? AND status = 'active'
          `,
          [String(userId)]
        );

        const rows = await tx.query(
          `
            SELECT id, phone, password_hash, status, session_version
            FROM users
            WHERE id = ?
            LIMIT 1
          `,
          [String(userId)]
        );

        return toUserRecord(rows[0]);
      })
  };
};

module.exports = { createMySqlAuthStore };
