const createSharedMysqlAuthStoreRepositoryRefreshSessionLifecycle = ({
  dbClient,
  runTenantUsershipQuery,
  toUserRecord,
  toSessionRecord,
  toRefreshRecord,
  toBoolean,
  isDuplicateEntryError,
  escapeSqlLikePattern,
  buildSqlInPlaceholders,
  toPlatformPermissionCodeKey,
  normalizeUserStatus,
  normalizeOrgStatus,
  normalizeStoreIsoTimestamp,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  createSystemSensitiveConfigVersionConflictError,
  normalizeRequiredPlatformUserProfileField,
  normalizeOptionalPlatformUserProfileField,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleCatalogStatus,
  toSystemSensitiveConfigRecord,
  toPlatformRoleCatalogRecord,
  resolveActivePlatformPermissionSnapshotByUserIdTx,
  syncPlatformPermissionSnapshotByUserIdImpl,
  bumpSessionVersionAndConvergeSessionsTx,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_PLATFORM_ROLE_CODE_LENGTH,
  MAX_PLATFORM_ROLE_NAME_LENGTH,
  MAINLAND_PHONE_PATTERN,
  CONTROL_CHAR_PATTERN,
  MYSQL_DUP_ENTRY_ERRNO,
  ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = {}) => {
  const deniedRoleManagementPermission = {
    canViewRoleManagement: false,
    canOperateRoleManagement: false,
    granted: false
  };

  return {
    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      await dbClient.query(
        `
          INSERT INTO auth_refresh_tokens (token_hash, session_id, user_id, status, expires_at)
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
          FROM auth_refresh_tokens
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
          UPDATE auth_refresh_tokens
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
          UPDATE auth_refresh_tokens
          SET rotated_to_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [nextTokenHash, previousTokenHash]
      );

      await dbClient.query(
        `
          UPDATE auth_refresh_tokens
          SET rotated_from_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [previousTokenHash, nextTokenHash]
      );
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) =>
      dbClient.inTransaction(async (tx) => {
        const normalizedSessionId = String(sessionId);
        const normalizedUserId = String(userId);
        const rows = await tx.query(
          `
            SELECT token_hash, status, session_id, user_id
            FROM auth_refresh_tokens
            WHERE token_hash = ?
            LIMIT 1
            FOR UPDATE
          `,
          [previousTokenHash]
        );
        const previous = rows[0];

        if (
          !previous
          || String(previous.status).toLowerCase() !== 'active'
          || String(previous.session_id || '') !== normalizedSessionId
          || String(previous.user_id || '') !== normalizedUserId
        ) {
          return { ok: false };
        }

        const updated = await tx.query(
          `
            UPDATE auth_refresh_tokens
            SET status = 'rotated',
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ? AND status = 'active' AND session_id = ? AND user_id = ?
          `,
          [previousTokenHash, normalizedSessionId, normalizedUserId]
        );

        if (!updated || Number(updated.affectedRows || 0) !== 1) {
          return { ok: false };
        }

        await tx.query(
          `
            INSERT INTO auth_refresh_tokens (token_hash, session_id, user_id, status, expires_at, rotated_from_token_hash)
            VALUES (?, ?, ?, 'active', FROM_UNIXTIME(? / 1000.0), ?)
          `,
          [nextTokenHash, normalizedSessionId, normalizedUserId, Number(expiresAt), previousTokenHash]
        );

        await tx.query(
          `
            UPDATE auth_refresh_tokens
            SET rotated_to_token_hash = ?,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ?
          `,
          [nextTokenHash, previousTokenHash]
        );

        return { ok: true };
      }),

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
          UPDATE auth_refresh_tokens
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
          UPDATE auth_refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [String(userId)]
      );
    },

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) =>
      dbClient.inTransaction(async (tx) =>
        bumpSessionVersionAndConvergeSessionsTx({
          txClient: tx,
          userId,
          passwordHash,
          reason: 'password-changed',
          revokeRefreshTokens: false,
          revokeAuthSessions: false
        })),

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) =>
      dbClient.inTransaction(async (tx) =>
        bumpSessionVersionAndConvergeSessionsTx({
          txClient: tx,
          userId,
          passwordHash,
          reason: reason || 'password-changed',
          revokeRefreshTokens: true,
          revokeAuthSessions: true
        }))
  };
};

module.exports = {
  createSharedMysqlAuthStoreRepositoryRefreshSessionLifecycle
};
