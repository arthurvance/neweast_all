'use strict';

const createSharedMysqlAuthStoreSessionConvergenceRuntimeSupport = ({
  toUserRecord
} = {}) => {
  const bumpSessionVersionAndConvergeSessionsTx = async ({
    txClient,
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const normalizedUserId = String(userId);
    const shouldUpdatePassword = passwordHash !== null && passwordHash !== undefined;
    const updateResult = shouldUpdatePassword
      ? await txClient.query(
        `
          UPDATE iam_users
          SET password_hash = ?,
              session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [passwordHash, normalizedUserId]
      )
      : await txClient.query(
        `
          UPDATE iam_users
          SET session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [normalizedUserId]
      );

    if (!updateResult || Number(updateResult.affectedRows || 0) !== 1) {
      return null;
    }

    if (revokeAuthSessions) {
      await txClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [reason || 'critical-state-changed', normalizedUserId]
      );
    }

    if (revokeRefreshTokens) {
      await txClient.query(
        `
          UPDATE auth_refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [normalizedUserId]
      );
    }

    const rows = await txClient.query(
      `
        SELECT id, phone, password_hash, status, session_version
        FROM iam_users
        WHERE id = ?
        LIMIT 1
      `,
      [normalizedUserId]
    );
    return toUserRecord(rows[0]);
  };

  return {
    bumpSessionVersionAndConvergeSessionsTx
  };
};

module.exports = {
  createSharedMysqlAuthStoreSessionConvergenceRuntimeSupport
};
