'use strict';

const createSharedMysqlAuthStoreRepositoryUserIdentityRead = ({
  dbClient,
  toUserRecord,
  isDuplicateEntryError,
  MAINLAND_PHONE_PATTERN,
  CONTROL_CHAR_PATTERN
} = {}) => ({
  findUserByPhone: async (phone) => {
    const rows = await dbClient.query(
      `
        SELECT id, phone, password_hash, status, session_version
        FROM iam_users
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
        FROM iam_users
        WHERE id = ?
        LIMIT 1
      `,
      [userId]
    );
    return toUserRecord(rows[0]);
  },

  updateUserPhone: async ({
    userId,
    phone
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedPhone = String(phone || '').trim();
    if (
      !normalizedUserId
      || !normalizedPhone
      || !MAINLAND_PHONE_PATTERN.test(normalizedPhone)
      || CONTROL_CHAR_PATTERN.test(normalizedPhone)
    ) {
      throw new Error('updateUserPhone requires valid userId and mainland phone');
    }

    try {
      const updateResult = await dbClient.query(
        `
          UPDATE iam_users
          SET phone = ?
          WHERE id = ?
          LIMIT 1
        `,
        [normalizedPhone, normalizedUserId]
      );
      const affectedRows = Number(updateResult?.affectedRows || 0);
      if (affectedRows >= 1) {
        return {
          reason: 'ok',
          user_id: normalizedUserId,
          phone: normalizedPhone
        };
      }

      const rows = await dbClient.query(
        `
          SELECT phone
          FROM iam_users
          WHERE id = ?
          LIMIT 1
        `,
        [normalizedUserId]
      );
      const row = rows?.[0];
      if (!row) {
        return {
          reason: 'invalid-user-id'
        };
      }
      const currentPhone = String(row.phone || '').trim();
      if (currentPhone === normalizedPhone) {
        return {
          reason: 'no-op',
          user_id: normalizedUserId,
          phone: normalizedPhone
        };
      }
      return {
        reason: 'unknown'
      };
    } catch (error) {
      if (isDuplicateEntryError(error)) {
        return {
          reason: 'phone-conflict'
        };
      }
      throw error;
    }
  },
});

module.exports = {
  createSharedMysqlAuthStoreRepositoryUserIdentityRead
};
