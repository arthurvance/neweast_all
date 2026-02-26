'use strict';

const createPlatformMysqlAuthStoreRoleCatalogListUserIdsByPlatformRoleId = ({
  dbClient,
  normalizePlatformRoleCatalogRoleId
} = {}) => ({
listUserIdsByPlatformRoleId: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT user_id
          FROM platform_user_roles
          WHERE role_id = ?
          ORDER BY user_id ASC
        `,
        [normalizedRoleId]
      );
      return (Array.isArray(rows) ? rows : [])
        .map((row) => String(row?.user_id || '').trim())
        .filter((userId) => userId.length > 0);
    }
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalogListUserIdsByPlatformRoleId
};
