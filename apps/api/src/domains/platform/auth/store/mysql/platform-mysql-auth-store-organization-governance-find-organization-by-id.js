'use strict';

const createPlatformMysqlAuthStoreOrganizationGovernanceFindOrganizationById = ({
  dbClient,
  normalizeOrgStatus
} = {}) => ({
findOrganizationById: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT id, name, owner_user_id, status, created_by_user_id
          FROM tenants
          WHERE BINARY id = ?
          LIMIT 1
        `,
        [normalizedOrgId]
      );
      const org = rows?.[0] || null;
      if (!org) {
        return null;
      }
      return {
        org_id: String(org.id || '').trim(),
        org_name: String(org.name || '').trim(),
        owner_user_id: String(org.owner_user_id || '').trim(),
        status: normalizeOrgStatus(org.status),
        created_by_user_id: org.created_by_user_id
          ? String(org.created_by_user_id).trim()
          : null
      };
    }
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernanceFindOrganizationById
};
