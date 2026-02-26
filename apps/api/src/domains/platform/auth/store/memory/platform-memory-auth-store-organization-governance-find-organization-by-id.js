'use strict';

const createPlatformMemoryAuthStoreOrganizationGovernanceFindOrganizationById = ({
  normalizeOrgStatus,
  orgsById
} = {}) => ({
findOrganizationById: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return null;
      }
      const org = orgsById.get(normalizedOrgId);
      if (!org) {
        return null;
      }
      return {
        org_id: normalizedOrgId,
        org_name: String(org.name || '').trim(),
        owner_user_id: String(org.ownerUserId || '').trim(),
        status: normalizeOrgStatus(org.status),
        created_by_user_id: org.createdByUserId
          ? String(org.createdByUserId).trim()
          : null
      };
    }
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernanceFindOrganizationById
};
