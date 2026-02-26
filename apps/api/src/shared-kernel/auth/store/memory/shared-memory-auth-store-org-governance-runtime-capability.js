'use strict';

const { createHash } = require('node:crypto');

const createSharedMemoryAuthStoreOrgGovernanceRuntimeCapability = ({
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH,
  OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX
} = {}) => {
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

  const toOwnerTransferTakeoverRoleId = ({ orgId } = {}) => {
    const normalizedOrgId = String(orgId || '').trim();
    if (!normalizedOrgId) {
      return '';
    }
    const digest = createHash('sha256')
      .update(normalizedOrgId)
      .digest('hex')
      .slice(0, OWNER_TRANSFER_TAKEOVER_ROLE_ID_DIGEST_LENGTH);
    return `${OWNER_TRANSFER_TAKEOVER_ROLE_ID_PREFIX}${digest}`;
  };

  return {
    isActiveLikeStatus,
    normalizeOrgStatus,
    toOwnerTransferTakeoverRoleId
  };
};

module.exports = {
  createSharedMemoryAuthStoreOrgGovernanceRuntimeCapability
};
