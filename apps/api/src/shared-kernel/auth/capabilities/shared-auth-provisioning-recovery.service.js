'use strict';

const createSharedAuthProvisioningRecoveryCapabilities = ({
  authStore,
  log,
  getDomainAccessForUser,
  getTenantOptionsForUser
} = {}) => {
  const rollbackProvisionedUser = async ({
    requestId,
    userId,
    strict = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId || typeof authStore?.deleteUserById !== 'function') {
      if (strict) {
        throw new Error('rollback-provisioned-user-capability-unavailable');
      }
      return {
        rolledBack: false,
        reason: 'rollback-capability-unavailable'
      };
    }

    try {
      const domainAccess = await getDomainAccessForUser(normalizedUserId);
      if (domainAccess.platform || domainAccess.tenant) {
        if (strict) {
          throw new Error('rollback-skipped-user-has-domain-access');
        }
        return {
          rolledBack: false,
          reason: 'rollback-skipped-user-has-domain-access'
        };
      }

      const tenantOptions = await getTenantOptionsForUser(normalizedUserId);
      if (tenantOptions.length > 0) {
        if (strict) {
          throw new Error('rollback-skipped-user-has-tenant-options');
        }
        return {
          rolledBack: false,
          reason: 'rollback-skipped-user-has-tenant-options'
        };
      }

      if (typeof authStore.hasAnyTenantRelationshipByUserId === 'function') {
        const hasAnyTenantRelationship = await authStore.hasAnyTenantRelationshipByUserId(
          normalizedUserId
        );
        if (hasAnyTenantRelationship) {
          if (strict) {
            throw new Error('rollback-skipped-user-has-tenant-relationship');
          }
          return {
            rolledBack: false,
            reason: 'rollback-skipped-user-has-tenant-relationship'
          };
        }
      }
    } catch (rollbackGuardError) {
      log(
        'warn',
        'Skipped rollback for provisioned user after conflict due to guard check failure',
        {
          request_id: requestId || 'request_id_unset',
          user_id: normalizedUserId,
          reason: String(rollbackGuardError?.message || 'unknown')
        }
      );
      if (strict) {
        throw rollbackGuardError;
      }
      return {
        rolledBack: false,
        reason: 'rollback-guard-check-failed'
      };
    }

    try {
      const rollbackResult = await authStore.deleteUserById(normalizedUserId);
      const rollbackDeleteApplied =
        rollbackResult
        && typeof rollbackResult === 'object'
        && rollbackResult.deleted === true;
      if (!rollbackDeleteApplied) {
        const rollbackReason =
          rollbackResult
          && typeof rollbackResult === 'object'
          && rollbackResult.deleted === false
            ? 'rollback-not-deleted'
            : 'rollback-delete-result-invalid';
        const rollbackNotAppliedError = new Error(
          rollbackReason === 'rollback-not-deleted'
            ? 'rollback-provisioned-user-not-deleted'
            : 'rollback-provisioned-user-delete-result-invalid'
        );
        if (strict) {
          throw rollbackNotAppliedError;
        }
        return {
          rolledBack: false,
          reason: rollbackReason
        };
      }
      return {
        rolledBack: true,
        reason: 'deleted'
      };
    } catch (rollbackError) {
      log('warn', 'Failed to rollback provisioned user after conflict', {
        request_id: requestId || 'request_id_unset',
        user_id: normalizedUserId,
        reason: String(rollbackError?.message || 'unknown')
      });
      if (strict) {
        throw rollbackError;
      }
      return {
        rolledBack: false,
        reason: 'rollback-delete-failed'
      };
    }
  };

  const rollbackProvisionedUserIdentity = async ({ requestId, userId }) =>
    rollbackProvisionedUser({
      requestId,
      userId,
      strict: true
    });

  return {
    rollbackProvisionedUser,
    rollbackProvisionedUserIdentity
  };
};

module.exports = {
  createSharedAuthProvisioningRecoveryCapabilities
};
