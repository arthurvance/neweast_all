'use strict';

const createPlatformMemoryAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover = ({
  KNOWN_TENANT_PERMISSION_CODE_SET,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  appendTenantUsershipHistory,
  buildEmptyTenantPermission,
  domainsByUserId,
  findPlatformRoleCatalogRecordStateByRoleId,
  findTenantUsershipStateByMembershipId,
  invokeFaultInjector,
  isActiveLikeStatus,
  listTenantRolePermissionGrantsForRoleId,
  listTenantUsershipRoleBindingsForMembershipId,
  normalizeOrgStatus,
  normalizePlatformRoleCatalogCode,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeTenantPermissionCodes,
  normalizeTenantUsershipStatusForRead,
  orgsById,
  persistAuditEvent,
  platformRoleCatalogById,
  platformRoleCatalogCodeIndex,
  randomUUID,
  refreshTokensByHash,
  replaceTenantRolePermissionGrantsForRoleId,
  replaceTenantUsershipRoleBindingsForMembershipId,
  sessionsById,
  syncTenantUsershipPermissionSnapshot,
  tenantRolePermissionGrantsByRoleId,
  tenantUsershipHistoryByPair,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId,
  toTenantUsershipScopeLabel,
  upsertPlatformRoleCatalogRecord,
  usersById
} = {}) => ({
executeOwnerTransferTakeover: async ({
      requestId = 'request_id_unset',
      orgId,
      oldOwnerUserId,
      newOwnerUserId,
      operatorUserId = null,
      operatorSessionId = null,
      reason = null,
      takeoverRoleId = 'sys_admin',
      takeoverRoleCode = 'sys_admin',
      takeoverRoleName = '管理员',
      requiredPermissionCodes = [],
      auditContext = null
    } = {}) => {
      const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOldOwnerUserId = String(oldOwnerUserId || '').trim();
      const normalizedNewOwnerUserId = String(newOwnerUserId || '').trim();
      const normalizedOperatorUserId = operatorUserId === null || operatorUserId === undefined
        ? null
        : String(operatorUserId || '').trim() || null;
      const normalizedOperatorSessionId =
        operatorSessionId === null || operatorSessionId === undefined
          ? null
          : String(operatorSessionId || '').trim() || null;
      const normalizedReason = reason === null || reason === undefined
        ? null
        : String(reason || '').trim() || null;
      const normalizedTakeoverRoleId = normalizePlatformRoleCatalogRoleId(
        takeoverRoleId
      );
      const normalizedTakeoverRoleCode = normalizePlatformRoleCatalogCode(
        takeoverRoleCode
      );
      const normalizedTakeoverRoleName = String(takeoverRoleName || '').trim();
      const normalizedRequiredPermissionCodes = normalizeTenantPermissionCodes(
        requiredPermissionCodes
      );
      const missingRequiredPermissionCodes = [
        TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
        TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
      ].filter(
        (permissionCode) =>
          !normalizedRequiredPermissionCodes.includes(permissionCode)
      );
      const hasUnsupportedRequiredPermissionCode = normalizedRequiredPermissionCodes.some(
        (permissionCode) =>
          !KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCode)
      );
      if (
        !normalizedOrgId
        || !normalizedOldOwnerUserId
        || !normalizedNewOwnerUserId
        || !normalizedTakeoverRoleId
        || !normalizedTakeoverRoleCode
        || !normalizedTakeoverRoleName
        || hasUnsupportedRequiredPermissionCode
        || missingRequiredPermissionCodes.length > 0
      ) {
        const invalidInputError = new Error(
          'executeOwnerTransferTakeover requires valid takeover payload'
        );
        invalidInputError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_INVALID_INPUT';
        throw invalidInputError;
      }

      const snapshot = {
        orgsById: structuredClone(orgsById),
        tenantsByUserId: structuredClone(tenantsByUserId),
        domainsByUserId: structuredClone(domainsByUserId),
        platformRoleCatalogById: structuredClone(platformRoleCatalogById),
        platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
        tenantRolePermissionGrantsByRoleId: structuredClone(
          tenantRolePermissionGrantsByRoleId
        ),
        tenantUsershipRolesByMembershipId: structuredClone(
          tenantUsershipRolesByMembershipId
        ),
        tenantUsershipHistoryByPair: structuredClone(tenantUsershipHistoryByPair),
        sessionsById: structuredClone(sessionsById),
        refreshTokensByHash: structuredClone(refreshTokensByHash)
      };
      const restoreMap = (target, source) => {
        target.clear();
        for (const [key, value] of source.entries()) {
          target.set(key, value);
        }
      };

      try {
        const org = orgsById.get(normalizedOrgId) || null;
        if (!org) {
          const orgNotFoundError = new Error(
            'owner transfer takeover organization not found'
          );
          orgNotFoundError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND';
          throw orgNotFoundError;
        }
        const currentOrgStatus = normalizeOrgStatus(org.status);
        const currentOwnerUserId = String(org.ownerUserId || '').trim();
        if (!isActiveLikeStatus(currentOrgStatus)) {
          const orgInactiveError = new Error(
            'owner transfer takeover organization not active'
          );
          orgInactiveError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_ACTIVE';
          throw orgInactiveError;
        }
        if (currentOwnerUserId !== normalizedOldOwnerUserId) {
          const preconditionFailedError = new Error(
            'owner transfer takeover precondition failed'
          );
          preconditionFailedError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PRECONDITION_FAILED';
          throw preconditionFailedError;
        }
        if (normalizedNewOwnerUserId === normalizedOldOwnerUserId) {
          const sameOwnerError = new Error(
            'owner transfer takeover new owner equals current owner'
          );
          sameOwnerError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SAME_OWNER';
          throw sameOwnerError;
        }

        const newOwner = usersById.get(normalizedNewOwnerUserId) || null;
        if (!newOwner) {
          const newOwnerNotFoundError = new Error(
            'owner transfer takeover new owner not found'
          );
          newOwnerNotFoundError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND';
          throw newOwnerNotFoundError;
        }
        if (
          !isActiveLikeStatus(
            String(newOwner?.status || '').trim().toLowerCase() || 'disabled'
          )
        ) {
          const newOwnerInactiveError = new Error(
            'owner transfer takeover new owner inactive'
          );
          newOwnerInactiveError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_INACTIVE';
          throw newOwnerInactiveError;
        }

        const createRoleInvalidError = () => {
          const roleInvalidError = new Error(
            'owner transfer takeover role definition invalid'
          );
          roleInvalidError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID';
          return roleInvalidError;
        };

        const existingRoleState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedTakeoverRoleId
        );
        const existingRole = existingRoleState?.record || null;
        if (!existingRole) {
          try {
            upsertPlatformRoleCatalogRecord({
              roleId: normalizedTakeoverRoleId,
              code: normalizedTakeoverRoleCode,
              name: normalizedTakeoverRoleName,
              status: 'active',
              scope: 'tenant',
              tenantId: normalizedOrgId,
              isSystem: true,
              createdByUserId: normalizedOperatorUserId,
              updatedByUserId: normalizedOperatorUserId
            });
          } catch (error) {
            if (String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY') {
              throw createRoleInvalidError();
            }
            throw error;
          }
        } else {
          const roleScope = normalizePlatformRoleCatalogScope(existingRole.scope);
          const roleTenantId = normalizePlatformRoleCatalogTenantId(
            existingRole.tenantId
          );
          const roleCode = normalizePlatformRoleCatalogCode(existingRole.code);
          if (roleScope !== 'tenant' || roleTenantId !== normalizedOrgId) {
            throw createRoleInvalidError();
          }
          if (
            !roleCode
            || roleCode.toLowerCase() !== normalizedTakeoverRoleCode.toLowerCase()
          ) {
            throw createRoleInvalidError();
          }
          const roleStatus = normalizePlatformRoleCatalogStatus(
            existingRole.status || 'disabled'
          );
          if (!isActiveLikeStatus(roleStatus)) {
            upsertPlatformRoleCatalogRecord({
              ...existingRole,
              roleId: normalizedTakeoverRoleId,
              status: 'active',
              updatedByUserId: normalizedOperatorUserId
            });
          }
        }

        const grantCodes = new Set(
          listTenantRolePermissionGrantsForRoleId(normalizedTakeoverRoleId)
        );
        for (const permissionCode of normalizedRequiredPermissionCodes) {
          grantCodes.add(permissionCode);
        }
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedTakeoverRoleId,
          permissionCodes: [...grantCodes]
        });

        org.ownerUserId = normalizedNewOwnerUserId;
        orgsById.set(normalizedOrgId, org);
        invokeFaultInjector('afterOwnerTransferTakeoverOwnerSwitch', {
          requestId: normalizedRequestId,
          orgId: normalizedOrgId,
          oldOwnerUserId: normalizedOldOwnerUserId,
          newOwnerUserId: normalizedNewOwnerUserId
        });

        const tenantUserships = tenantsByUserId.get(normalizedNewOwnerUserId) || [];
        let membership = tenantUserships.find(
          (item) => String(item?.tenantId || '').trim() === normalizedOrgId
        ) || null;
        if (!membership) {
          membership = {
            membershipId: randomUUID(),
            tenantId: normalizedOrgId,
            tenantName: null,
            status: 'active',
            displayName: null,
            departmentName: null,
            joinedAt: new Date().toISOString(),
            leftAt: null,
            permission: buildEmptyTenantPermission(
              `组织权限（${normalizedOrgId}）`
            )
          };
          tenantUserships.push(membership);
          tenantUsershipRolesByMembershipId.set(
            String(membership.membershipId || '').trim(),
            []
          );
        } else {
          const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
            membership.status
          );
          if (
            normalizedMembershipStatus !== 'active'
            && normalizedMembershipStatus !== 'disabled'
            && normalizedMembershipStatus !== 'left'
          ) {
            const membershipInvalidError = new Error(
              'owner transfer takeover membership status invalid'
            );
            membershipInvalidError.code =
              'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
            throw membershipInvalidError;
          }
          if (normalizedMembershipStatus === 'left') {
            appendTenantUsershipHistory({
              membership: {
                ...membership,
                userId: normalizedNewOwnerUserId,
                tenantId: normalizedOrgId
              },
              reason: 'rejoin',
              operatorUserId: normalizedOperatorUserId
            });
            const previousMembershipId = String(
              membership.membershipId || ''
            ).trim();
            membership.membershipId = randomUUID();
            membership.status = 'active';
            membership.leftAt = null;
            membership.joinedAt = new Date().toISOString();
            membership.permission = buildEmptyTenantPermission(
              toTenantUsershipScopeLabel(membership)
            );
            if (previousMembershipId) {
              tenantUsershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantUsershipRolesByMembershipId.set(
              String(membership.membershipId || '').trim(),
              []
            );
          } else if (normalizedMembershipStatus === 'disabled') {
            membership.status = 'active';
            membership.leftAt = null;
            membership.permission = buildEmptyTenantPermission(
              toTenantUsershipScopeLabel(membership)
            );
          }
        }
        tenantsByUserId.set(normalizedNewOwnerUserId, tenantUserships);

        const membershipId = String(membership?.membershipId || '').trim();
        if (!membershipId) {
          const membershipResolveError = new Error(
            'owner transfer takeover membership resolution failed'
          );
          membershipResolveError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
          throw membershipResolveError;
        }

        const userDomains = domainsByUserId.get(normalizedNewOwnerUserId) || new Set();
        userDomains.add('tenant');
        domainsByUserId.set(normalizedNewOwnerUserId, userDomains);

        const existingRoleIds = listTenantUsershipRoleBindingsForMembershipId({
          membershipId,
          tenantId: normalizedOrgId
        });
        const nextRoleIds = [...new Set([
          ...existingRoleIds,
          normalizedTakeoverRoleId
        ])].sort((left, right) => left.localeCompare(right));
        if (nextRoleIds.length < 1) {
          const roleBindingError = new Error(
            'owner transfer takeover role binding invalid'
          );
          roleBindingError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
          throw roleBindingError;
        }
        replaceTenantUsershipRoleBindingsForMembershipId({
          membershipId,
          roleIds: nextRoleIds
        });

        const membershipState = findTenantUsershipStateByMembershipId(
          membershipId
        );
        const syncResult = syncTenantUsershipPermissionSnapshot({
          membershipState,
          reason: 'owner-transfer-takeover'
        });
        const syncReason = String(syncResult?.reason || 'unknown')
          .trim()
          .toLowerCase();
        if (syncReason !== 'ok') {
          const syncError = new Error(
            `owner transfer takeover sync failed: ${syncReason || 'unknown'}`
          );
          syncError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SYNC_FAILED';
          syncError.syncReason = syncReason || 'unknown';
          throw syncError;
        }
        if (
          !Boolean(syncResult?.permission?.canViewUserManagement)
          || !Boolean(syncResult?.permission?.canOperateUserManagement)
          || !Boolean(syncResult?.permission?.canViewRoleManagement)
          || !Boolean(syncResult?.permission?.canOperateRoleManagement)
        ) {
          const permissionInsufficientError = new Error(
            'owner transfer takeover permission insufficient'
          );
          permissionInsufficientError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
          throw permissionInsufficientError;
        }

        invokeFaultInjector('beforeOwnerTransferTakeoverCommit', {
          requestId: normalizedRequestId,
          orgId: normalizedOrgId,
          membershipId
        });

        let auditRecorded = false;
        if (auditContext && typeof auditContext === 'object') {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.owner_transfer.executed',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || normalizedOperatorSessionId,
              targetType: 'org',
              targetId: normalizedOrgId,
              result: 'success',
              beforeState: {
                owner_user_id: normalizedOldOwnerUserId
              },
              afterState: {
                owner_user_id: normalizedNewOwnerUserId
              },
              metadata: {
                old_owner_user_id: normalizedOldOwnerUserId,
                new_owner_user_id: normalizedNewOwnerUserId,
                reason:
                  auditContext.reason === null || auditContext.reason === undefined
                    ? null
                    : String(auditContext.reason).trim() || null
              }
            });
          } catch (error) {
            const auditWriteError = new Error(
              'owner transfer takeover audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          org_id: normalizedOrgId,
          old_owner_user_id: normalizedOldOwnerUserId,
          new_owner_user_id: normalizedNewOwnerUserId,
          membership_id: membershipId,
          role_ids: nextRoleIds,
          permission_codes: listTenantRolePermissionGrantsForRoleId(
            normalizedTakeoverRoleId
          ),
          audit_recorded: auditRecorded
        };
      } catch (error) {
        restoreMap(orgsById, snapshot.orgsById);
        restoreMap(tenantsByUserId, snapshot.tenantsByUserId);
        restoreMap(domainsByUserId, snapshot.domainsByUserId);
        restoreMap(platformRoleCatalogById, snapshot.platformRoleCatalogById);
        restoreMap(platformRoleCatalogCodeIndex, snapshot.platformRoleCatalogCodeIndex);
        restoreMap(
          tenantRolePermissionGrantsByRoleId,
          snapshot.tenantRolePermissionGrantsByRoleId
        );
        restoreMap(
          tenantUsershipRolesByMembershipId,
          snapshot.tenantUsershipRolesByMembershipId
        );
        restoreMap(
          tenantUsershipHistoryByPair,
          snapshot.tenantUsershipHistoryByPair
        );
        restoreMap(sessionsById, snapshot.sessionsById);
        restoreMap(refreshTokensByHash, snapshot.refreshTokensByHash);
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover
};
