'use strict';

const createPlatformMemoryAuthStoreOrganizationGovernanceCreateOrganizationWithOwner = ({
  MAX_ORG_NAME_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
  OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
  OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
  appendTenantUsershipHistory,
  auditEvents,
  buildEmptyTenantPermission,
  createDataTooLongError,
  domainsByUserId,
  findPlatformRoleCatalogRecordStateByRoleId,
  findTenantUsershipStateByMembershipId,
  isActiveLikeStatus,
  listTenantRolePermissionGrantsForRoleId,
  listTenantUsershipRoleBindingsForMembershipId,
  membershipsByOrgId,
  normalizeOptionalTenantUserProfileField,
  normalizePlatformRoleCatalogCode,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeTenantUsershipStatusForRead,
  orgIdByName,
  orgsById,
  persistAuditEvent,
  platformRoleCatalogById,
  platformRoleCatalogCodeIndex,
  randomUUID,
  refreshTokensByHash,
  replaceTenantRolePermissionGrantsForRoleId,
  replaceTenantUsershipRoleBindingsForMembershipId,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  sessionsById,
  syncTenantUsershipPermissionSnapshot,
  tenantRolePermissionGrantsByRoleId,
  tenantUsershipHistoryByPair,
  tenantUsershipRolesByMembershipId,
  tenantsByUserId,
  toOwnerTransferTakeoverRoleId,
  toTenantUsershipScopeLabel,
  upsertPlatformRoleCatalogRecord,
  usersById
} = {}) => ({
createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerDisplayName = null,
      ownerUserId,
      operatorUserId,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = {
        orgsById: structuredClone(orgsById),
        orgIdByName: structuredClone(orgIdByName),
        membershipsByOrgId: structuredClone(membershipsByOrgId),
        tenantsByUserId: structuredClone(tenantsByUserId),
        tenantUsershipRolesByMembershipId: structuredClone(
          tenantUsershipRolesByMembershipId
        ),
        tenantUsershipHistoryByPair: structuredClone(tenantUsershipHistoryByPair),
        domainsByUserId: structuredClone(domainsByUserId),
        platformRoleCatalogById: structuredClone(platformRoleCatalogById),
        platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
        tenantRolePermissionGrantsByRoleId: structuredClone(
          tenantRolePermissionGrantsByRoleId
        ),
        sessionsById: structuredClone(sessionsById),
        refreshTokensByHash: structuredClone(refreshTokensByHash),
        auditEvents: structuredClone(auditEvents)
      };
      try {
        const normalizedOrgId = String(orgId || '').trim() || randomUUID();
        const normalizedOrgName = String(orgName || '').trim();
        const normalizedOwnerDisplayName = normalizeOptionalTenantUserProfileField({
          value: ownerDisplayName,
          maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
        });
        const normalizedOwnerUserId = String(ownerUserId || '').trim();
        const normalizedOperatorUserId = String(operatorUserId || '').trim();
        if (
          !normalizedOrgName
          || !normalizedOwnerUserId
          || !normalizedOperatorUserId
        ) {
          throw new Error(
            'createOrganizationWithOwner requires orgName, ownerUserId, and operatorUserId'
          );
        }
        if (!usersById.has(normalizedOwnerUserId) || !usersById.has(normalizedOperatorUserId)) {
          throw new Error('createOrganizationWithOwner requires existing owner and operator users');
        }
        if (normalizedOrgName.length > MAX_ORG_NAME_LENGTH) {
          throw createDataTooLongError();
        }

        const orgNameDedupeKey = normalizedOrgName.toLowerCase();
        if (orgIdByName.has(orgNameDedupeKey)) {
          const duplicateError = new Error('duplicate org name');
          duplicateError.code = 'ER_DUP_ENTRY';
          duplicateError.errno = 1062;
          throw duplicateError;
        }
        if (orgsById.has(normalizedOrgId)) {
          const duplicateError = new Error('duplicate org id');
          duplicateError.code = 'ER_DUP_ENTRY';
          duplicateError.errno = 1062;
          throw duplicateError;
        }

        const nowIso = new Date().toISOString();
        orgsById.set(normalizedOrgId, {
          id: normalizedOrgId,
          name: normalizedOrgName,
          ownerUserId: normalizedOwnerUserId,
          createdByUserId: normalizedOperatorUserId,
          status: 'active',
          createdAt: nowIso,
          updatedAt: nowIso
        });
        orgIdByName.set(orgNameDedupeKey, normalizedOrgId);
        membershipsByOrgId.set(normalizedOrgId, [
          {
            orgId: normalizedOrgId,
            userId: normalizedOwnerUserId,
            membershipRole: 'owner',
            status: 'active'
          }
        ]);
        const normalizedTakeoverRoleId = toOwnerTransferTakeoverRoleId({
          orgId: normalizedOrgId
        });
        const normalizedTakeoverRoleCode = OWNER_TRANSFER_TAKEOVER_ROLE_CODE;
        const normalizedTakeoverRoleName = OWNER_TRANSFER_TAKEOVER_ROLE_NAME;
        const normalizedRequiredPermissionCodes = [
          ...OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES
        ];
        if (
          !normalizedTakeoverRoleId
          || !normalizedTakeoverRoleCode
          || !normalizedTakeoverRoleName
        ) {
          throw new Error('org-owner-takeover-role-invalid');
        }

        const tenantUserships = Array.isArray(tenantsByUserId.get(normalizedOwnerUserId))
          ? tenantsByUserId.get(normalizedOwnerUserId)
          : [];
        let membership = tenantUserships.find(
          (tenant) => String(tenant?.tenantId || '').trim() === normalizedOrgId
        ) || null;
        if (!membership) {
          membership = {
            membershipId: randomUUID(),
            tenantId: normalizedOrgId,
            tenantName: normalizedOrgName,
            status: 'active',
            displayName: normalizedOwnerDisplayName,
            departmentName: null,
            joinedAt: nowIso,
            leftAt: null,
            permission: buildEmptyTenantPermission(
              `组织权限（${normalizedOrgName || normalizedOrgId}）`
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
            throw new Error('org-owner-membership-status-invalid');
          }
          membership.tenantName = normalizedOrgName;
          if (normalizedMembershipStatus === 'left') {
            appendTenantUsershipHistory({
              membership: {
                ...membership,
                userId: normalizedOwnerUserId,
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
            membership.permission = buildEmptyTenantPermission(
              toTenantUsershipScopeLabel(membership)
            );
            membership.joinedAt = nowIso;
            membership.leftAt = null;
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
          }
          if (normalizedOwnerDisplayName !== null) {
            membership.displayName = normalizedOwnerDisplayName;
          }
          if (!membership.joinedAt) {
            membership.joinedAt = nowIso;
          }
        }
        tenantsByUserId.set(normalizedOwnerUserId, tenantUserships);

        const resolvedMembershipId = String(membership?.membershipId || '').trim();
        if (!resolvedMembershipId) {
          throw new Error('org-owner-membership-resolution-failed');
        }

        const userDomains = domainsByUserId.get(normalizedOwnerUserId) || new Set();
        userDomains.add('tenant');
        domainsByUserId.set(normalizedOwnerUserId, userDomains);

        const createRoleInvalidError = () => {
          const roleInvalidError = new Error(
            'owner transfer takeover role definition invalid'
          );
          roleInvalidError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID';
          return roleInvalidError;
        };
        let existingRole = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedTakeoverRoleId
        )?.record || null;
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
              existingRole = findPlatformRoleCatalogRecordStateByRoleId(
                normalizedTakeoverRoleId
              )?.record || null;
              if (!existingRole) {
                throw createRoleInvalidError();
              }
            } else {
              throw error;
            }
          }
        }
        if (!existingRole) {
          existingRole = findPlatformRoleCatalogRecordStateByRoleId(
            normalizedTakeoverRoleId
          )?.record || null;
        }
        if (!existingRole) {
          throw createRoleInvalidError();
        }
        const normalizedRoleScope = normalizePlatformRoleCatalogScope(existingRole.scope);
        const normalizedRoleTenantId = normalizePlatformRoleCatalogTenantId(
          existingRole.tenantId
        );
        const normalizedRoleCode = normalizePlatformRoleCatalogCode(existingRole.code);
        if (
          normalizedRoleScope !== 'tenant'
          || normalizedRoleTenantId !== normalizedOrgId
        ) {
          throw createRoleInvalidError();
        }
        if (
          !normalizedRoleCode
          || normalizedRoleCode.toLowerCase() !== normalizedTakeoverRoleCode.toLowerCase()
        ) {
          throw createRoleInvalidError();
        }
        const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
          existingRole.status || 'disabled'
        );
        if (!isActiveLikeStatus(normalizedRoleStatus)) {
          upsertPlatformRoleCatalogRecord({
            ...existingRole,
            roleId: normalizedTakeoverRoleId,
            status: 'active',
            updatedByUserId: normalizedOperatorUserId
          });
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

        const existingRoleIds = listTenantUsershipRoleBindingsForMembershipId({
          membershipId: resolvedMembershipId,
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
          membershipId: resolvedMembershipId,
          roleIds: nextRoleIds
        });

        const membershipState = findTenantUsershipStateByMembershipId(
          resolvedMembershipId
        );
        const syncResult = syncTenantUsershipPermissionSnapshot({
          membershipState,
          reason: 'org-owner-bootstrap'
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
        const effectivePermission = syncResult?.permission || {};
        if (
          !Boolean(effectivePermission.canViewUserManagement)
          || !Boolean(effectivePermission.canOperateUserManagement)
          || !Boolean(effectivePermission.canViewRoleManagement)
          || !Boolean(effectivePermission.canOperateRoleManagement)
        ) {
          const permissionInsufficientError = new Error(
            'owner transfer takeover permission insufficient'
          );
          permissionInsufficientError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
          throw permissionInsufficientError;
        }

        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.create.succeeded',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || operatorSessionId,
              targetType: 'org',
              targetId: normalizedOrgId,
              result: 'success',
              beforeState: null,
              afterState: {
                org_id: normalizedOrgId,
                org_name: normalizedOrgName,
                owner_user_id: normalizedOwnerUserId
              },
              metadata: {
                operator_user_id: normalizedOperatorUserId
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error('organization create audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }

        return {
          org_id: normalizedOrgId,
          owner_user_id: normalizedOwnerUserId,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        restoreMapFromSnapshot(orgsById, snapshot.orgsById);
        restoreMapFromSnapshot(orgIdByName, snapshot.orgIdByName);
        restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
        restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
        restoreMapFromSnapshot(
          tenantUsershipRolesByMembershipId,
          snapshot.tenantUsershipRolesByMembershipId
        );
        restoreMapFromSnapshot(
          tenantUsershipHistoryByPair,
          snapshot.tenantUsershipHistoryByPair
        );
        restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
        restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
        restoreMapFromSnapshot(
          platformRoleCatalogCodeIndex,
          snapshot.platformRoleCatalogCodeIndex
        );
        restoreMapFromSnapshot(
          tenantRolePermissionGrantsByRoleId,
          snapshot.tenantRolePermissionGrantsByRoleId
        );
        restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
        restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
        restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreOrganizationGovernanceCreateOrganizationWithOwner
};
