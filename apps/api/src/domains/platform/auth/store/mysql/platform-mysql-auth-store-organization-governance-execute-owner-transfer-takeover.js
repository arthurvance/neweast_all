'use strict';

const createPlatformMysqlAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover = ({
  KNOWN_TENANT_PERMISSION_CODE_SET,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  dbClient,
  ensureTenantDomainAccessForUserTx,
  executeWithDeadlockRetry,
  insertTenantUsershipHistoryTx,
  isActiveLikeStatus,
  isDuplicateEntryError,
  listTenantUsershipRoleBindingsTx,
  normalizeOrgStatus,
  normalizePlatformRoleCatalogCode,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeStrictTenantPermissionCodeFromGrantRow,
  normalizeTenantPermissionCodes,
  normalizeTenantUsershipRoleIds,
  normalizeTenantUsershipStatusForRead,
  normalizeUserStatus,
  randomUUID,
  recordAuditEventWithQueryClient,
  syncTenantUsershipPermissionSnapshotInTx
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
      const normalizedTakeoverRoleCode = String(takeoverRoleCode || '').trim();
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

      return executeWithDeadlockRetry({
        operation: 'executeOwnerTransferTakeover',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const orgRows = await tx.query(
              `
                SELECT id, status, owner_user_id
                FROM tenants
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOrgId]
            );
            const orgRow = orgRows?.[0] || null;
            if (!orgRow) {
              const orgNotFoundError = new Error(
                'owner transfer takeover organization not found'
              );
              orgNotFoundError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND';
              throw orgNotFoundError;
            }

            const currentOwnerUserId = String(orgRow.owner_user_id || '').trim();
            const currentOrgStatus = normalizeOrgStatus(orgRow.status);
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

            const newOwnerRows = await tx.query(
              `
                SELECT id, status
                FROM iam_users
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedNewOwnerUserId]
            );
            const newOwnerRow = newOwnerRows?.[0] || null;
            if (!newOwnerRow) {
              const newOwnerNotFoundError = new Error(
                'owner transfer takeover new owner not found'
              );
              newOwnerNotFoundError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND';
              throw newOwnerNotFoundError;
            }
            if (!isActiveLikeStatus(normalizeUserStatus(newOwnerRow.status))) {
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

            let roleRows = await tx.query(
              `
                SELECT role_id, tenant_id, code, status, scope
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedTakeoverRoleId]
            );
            let roleRow = roleRows?.[0] || null;
            if (!roleRow) {
              try {
                await tx.query(
                  `
                    INSERT INTO platform_roles (
                      role_id,
                      tenant_id,
                      code,
                      code_normalized,
                      name,
                      status,
                      scope,
                      is_system,
                      created_by_user_id,
                      updated_by_user_id
                    )
                    VALUES (?, ?, ?, ?, ?, 'active', 'tenant', 1, ?, ?)
                  `,
                  [
                    normalizedTakeoverRoleId,
                    normalizedOrgId,
                    normalizedTakeoverRoleCode,
                    normalizedTakeoverRoleCode.toLowerCase(),
                    normalizedTakeoverRoleName,
                    normalizedOperatorUserId,
                    normalizedOperatorUserId
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
                roleRows = await tx.query(
                  `
                    SELECT role_id, tenant_id, code, status, scope
                    FROM platform_roles
                    WHERE role_id = ?
                    LIMIT 1
                    FOR UPDATE
                  `,
                  [normalizedTakeoverRoleId]
                );
                roleRow = roleRows?.[0] || null;
                if (!roleRow) {
                  throw createRoleInvalidError();
                }
              }
            }
            if (!roleRow) {
              roleRow = {
                role_id: normalizedTakeoverRoleId,
                tenant_id: normalizedOrgId,
                code: normalizedTakeoverRoleCode,
                status: 'active',
                scope: 'tenant'
              };
            }
            const normalizedRoleScope = normalizePlatformRoleCatalogScope(
              roleRow.scope
            );
            const normalizedRoleTenantId = normalizePlatformRoleCatalogTenantId(
              roleRow.tenant_id
            );
            const normalizedRoleCode = normalizePlatformRoleCatalogCode(
              roleRow.code
            );
            if (
              normalizedRoleScope !== 'tenant'
              || normalizedRoleTenantId !== normalizedOrgId
            ) {
              throw createRoleInvalidError();
            }
            if (
              !normalizedRoleCode
              || normalizedRoleCode.toLowerCase()
              !== normalizedTakeoverRoleCode.toLowerCase()
            ) {
              throw createRoleInvalidError();
            }
            const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
              roleRow.status || 'disabled'
            );
            if (!isActiveLikeStatus(normalizedRoleStatus)) {
              await tx.query(
                `
                  UPDATE platform_roles
                  SET status = 'active',
                      updated_by_user_id = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE role_id = ?
                `,
                [normalizedOperatorUserId, normalizedTakeoverRoleId]
              );
            }

            const existingGrantRows = await tx.query(
              `
                SELECT permission_code
                FROM tenant_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
                FOR UPDATE
              `,
              [normalizedTakeoverRoleId]
            );
            const normalizedGrantSet = new Set();
            for (const row of Array.isArray(existingGrantRows)
              ? existingGrantRows
              : []) {
              normalizedGrantSet.add(
                normalizeStrictTenantPermissionCodeFromGrantRow(
                  row?.permission_code,
                  'owner-transfer-takeover-role-grants-invalid'
                )
              );
            }
            for (const permissionCode of normalizedRequiredPermissionCodes) {
              if (normalizedGrantSet.has(permissionCode)) {
                continue;
              }
              await tx.query(
                `
                  INSERT INTO tenant_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedTakeoverRoleId,
                  permissionCode,
                  normalizedOperatorUserId,
                  normalizedOperatorUserId
                ]
              );
              normalizedGrantSet.add(permissionCode);
            }

            let membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status,
                       tenant_name,
                       can_view_user_management,
                       can_operate_user_management,
                       can_view_role_management,
                       can_operate_role_management,
                       joined_at,
                       left_at
                FROM tenant_memberships
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedNewOwnerUserId, normalizedOrgId]
            );
            let membershipRow = membershipRows?.[0] || null;
            let resolvedMembershipId = String(
              membershipRow?.membership_id || ''
            ).trim();
            if (!membershipRow) {
              const createdMembershipId = randomUUID();
              let insertedMembership = null;
              try {
                insertedMembership = await tx.query(
                  `
                    INSERT INTO tenant_memberships (
                      membership_id,
                      user_id,
                      tenant_id,
                      tenant_name,
                      status,
                      joined_at,
                      left_at
                    )
                    VALUES (?, ?, ?, ?, 'active', CURRENT_TIMESTAMP(3), NULL)
                  `,
                  [
                    createdMembershipId,
                    normalizedNewOwnerUserId,
                    normalizedOrgId,
                    null
                  ]
                );
              } catch (error) {
                if (!isDuplicateEntryError(error)) {
                  throw error;
                }
              }
              if (
                insertedMembership
                && Number(insertedMembership?.affectedRows || 0) !== 1
              ) {
                const membershipCreateError = new Error(
                  'owner transfer takeover membership write not applied'
                );
                membershipCreateError.code =
                  'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_WRITE_NOT_APPLIED';
                throw membershipCreateError;
              }
              membershipRows = await tx.query(
                `
                  SELECT membership_id,
                         user_id,
                         tenant_id,
                         status,
                         tenant_name,
                         can_view_user_management,
                         can_operate_user_management,
                         can_view_role_management,
                         can_operate_role_management,
                         joined_at,
                         left_at
                  FROM tenant_memberships
                  WHERE user_id = ? AND tenant_id = ?
                  LIMIT 1
                  FOR UPDATE
                `,
                [normalizedNewOwnerUserId, normalizedOrgId]
              );
              membershipRow = membershipRows?.[0] || null;
            } else {
              const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
                membershipRow.status
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
                const previousMembershipId = String(
                  membershipRow.membership_id || ''
                ).trim();
                await insertTenantUsershipHistoryTx({
                  txClient: tx,
                  row: {
                    ...membershipRow,
                    membership_id: previousMembershipId,
                    user_id: normalizedNewOwnerUserId,
                    tenant_id: normalizedOrgId
                  },
                  archivedReason: 'rejoin',
                  archivedByUserId: normalizedOperatorUserId
                });
                await tx.query(
                  `
                    DELETE FROM tenant_membership_roles
                    WHERE membership_id = ?
                  `,
                  [previousMembershipId]
                );
                const nextMembershipId = randomUUID();
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET membership_id = ?,
                        status = 'active',
                        can_view_user_management = 0,
                        can_operate_user_management = 0,
                        can_view_role_management = 0,
                        can_operate_role_management = 0,
                        joined_at = CURRENT_TIMESTAMP(3),
                        left_at = NULL,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ? AND tenant_id = ?
                  `,
                  [
                    nextMembershipId,
                    normalizedNewOwnerUserId,
                    normalizedOrgId
                  ]
                );
              } else if (normalizedMembershipStatus === 'disabled') {
                await tx.query(
                  `
                    UPDATE tenant_memberships
                    SET status = 'active',
                        left_at = NULL,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ? AND tenant_id = ?
                  `,
                  [normalizedNewOwnerUserId, normalizedOrgId]
                );
              }
              membershipRows = await tx.query(
                `
                  SELECT membership_id,
                         user_id,
                         tenant_id,
                         status,
                         tenant_name,
                         can_view_user_management,
                         can_operate_user_management,
                         can_view_role_management,
                         can_operate_role_management,
                         joined_at,
                         left_at
                  FROM tenant_memberships
                  WHERE user_id = ? AND tenant_id = ?
                  LIMIT 1
                  FOR UPDATE
                `,
                [normalizedNewOwnerUserId, normalizedOrgId]
              );
              membershipRow = membershipRows?.[0] || null;
            }

            resolvedMembershipId = String(
              membershipRow?.membership_id || ''
            ).trim();
            if (
              !membershipRow
              || !resolvedMembershipId
              || String(membershipRow?.user_id || '').trim()
              !== normalizedNewOwnerUserId
            ) {
              const membershipResolveError = new Error(
                'owner transfer takeover membership resolution failed'
              );
              membershipResolveError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
              throw membershipResolveError;
            }

            await ensureTenantDomainAccessForUserTx({
              txClient: tx,
              userId: normalizedNewOwnerUserId,
              skipMembershipCheck: true
            });

            const ownerSwitchResult = await tx.query(
              `
                UPDATE tenants
                SET owner_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE BINARY id = ?
              `,
              [normalizedNewOwnerUserId, normalizedOrgId]
            );
            if (Number(ownerSwitchResult?.affectedRows || 0) !== 1) {
              const ownerSwitchError = new Error(
                'owner transfer takeover owner switch write not applied'
              );
              ownerSwitchError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_OWNER_SWITCH_NOT_APPLIED';
              throw ownerSwitchError;
            }

            const existingRoleIds = await listTenantUsershipRoleBindingsTx({
              txClient: tx,
              membershipId: resolvedMembershipId
            });
            const nextRoleIds = normalizeTenantUsershipRoleIds([
              ...existingRoleIds,
              normalizedTakeoverRoleId
            ]);
            if (nextRoleIds.length < 1) {
              const roleBindingError = new Error(
                'owner transfer takeover role binding invalid'
              );
              roleBindingError.code =
                'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
              throw roleBindingError;
            }
            await tx.query(
              `
                DELETE FROM tenant_membership_roles
                WHERE membership_id = ?
              `,
              [resolvedMembershipId]
            );
            for (const roleId of nextRoleIds) {
              await tx.query(
                `
                  INSERT INTO tenant_membership_roles (
                    membership_id,
                    role_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  resolvedMembershipId,
                  roleId,
                  normalizedOperatorUserId,
                  normalizedOperatorUserId
                ]
              );
            }

            const syncResult = await syncTenantUsershipPermissionSnapshotInTx({
              txClient: tx,
              membershipId: resolvedMembershipId,
              tenantId: normalizedOrgId,
              roleIds: nextRoleIds,
              revokeReason: 'owner-transfer-takeover'
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

            const resolvedPermissionCodes = [...normalizedGrantSet]
              .filter((permissionCode) =>
                KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCode)
              )
              .sort((left, right) => left.localeCompare(right));
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: 'tenant',
                  tenantId: normalizedOrgId,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.org.owner_transfer.executed',
                  actorUserId: auditContext.actorUserId,
                  actorSessionId: auditContext.actorSessionId,
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
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error(
                  'owner transfer takeover audit write failed'
                );
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              org_id: normalizedOrgId,
              old_owner_user_id: normalizedOldOwnerUserId,
              new_owner_user_id: normalizedNewOwnerUserId,
              membership_id: resolvedMembershipId,
              role_ids: nextRoleIds,
              permission_codes: resolvedPermissionCodes,
              audit_recorded: auditRecorded
            };
          })
      });
    }
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernanceExecuteOwnerTransferTakeover
};
