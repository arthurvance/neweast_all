'use strict';

const createPlatformMysqlAuthStoreOrganizationGovernanceCreateOrganizationWithOwner = ({
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  OWNER_TRANSFER_TAKEOVER_REQUIRED_PERMISSION_CODES,
  OWNER_TRANSFER_TAKEOVER_ROLE_CODE,
  OWNER_TRANSFER_TAKEOVER_ROLE_NAME,
  dbClient,
  ensureTenantDomainAccessForUserTx,
  executeWithDeadlockRetry,
  insertTenantUsershipHistoryTx,
  isActiveLikeStatus,
  isDuplicateEntryError,
  listTenantUsershipRoleBindingsTx,
  normalizeAuditStringOrNull,
  normalizeOptionalTenantUserProfileField,
  normalizeOrgName,
  normalizePlatformRoleCatalogCode,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizeStrictTenantPermissionCodeFromGrantRow,
  normalizeTenantUsershipRoleIds,
  normalizeTenantUsershipStatusForRead,
  randomUUID,
  recordAuditEventWithQueryClient,
  syncTenantUsershipPermissionSnapshotInTx,
  toOwnerTransferTakeoverRoleId
} = {}) => ({
createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerDisplayName = null,
      ownerUserId,
      operatorUserId,
      operatorSessionId = null,
      auditContext = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'createOrganizationWithOwner',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedOrgId = String(orgId || '').trim() || randomUUID();
            const normalizedOrgName = normalizeOrgName(orgName);
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

            const insertOrgResult = await tx.query(
              `
                INSERT INTO tenants (id, name, owner_user_id, status, created_by_user_id)
                VALUES (?, ?, ?, 'active', ?)
              `,
              [
                normalizedOrgId,
                normalizedOrgName,
                normalizedOwnerUserId,
                normalizedOperatorUserId
              ]
            );
            if (Number(insertOrgResult?.affectedRows || 0) !== 1) {
              throw new Error('org-create-write-not-applied');
            }

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
            const ownerMembershipUpsertResult = await tx.query(
              `
                INSERT INTO tenant_memberships (
                  membership_id,
                  user_id,
                  tenant_id,
                  tenant_name,
                  status,
                  display_name,
                  department_name,
                  joined_at,
                  left_at
                )
                VALUES (?, ?, ?, ?, 'active', ?, NULL, CURRENT_TIMESTAMP(3), NULL)
                ON DUPLICATE KEY UPDATE
                  tenant_name = VALUES(tenant_name),
                  status = 'active',
                  display_name = CASE
                    WHEN VALUES(display_name) IS NULL THEN display_name
                    ELSE VALUES(display_name)
                  END,
                  left_at = NULL,
                  updated_at = CURRENT_TIMESTAMP(3)
              `,
              [
                randomUUID(),
                normalizedOwnerUserId,
                normalizedOrgId,
                normalizedOrgName,
                normalizedOwnerDisplayName
              ]
            );
            if (Number(ownerMembershipUpsertResult?.affectedRows || 0) <= 0) {
              throw new Error('org-owner-profile-write-not-applied');
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
              [normalizedOwnerUserId, normalizedOrgId]
            );
            let membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              throw new Error('org-owner-membership-missing');
            }
            const normalizedMembershipStatus = normalizeTenantUsershipStatusForRead(
              membershipRow.status
            );
            if (
              normalizedMembershipStatus !== 'active'
              && normalizedMembershipStatus !== 'disabled'
              && normalizedMembershipStatus !== 'left'
            ) {
              throw new Error('org-owner-membership-status-invalid');
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
                  user_id: normalizedOwnerUserId,
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
                      display_name = CASE
                        WHEN ? IS NULL THEN display_name
                        ELSE ?
                      END,
                      joined_at = CURRENT_TIMESTAMP(3),
                      left_at = NULL,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ? AND tenant_id = ?
                `,
                [
                  nextMembershipId,
                  normalizedOwnerDisplayName,
                  normalizedOwnerDisplayName,
                  normalizedOwnerUserId,
                  normalizedOrgId
                ]
              );
            } else if (normalizedMembershipStatus === 'disabled') {
              await tx.query(
                `
                  UPDATE tenant_memberships
                  SET status = 'active',
                      display_name = CASE
                        WHEN ? IS NULL THEN display_name
                        ELSE ?
                      END,
                      left_at = NULL,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ? AND tenant_id = ?
                `,
                [
                  normalizedOwnerDisplayName,
                  normalizedOwnerDisplayName,
                  normalizedOwnerUserId,
                  normalizedOrgId
                ]
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
              [normalizedOwnerUserId, normalizedOrgId]
            );
            membershipRow = membershipRows?.[0] || null;
            const resolvedMembershipId = String(
              membershipRow?.membership_id || ''
            ).trim();
            if (
              !membershipRow
              || !resolvedMembershipId
              || String(membershipRow?.user_id || '').trim() !== normalizedOwnerUserId
            ) {
              throw new Error('org-owner-membership-resolution-failed');
            }

            await ensureTenantDomainAccessForUserTx({
              txClient: tx,
              userId: normalizedOwnerUserId,
              skipMembershipCheck: true
            });

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
              || normalizedRoleCode.toLowerCase() !== normalizedTakeoverRoleCode.toLowerCase()
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
              revokeReason: 'org-owner-bootstrap'
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
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
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
                    org_name: normalizeAuditStringOrNull(normalizedOrgName, 128),
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
          })
      })
});

module.exports = {
  createPlatformMysqlAuthStoreOrganizationGovernanceCreateOrganizationWithOwner
};
