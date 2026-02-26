'use strict';

const createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipProfile = ({
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  dbClient,
  executeWithDeadlockRetry,
  isStrictMainlandPhone,
  isStrictOptionalTenantUserProfileField,
  normalizeOptionalTenantUserProfileField,
  normalizeTenantUsershipStatusForRead,
  resolveOptionalTenantUserProfileField
} = {}) => ({
updateTenantUsershipProfile: async ({
      membershipId,
      tenantId,
      displayName,
      departmentNameProvided = false,
      departmentName = null,
      operatorUserId = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateTenantUsershipProfile',
        onExhausted: 'throw',
        execute: async () => {
          const normalizedMembershipId = String(membershipId || '').trim();
          const normalizedTenantId = String(tenantId || '').trim();
          const normalizedDisplayName = normalizeOptionalTenantUserProfileField({
            value: displayName,
            maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
          });
          const normalizedOperatorUserId = String(operatorUserId || '').trim() || null;
          if (
            !normalizedMembershipId
            || !normalizedTenantId
            || normalizedDisplayName === null
          ) {
            throw new Error(
              'updateTenantUsershipProfile requires membershipId, tenantId and displayName'
            );
          }

          const shouldUpdateDepartmentName = departmentNameProvided === true;
          let normalizedDepartmentName = null;
          if (shouldUpdateDepartmentName) {
            if (departmentName === null) {
              normalizedDepartmentName = null;
            } else {
              normalizedDepartmentName = normalizeOptionalTenantUserProfileField({
                value: departmentName,
                maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
              });
              if (normalizedDepartmentName === null) {
                throw new Error('updateTenantUsershipProfile departmentName is invalid');
              }
            }
          }

          return dbClient.inTransaction(async (tx) => {
            const membershipRows = await tx.query(
              `
                SELECT ut.membership_id,
                       ut.department_name,
                       u.phone
                FROM tenant_memberships ut
                LEFT JOIN iam_users u ON u.id = ut.user_id
                WHERE ut.membership_id = ? AND ut.tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              return null;
            }
            if (!isStrictMainlandPhone(membershipRow.phone)) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: user-profile-missing'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }
            if (
              !shouldUpdateDepartmentName
              && !isStrictOptionalTenantUserProfileField({
                value: membershipRow.department_name,
                maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
              })
            ) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: membership-profile-invalid'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }

            const updateResult = await tx.query(
              `
                UPDATE tenant_memberships
                SET display_name = ?,
                    department_name = CASE
                      WHEN ? = 1 THEN ?
                      ELSE department_name
                    END,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE membership_id = ? AND tenant_id = ?
              `,
              [
                normalizedDisplayName,
                shouldUpdateDepartmentName ? 1 : 0,
                shouldUpdateDepartmentName ? normalizedDepartmentName : null,
                normalizedMembershipId,
                normalizedTenantId
              ]
            );
            if (Number(updateResult?.affectedRows || 0) !== 1) {
              return null;
            }

            const rows = await tx.query(
              `
                SELECT ut.membership_id,
                       ut.user_id,
                       ut.tenant_id,
                       ut.tenant_name,
                       ut.status,
                       ut.display_name,
                       ut.department_name,
                       ut.joined_at,
                       ut.left_at,
                       u.phone
                FROM tenant_memberships ut
                LEFT JOIN iam_users u ON u.id = ut.user_id
                WHERE ut.membership_id = ? AND ut.tenant_id = ?
                LIMIT 1
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const row = rows?.[0] || null;
            if (!row) {
              return null;
            }
            if (!isStrictMainlandPhone(row.phone)) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: user-profile-missing'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }
            if (!isStrictOptionalTenantUserProfileField({
              value: row.department_name,
              maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
            })) {
              const dependencyError = new Error(
                'updateTenantUsershipProfile dependency unavailable: membership-profile-invalid'
              );
              dependencyError.code =
                'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
              throw dependencyError;
            }
            return {
              membership_id: String(row.membership_id || '').trim(),
              user_id: String(row.user_id || '').trim(),
              tenant_id: String(row.tenant_id || '').trim(),
              tenant_name: row.tenant_name ? String(row.tenant_name) : null,
              phone: String(row.phone || ''),
              status: normalizeTenantUsershipStatusForRead(row.status),
              display_name: resolveOptionalTenantUserProfileField(
                row.display_name
              ),
              department_name: resolveOptionalTenantUserProfileField(
                row.department_name
              ),
              joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
              left_at: row.left_at ? new Date(row.left_at).toISOString() : null,
              updated_by_user_id: normalizedOperatorUserId
            };
          });
        }
      })
});

module.exports = {
  createTenantMysqlAuthStoreUsershipGovernanceUpdateTenantUsershipProfile
};
