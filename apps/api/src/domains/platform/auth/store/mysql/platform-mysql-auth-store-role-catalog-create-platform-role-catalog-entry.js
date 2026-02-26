'use strict';

const createPlatformMysqlAuthStoreRoleCatalogCreatePlatformRoleCatalogEntry = ({
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  dbClient,
  executeWithDeadlockRetry,
  normalizeAuditStringOrNull,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantIdForScope,
  recordAuditEventWithQueryClient,
  toPlatformRoleCatalogRecord
} = {}) => ({
createPlatformRoleCatalogEntry: async ({
      roleId,
      code,
      name,
      status = 'active',
      scope = 'platform',
      tenantId = null,
      isSystem = false,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      const normalizedCode = String(code || '').trim();
      const normalizedName = String(name || '').trim();
      const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      if (
        !normalizedRoleId
        || !normalizedCode
        || !normalizedName
        || !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
        || !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
      ) {
        throw new Error('createPlatformRoleCatalogEntry received invalid input');
      }

      return executeWithDeadlockRetry({
        operation: 'createPlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
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
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `,
              [
                normalizedRoleId,
                normalizedTenantId,
                normalizedCode,
                normalizedCode.toLowerCase(),
                normalizedName,
                normalizedStatus,
                normalizedScope,
                Number(Boolean(isSystem)),
                operatorUserId ? String(operatorUserId) : null,
                operatorUserId ? String(operatorUserId) : null
              ]
            );
            const rows = await tx.query(
              `
                SELECT role_id,
                       tenant_id,
                       code,
                       name,
                       status,
                       scope,
                       is_system,
                       created_by_user_id,
                       updated_by_user_id,
                       created_at,
                       updated_at
                FROM platform_roles
                WHERE role_id = ?
                LIMIT 1
              `,
              [normalizedRoleId]
            );
            const createdRole = toPlatformRoleCatalogRecord(rows?.[0] || null);
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
                  tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.role.catalog.created',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: null,
                  afterState: {
                    role_id: normalizeAuditStringOrNull(createdRole?.roleId, 64) || normalizedRoleId,
                    code: normalizeAuditStringOrNull(createdRole?.code, 64) || normalizedCode,
                    name: normalizeAuditStringOrNull(createdRole?.name, 128) || normalizedName,
                    status: normalizePlatformRoleCatalogStatus(
                      createdRole?.status || normalizedStatus
                    ),
                    scope: normalizedScope,
                    tenant_id: normalizedScope === 'tenant' ? normalizedTenantId : null,
                    is_system: Boolean(createdRole?.isSystem ?? Boolean(isSystem))
                  },
                  metadata: {
                    scope: normalizedScope
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('platform role create audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...createdRole,
              auditRecorded
            };
          })
      });
    }
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalogCreatePlatformRoleCatalogEntry
};
