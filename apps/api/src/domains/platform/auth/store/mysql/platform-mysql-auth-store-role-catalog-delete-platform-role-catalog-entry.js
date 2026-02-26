'use strict';

const createPlatformMysqlAuthStoreRoleCatalogDeletePlatformRoleCatalogEntry = ({
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
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
deletePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('deletePlatformRoleCatalogEntry requires roleId');
      }
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('deletePlatformRoleCatalogEntry received unsupported scope');
      }
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      const whereClause = normalizedScope === 'tenant'
        ? 'role_id = ? AND scope = ? AND tenant_id = ?'
        : "role_id = ? AND scope = ? AND tenant_id = ''";
      const lookupArgs = normalizedScope === 'tenant'
        ? [normalizedRoleId, normalizedScope, normalizedTenantId]
        : [normalizedRoleId, normalizedScope];

      return executeWithDeadlockRetry({
        operation: 'deletePlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
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
                WHERE ${whereClause}
                LIMIT 1
                FOR UPDATE
              `,
              lookupArgs
            );
            const existing = toPlatformRoleCatalogRecord(rows?.[0] || null);
            if (!existing) {
              return null;
            }

            await tx.query(
              `
                UPDATE platform_roles
                SET status = 'disabled',
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE role_id = ?
              `,
              [
                operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
                existing.roleId
              ]
            );

            const updatedRows = await tx.query(
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
              [existing.roleId]
            );
            const deletedRole = toPlatformRoleCatalogRecord(updatedRows?.[0] || null);
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
                  tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.role.catalog.deleted',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    code: normalizeAuditStringOrNull(existing.code, 64),
                    name: normalizeAuditStringOrNull(existing.name, 128),
                    status: normalizePlatformRoleCatalogStatus(existing.status || 'disabled')
                  },
                  afterState: {
                    status: normalizePlatformRoleCatalogStatus(deletedRole?.status || 'disabled')
                  },
                  metadata: {
                    scope: normalizedScope
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('platform role delete audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...deletedRole,
              auditRecorded
            };
          })
      });
    }
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalogDeletePlatformRoleCatalogEntry
};
