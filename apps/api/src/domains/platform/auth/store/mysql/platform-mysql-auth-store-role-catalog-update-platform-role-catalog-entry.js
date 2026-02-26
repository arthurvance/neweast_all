'use strict';

const createPlatformMysqlAuthStoreRoleCatalogUpdatePlatformRoleCatalogEntry = ({
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
updatePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      code = undefined,
      name = undefined,
      status = undefined,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('updatePlatformRoleCatalogEntry requires roleId');
      }
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('updatePlatformRoleCatalogEntry received unsupported scope');
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
        operation: 'updatePlatformRoleCatalogEntry',
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

            const nextCode = code === undefined
              ? existing.code
              : String(code || '').trim();
            const nextName = name === undefined
              ? existing.name
              : String(name || '').trim();
            const nextStatus = status === undefined
              ? existing.status
              : normalizePlatformRoleCatalogStatus(status);
            if (
              !nextCode
              || !nextName
              || !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(nextStatus)
            ) {
              throw new Error('updatePlatformRoleCatalogEntry received invalid update payload');
            }

            await tx.query(
              `
                UPDATE platform_roles
                SET code = ?,
                    code_normalized = ?,
                    name = ?,
                    status = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE role_id = ?
              `,
              [
                nextCode,
                nextCode.toLowerCase(),
                nextName,
                nextStatus,
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
            const updatedRole = toPlatformRoleCatalogRecord(updatedRows?.[0] || null);
            let auditRecorded = false;
            if (auditContext && typeof auditContext === 'object') {
              try {
                await recordAuditEventWithQueryClient({
                  queryClient: tx,
                  domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
                  tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
                  requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
                  traceparent: auditContext.traceparent,
                  eventType: 'auth.role.catalog.updated',
                  actorUserId: auditContext.actorUserId || operatorUserId,
                  actorSessionId: auditContext.actorSessionId || operatorSessionId,
                  targetType: 'role',
                  targetId: normalizedRoleId,
                  result: 'success',
                  beforeState: {
                    code: normalizeAuditStringOrNull(existing.code, 64),
                    name: normalizeAuditStringOrNull(existing.name, 128),
                    status: normalizePlatformRoleCatalogStatus(existing.status || 'active')
                  },
                  afterState: {
                    code: normalizeAuditStringOrNull(updatedRole?.code, 64),
                    name: normalizeAuditStringOrNull(updatedRole?.name, 128),
                    status: normalizePlatformRoleCatalogStatus(updatedRole?.status || 'active')
                  },
                  metadata: {
                    scope: normalizedScope,
                    changed_fields: [
                      ...new Set(Object.keys({
                        ...(code === undefined ? {} : { code: true }),
                        ...(name === undefined ? {} : { name: true }),
                        ...(status === undefined ? {} : { status: true })
                      }))
                    ]
                  }
                });
                auditRecorded = true;
              } catch (error) {
                const auditWriteError = new Error('platform role update audit write failed');
                auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
                auditWriteError.cause = error;
                throw auditWriteError;
              }
            }
            return {
              ...updatedRole,
              auditRecorded
            };
          })
      });
    }
});

module.exports = {
  createPlatformMysqlAuthStoreRoleCatalogUpdatePlatformRoleCatalogEntry
};
