'use strict';

const createPlatformMemoryAuthStoreRoleCatalog = ({
  auditEvents,
  createDuplicatePlatformRoleCatalogEntryError,
  findPlatformRoleCatalogRecordStateByRoleId,
  normalizePlatformRoleCatalogCode,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogTenantIdForScope,
  persistAuditEvent,
  platformRoleCatalogById,
  platformRoleCatalogCodeIndex,
  platformRolesByUserId,
  repositoryMethods,
  restoreAuditEventsFromSnapshot,
  restoreMapFromSnapshot,
  upsertPlatformRoleCatalogRecord
} = {}) => ({
countPlatformRoleCatalogEntries: repositoryMethods.countPlatformRoleCatalogEntries,

listPlatformRoleCatalogEntries: repositoryMethods.listPlatformRoleCatalogEntries,

findPlatformRoleCatalogEntryByRoleId: repositoryMethods.findPlatformRoleCatalogEntryByRoleId,

findPlatformRoleCatalogEntriesByRoleIds: repositoryMethods.findPlatformRoleCatalogEntriesByRoleIds,

listUserIdsByPlatformRoleId: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const normalizedRoleIdKey = normalizedRoleId.toLowerCase();
      const matchedUserIds = [];
      for (const [userId, roles] of platformRolesByUserId.entries()) {
        const hasMatchedRole = (Array.isArray(roles) ? roles : []).some((role) =>
          String(role?.roleId || '').trim().toLowerCase() === normalizedRoleIdKey
        );
        if (hasMatchedRole) {
          matchedUserIds.push(String(userId));
        }
      }
      return matchedUserIds;
    },

listPlatformRoleFactsByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return [];
      }
      const roles = platformRolesByUserId.get(normalizedUserId) || [];
      return (Array.isArray(roles) ? roles : []).map((role) => ({
        roleId: String(role?.roleId || '').trim(),
        role_id: String(role?.roleId || '').trim(),
        status: String(role?.status || 'active').trim().toLowerCase() || 'active',
        permission: role?.permission ? { ...role.permission } : null
      }));
    },

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
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
        const normalizedCode = normalizePlatformRoleCatalogCode(code);
        const normalizedName = String(name || '').trim();
        const normalizedScope = normalizePlatformRoleCatalogScope(scope);
        const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        });
        if (!normalizedRoleId || !normalizedCode || !normalizedName) {
          throw new Error('createPlatformRoleCatalogEntry requires roleId, code, and name');
        }
        if (findPlatformRoleCatalogRecordStateByRoleId(normalizedRoleId)) {
          throw createDuplicatePlatformRoleCatalogEntryError({
            target: 'role_id'
          });
        }
        const createdRole = upsertPlatformRoleCatalogRecord({
          roleId: normalizedRoleId,
          code: normalizedCode,
          name: normalizedName,
          status: normalizePlatformRoleCatalogStatus(status),
          scope: normalizedScope,
          tenantId: normalizedTenantId,
          isSystem: Boolean(isSystem),
          createdByUserId: operatorUserId ? String(operatorUserId) : null,
          updatedByUserId: operatorUserId ? String(operatorUserId) : null,
          createdAt: new Date().toISOString(),
          updatedAt: new Date().toISOString(),
          updatedBySessionId: operatorSessionId ? String(operatorSessionId) : null
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
              tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.role.catalog.created',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'role',
              targetId: normalizedRoleId,
              result: 'success',
              beforeState: null,
              afterState: {
                role_id: normalizedRoleId,
                code: createdRole.code,
                name: createdRole.name,
                status: createdRole.status,
                scope: createdRole.scope,
                tenant_id: createdRole.tenantId,
                is_system: createdRole.isSystem
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(
            platformRoleCatalogCodeIndex,
            snapshot.platformRoleCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

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
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
        if (!normalizedRoleId) {
          throw new Error('updatePlatformRoleCatalogEntry requires roleId');
        }
        const normalizedScope = normalizePlatformRoleCatalogScope(scope);
        const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        });
        const existingState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedRoleId
        );
        const existing = existingState?.record || null;
        if (!existing) {
          return null;
        }
        if (normalizePlatformRoleCatalogScope(existing.scope) !== normalizedScope) {
          return null;
        }
        if (
          normalizedScope === 'tenant'
          && String(existing.tenantId || '') !== normalizedTenantId
        ) {
          return null;
        }
        if (normalizedScope !== 'tenant' && String(existing.tenantId || '') !== '') {
          return null;
        }
        const nextCode = code === undefined
          ? existing.code
          : normalizePlatformRoleCatalogCode(code);
        const nextName = name === undefined
          ? existing.name
          : String(name || '').trim();
        const nextStatus = status === undefined
          ? existing.status
          : normalizePlatformRoleCatalogStatus(status);
        if (!nextCode || !nextName) {
          throw new Error('updatePlatformRoleCatalogEntry requires non-empty code and name');
        }
        const updatedRole = upsertPlatformRoleCatalogRecord({
          ...existing,
          roleId: existing.roleId,
          code: nextCode,
          name: nextName,
          status: nextStatus,
          scope: existing.scope,
          tenantId: existing.tenantId,
          isSystem: Boolean(existing.isSystem),
          updatedByUserId: operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
          updatedBySessionId: operatorSessionId ? String(operatorSessionId) : null,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
              tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.role.catalog.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'role',
              targetId: normalizedRoleId,
              result: 'success',
              beforeState: {
                code: existing.code,
                name: existing.name,
                status: existing.status
              },
              afterState: {
                code: updatedRole.code,
                name: updatedRole.name,
                status: updatedRole.status
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(
            platformRoleCatalogCodeIndex,
            snapshot.platformRoleCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

deletePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
        if (!normalizedRoleId) {
          throw new Error('deletePlatformRoleCatalogEntry requires roleId');
        }
        const normalizedScope = normalizePlatformRoleCatalogScope(scope);
        const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        });
        const existingState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedRoleId
        );
        const existing = existingState?.record || null;
        if (!existing) {
          return null;
        }
        if (normalizePlatformRoleCatalogScope(existing.scope) !== normalizedScope) {
          return null;
        }
        if (
          normalizedScope === 'tenant'
          && String(existing.tenantId || '') !== normalizedTenantId
        ) {
          return null;
        }
        if (normalizedScope !== 'tenant' && String(existing.tenantId || '') !== '') {
          return null;
        }
        const deletedRole = upsertPlatformRoleCatalogRecord({
          ...existing,
          status: 'disabled',
          updatedByUserId: operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
          updatedBySessionId: operatorSessionId ? String(operatorSessionId) : null,
          updatedAt: new Date().toISOString()
        });
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: normalizedScope === 'tenant' ? 'tenant' : 'platform',
              tenantId: normalizedScope === 'tenant' ? normalizedTenantId : null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.role.catalog.deleted',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
              targetType: 'role',
              targetId: normalizedRoleId,
              result: 'success',
              beforeState: {
                code: existing.code,
                name: existing.name,
                status: existing.status
              },
              afterState: {
                status: deletedRole.status
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
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(
            platformRoleCatalogCodeIndex,
            snapshot.platformRoleCatalogCodeIndex
          );
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    }
});

module.exports = {
  createPlatformMemoryAuthStoreRoleCatalog
};
