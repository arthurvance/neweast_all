'use strict';

const createPlatformMysqlAuthStoreRepositoryGovernanceRead = ({
  dbClient,
  runTenantUsershipQuery,
  toUserRecord,
  toSessionRecord,
  toRefreshRecord,
  toBoolean,
  isDuplicateEntryError,
  escapeSqlLikePattern,
  buildSqlInPlaceholders,
  toPlatformPermissionCodeKey,
  normalizeUserStatus,
  normalizeOrgStatus,
  normalizeStoreIsoTimestamp,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  createSystemSensitiveConfigVersionConflictError,
  normalizeRequiredPlatformUserProfileField,
  normalizeOptionalPlatformUserProfileField,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleCatalogStatus,
  toSystemSensitiveConfigRecord,
  toPlatformRoleCatalogRecord,
  resolveActivePlatformPermissionSnapshotByUserIdTx,
  syncPlatformPermissionSnapshotByUserIdImpl,
  bumpSessionVersionAndConvergeSessionsTx,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_PLATFORM_ROLE_CODE_LENGTH,
  MAX_PLATFORM_ROLE_NAME_LENGTH,
  MAINLAND_PHONE_PATTERN,
  CONTROL_CHAR_PATTERN,
  MYSQL_DUP_ENTRY_ERRNO,
  ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_SCOPE,
  VALID_PLATFORM_ROLE_CATALOG_STATUS,
  PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = {}) => {
  const deniedRoleManagementPermission = {
    canViewRoleManagement: false,
    canOperateRoleManagement: false,
    granted: false
  };

  return {
    getSystemSensitiveConfig: async ({ configKey } = {}) => {
      const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
      if (!normalizedConfigKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT config_key,
                 encrypted_value,
                 version,
                 status,
                 updated_by_user_id,
                 updated_at,
                 created_by_user_id,
                 created_at
          FROM system_sensitive_configs
          WHERE config_key = ?
          LIMIT 1
        `,
        [normalizedConfigKey]
      );
      return toSystemSensitiveConfigRecord(rows?.[0]);
    },

    upsertSystemSensitiveConfig: async ({
      configKey,
      encryptedValue,
      expectedVersion,
      updatedByUserId,
      status = 'active'
    } = {}) =>
      dbClient.inTransaction(async (tx) => {
        const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
        if (!normalizedConfigKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)) {
          throw new Error('upsertSystemSensitiveConfig requires whitelisted configKey');
        }
        const normalizedEncryptedValue = String(encryptedValue || '').trim();
        if (
          !normalizedEncryptedValue
          || CONTROL_CHAR_PATTERN.test(normalizedEncryptedValue)
        ) {
          throw new Error('upsertSystemSensitiveConfig requires encryptedValue');
        }
        const parsedExpectedVersion = Number(expectedVersion);
        if (
          !Number.isInteger(parsedExpectedVersion)
          || parsedExpectedVersion < 0
        ) {
          throw new Error('upsertSystemSensitiveConfig requires expectedVersion >= 0');
        }
        const normalizedUpdatedByUserId = String(updatedByUserId || '').trim();
        if (!normalizedUpdatedByUserId) {
          throw new Error('upsertSystemSensitiveConfig requires updatedByUserId');
        }
        const normalizedStatus = normalizeSystemSensitiveConfigStatus(status);
        if (!normalizedStatus) {
          throw new Error('upsertSystemSensitiveConfig received unsupported status');
        }

        const existingRows = await tx.query(
          `
            SELECT config_key,
                   version,
                   created_by_user_id,
                   created_at
            FROM system_sensitive_configs
            WHERE config_key = ?
            LIMIT 1
            FOR UPDATE
          `,
          [normalizedConfigKey]
        );
        const existingRow = existingRows?.[0] || null;
        const currentVersion = existingRow ? Number(existingRow.version || 0) : 0;
        if (parsedExpectedVersion !== currentVersion) {
          throw createSystemSensitiveConfigVersionConflictError({
            configKey: normalizedConfigKey,
            expectedVersion: parsedExpectedVersion,
            currentVersion
          });
        }

        const nextVersion = currentVersion + 1;
        if (existingRow) {
          await tx.query(
            `
              UPDATE system_sensitive_configs
              SET encrypted_value = ?,
                  version = ?,
                  status = ?,
                  updated_by_user_id = ?,
                  updated_at = CURRENT_TIMESTAMP(3)
              WHERE config_key = ?
            `,
            [
              normalizedEncryptedValue,
              nextVersion,
              normalizedStatus,
              normalizedUpdatedByUserId,
              normalizedConfigKey
            ]
          );
        } else {
          try {
            await tx.query(
              `
                INSERT INTO system_sensitive_configs (
                  config_key,
                  encrypted_value,
                  version,
                  status,
                  updated_by_user_id,
                  created_by_user_id
                )
                VALUES (?, ?, ?, ?, ?, ?)
              `,
              [
                normalizedConfigKey,
                normalizedEncryptedValue,
                nextVersion,
                normalizedStatus,
                normalizedUpdatedByUserId,
                normalizedUpdatedByUserId
              ]
            );
          } catch (error) {
            const normalizedErrorCode = String(error?.code || '').trim();
            if (
              normalizedErrorCode !== 'ER_DUP_ENTRY'
              && Number(error?.errno || 0) !== MYSQL_DUP_ENTRY_ERRNO
            ) {
              throw error;
            }
            let conflictCurrentVersion = currentVersion;
            try {
              const conflictRows = await tx.query(
                `
                  SELECT version
                  FROM system_sensitive_configs
                  WHERE config_key = ?
                  LIMIT 1
                `,
                [normalizedConfigKey]
              );
              const loadedVersion = Number(conflictRows?.[0]?.version);
              if (Number.isInteger(loadedVersion) && loadedVersion >= 0) {
                conflictCurrentVersion = loadedVersion;
              }
            } catch (_lookupError) {}
            throw createSystemSensitiveConfigVersionConflictError({
              configKey: normalizedConfigKey,
              expectedVersion: parsedExpectedVersion,
              currentVersion: conflictCurrentVersion
            });
          }
        }

        const rows = await tx.query(
          `
            SELECT config_key,
                   encrypted_value,
                   version,
                   status,
                   updated_by_user_id,
                   updated_at,
                   created_by_user_id,
                   created_at
            FROM system_sensitive_configs
            WHERE config_key = ?
            LIMIT 1
          `,
          [normalizedConfigKey]
        );
        const record = toSystemSensitiveConfigRecord(rows?.[0]);
        if (!record) {
          throw new Error('upsertSystemSensitiveConfig result unavailable');
        }
        return {
          ...record,
          previousVersion: currentVersion
        };
      }),

    countPlatformRoleCatalogEntries: async () => {
      const rows = await dbClient.query(
        `
          SELECT COUNT(*) AS role_count
          FROM platform_roles
        `
      );
      return Number(rows?.[0]?.role_count || 0);
    },

    listPlatformRoleCatalogEntries: async ({
      scope = 'platform',
      tenantId = null
    } = {}) => {
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('listPlatformRoleCatalogEntries received unsupported scope');
      }
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      const whereClause = normalizedScope === 'tenant'
        ? 'scope = ? AND tenant_id = ?'
        : "scope = ? AND tenant_id = ''";
      const queryArgs = normalizedScope === 'tenant'
        ? [normalizedScope, normalizedTenantId]
        : [normalizedScope];
      const rows = await dbClient.query(
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
          ORDER BY created_at ASC, role_id ASC
        `,
        queryArgs
      );
      return (Array.isArray(rows) ? rows : [])
        .map((row) => toPlatformRoleCatalogRecord(row))
        .filter(Boolean);
    },

    findPlatformRoleCatalogEntryByRoleId: async ({
      roleId,
      scope = undefined,
      tenantId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return null;
      }
      const hasScopeFilter = scope !== undefined && scope !== null;
      const normalizedScope = hasScopeFilter
        ? normalizePlatformRoleCatalogScope(scope)
        : null;
      if (
        hasScopeFilter
        && !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
      ) {
        throw new Error('findPlatformRoleCatalogEntryByRoleId received unsupported scope');
      }
      const normalizedTenantId = hasScopeFilter
        ? normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        })
        : null;
      const whereClause = !hasScopeFilter
        ? 'role_id = ?'
        : normalizedScope === 'tenant'
          ? 'role_id = ? AND scope = ? AND tenant_id = ?'
          : "role_id = ? AND scope = ? AND tenant_id = ''";
      const queryArgs = !hasScopeFilter
        ? [normalizedRoleId]
        : normalizedScope === 'tenant'
          ? [normalizedRoleId, normalizedScope, normalizedTenantId]
          : [normalizedRoleId, normalizedScope];
      const rows = await dbClient.query(
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
        `,
        queryArgs
      );
      return toPlatformRoleCatalogRecord(rows?.[0] || null);
    },

    findPlatformRoleCatalogEntriesByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      if (normalizedRoleIds.length === 0) {
        return [];
      }
      const placeholders = buildSqlInPlaceholders(normalizedRoleIds.length);
      const rows = await dbClient.query(
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
          WHERE role_id IN (${placeholders})
          ORDER BY created_at ASC, role_id ASC
        `,
        normalizedRoleIds
      );
      return (Array.isArray(rows) ? rows : [])
        .map((row) => toPlatformRoleCatalogRecord(row))
        .filter(Boolean);
    },

    getPlatformUserById: async ({ userId } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT u.id AS user_id,
                 u.phone AS phone,
                 pup.status AS platform_status,
                 pup.name AS profile_name,
                 pup.department AS profile_department,
                 u.created_at AS created_at
          FROM platform_users pup
          INNER JOIN iam_users u
            ON pup.user_id = u.id
          WHERE u.id = ?
          LIMIT 1
        `,
        [normalizedUserId]
      );
      const row = rows?.[0];
      if (!row) {
        return null;
      }
      const normalizedStatus = normalizeOrgStatus(row.platform_status);
      if (!VALID_PLATFORM_USER_STATUS.has(normalizedStatus)) {
        throw new Error('getPlatformUserById returned invalid platform status');
      }
      const resolvedName = row.profile_name === null || row.profile_name === undefined
        ? null
        : normalizeRequiredPlatformUserProfileField({
          value: row.profile_name,
          maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
          fieldName: 'profile_name'
        });
      const resolvedDepartment = row.profile_department === null || row.profile_department === undefined
        ? null
        : normalizeOptionalPlatformUserProfileField({
          value: row.profile_department,
          maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
          fieldName: 'profile_department'
        });
      const resolvedCreatedAt = normalizeStoreIsoTimestamp(row.created_at);
      if (!resolvedCreatedAt) {
        throw new Error('getPlatformUserById returned invalid created_at');
      }

      const roleRows = await dbClient.query(
        `
          SELECT upr.role_id,
                 prc.code AS role_code,
                 prc.name AS role_name,
                 prc.status AS role_status
          FROM platform_user_roles upr
          LEFT JOIN platform_roles prc
            ON prc.role_id = upr.role_id
           AND prc.scope = 'platform'
           AND prc.tenant_id = ''
          WHERE upr.user_id = ?
            AND upr.status IN ('active', 'enabled')
          ORDER BY upr.role_id ASC
        `,
        [normalizedUserId]
      );
      const roles = [];
      for (const roleRow of Array.isArray(roleRows) ? roleRows : []) {
        const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleRow.role_id);
        if (!normalizedRoleId) {
          throw new Error('getPlatformUserById returned invalid role binding');
        }
        const roleCode = roleRow.role_code === null || roleRow.role_code === undefined
          ? null
          : normalizeRequiredPlatformUserProfileField({
            value: roleRow.role_code,
            maxLength: MAX_PLATFORM_ROLE_CODE_LENGTH,
            fieldName: 'role_code'
          });
        const roleName = roleRow.role_name === null || roleRow.role_name === undefined
          ? null
          : normalizeRequiredPlatformUserProfileField({
            value: roleRow.role_name,
            maxLength: MAX_PLATFORM_ROLE_NAME_LENGTH,
            fieldName: 'role_name'
          });
        const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
          roleRow.role_status || 'disabled'
        );
        roles.push({
          role_id: normalizedRoleId,
          code: roleCode,
          name: roleName,
          status: VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedRoleStatus)
            ? normalizedRoleStatus
            : 'disabled'
        });
      }

      return {
        user_id: String(row.user_id || '').trim(),
        phone: String(row.phone || '').trim(),
        name: resolvedName,
        department: resolvedDepartment,
        status: normalizedStatus,
        created_at: resolvedCreatedAt,
        roles
      };
    },

  };
};

module.exports = {
  createPlatformMysqlAuthStoreRepositoryGovernanceRead
};
