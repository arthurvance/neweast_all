const createSharedMysqlAuthStoreRepositorySessionAccessGovernance = ({
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
    createSession: async ({
      sessionId,
      userId,
      sessionVersion,
      entryDomain = 'platform',
      activeTenantId = null
    }) => {
      await dbClient.query(
        `
          INSERT INTO auth_sessions (session_id, user_id, session_version, entry_domain, active_tenant_id, status)
          VALUES (?, ?, ?, ?, ?, 'active')
        `,
        [
          sessionId,
          String(userId),
          Number(sessionVersion),
          String(entryDomain || 'platform').toLowerCase(),
          activeTenantId ? String(activeTenantId) : null
        ]
      );
    },

    findSessionById: async (sessionId) => {
      const rows = await dbClient.query(
        `
          SELECT session_id, user_id, session_version, entry_domain, active_tenant_id, status, revoked_reason
          FROM auth_sessions
          WHERE session_id = ?
          LIMIT 1
        `,
        [sessionId]
      );
      return toSessionRecord(rows[0]);
    },

    updateSessionContext: async ({ sessionId, entryDomain, activeTenantId }) => {
      await dbClient.query(
        `
          UPDATE auth_sessions
          SET entry_domain = COALESCE(?, entry_domain),
              active_tenant_id = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE session_id = ?
        `,
        [
          entryDomain === undefined ? null : String(entryDomain || 'platform').toLowerCase(),
          activeTenantId ? String(activeTenantId) : null,
          String(sessionId)
        ]
      );
      return true;
    },

    findDomainAccessByUserId: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return {
          platform: false,
          tenant: false
        };
      }

      const platformRows = await dbClient.query(
        `
          SELECT pu.status AS platform_status,
                 u.status AS user_status
          FROM platform_users pu
          INNER JOIN iam_users u
            ON u.id = pu.user_id
          WHERE pu.user_id = ?
          LIMIT 1
        `,
        [normalizedUserId]
      );
      const platformRow = platformRows?.[0] || null;
      const platformStatus = normalizeOrgStatus(platformRow?.platform_status || '');
      const userStatus = normalizeUserStatus(platformRow?.user_status || '');
      const hasPlatformAccess =
        platformRow !== null
        && VALID_PLATFORM_USER_STATUS.has(platformStatus)
        && platformStatus === 'active'
        && userStatus === 'active';

      const tenantRows = await runTenantUsershipQuery({
        sqlWithOrgGuard: `
            SELECT COUNT(*) AS tenant_count
            FROM tenant_memberships ut
            LEFT JOIN tenants o ON o.id = ut.tenant_id
            LEFT JOIN iam_users u ON u.id = ut.user_id
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
              AND o.status IN ('active', 'enabled')
              AND u.status IN ('active', 'enabled')
          `,
        sqlWithoutOrgGuard: `
            SELECT COUNT(*) AS tenant_count
            FROM tenant_memberships ut
            LEFT JOIN iam_users u ON u.id = ut.user_id
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
              AND u.status IN ('active', 'enabled')
          `,
        params: [normalizedUserId]
      });
      const tenantCount = Number(tenantRows?.[0]?.tenant_count || 0);

      return {
        platform: hasPlatformAccess,
        tenant: tenantCount > 0
      };
    },

  };
};

module.exports = {
  createSharedMysqlAuthStoreRepositorySessionAccessGovernance
};
