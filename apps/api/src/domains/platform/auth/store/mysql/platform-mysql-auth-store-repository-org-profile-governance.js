'use strict';

const createPlatformMysqlAuthStoreRepositoryOrgProfileGovernance = ({
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
    listPlatformOrgs: async ({
      page = 1,
      pageSize = 20,
      orgName = null,
      owner = null,
      status = null,
      createdAtStart = null,
      createdAtEnd = null
    } = {}) => {
      const resolvedPage = Number(page);
      const resolvedPageSize = Number(pageSize);
      if (
        !Number.isInteger(resolvedPage)
        || resolvedPage <= 0
        || !Number.isInteger(resolvedPageSize)
        || resolvedPageSize <= 0
      ) {
        throw new Error('listPlatformOrgs requires positive integer page and pageSize');
      }

      const normalizedOrgName = orgName === null || orgName === undefined
        ? ''
        : String(orgName).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedOrgName)) {
        throw new Error('listPlatformOrgs orgName cannot contain control chars');
      }

      const normalizedOwner = owner === null || owner === undefined
        ? ''
        : String(owner).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedOwner)) {
        throw new Error('listPlatformOrgs owner cannot contain control chars');
      }

      const normalizedStatusFilter =
        status === null || status === undefined || String(status).trim() === ''
          ? null
          : normalizeOrgStatus(status);
      if (
        normalizedStatusFilter !== null
        && !VALID_ORG_STATUS.has(normalizedStatusFilter)
      ) {
        throw new Error('listPlatformOrgs status filter must be active or disabled');
      }

      const normalizedCreatedAtStart = createdAtStart === null || createdAtStart === undefined
        ? null
        : new Date(String(createdAtStart).trim());
      if (
        normalizedCreatedAtStart !== null
        && Number.isNaN(normalizedCreatedAtStart.getTime())
      ) {
        throw new Error('listPlatformOrgs createdAtStart must be valid datetime');
      }
      const normalizedCreatedAtEnd = createdAtEnd === null || createdAtEnd === undefined
        ? null
        : new Date(String(createdAtEnd).trim());
      if (
        normalizedCreatedAtEnd !== null
        && Number.isNaN(normalizedCreatedAtEnd.getTime())
      ) {
        throw new Error('listPlatformOrgs createdAtEnd must be valid datetime');
      }
      if (
        normalizedCreatedAtStart !== null
        && normalizedCreatedAtEnd !== null
        && normalizedCreatedAtStart.getTime() > normalizedCreatedAtEnd.getTime()
      ) {
        throw new Error('listPlatformOrgs createdAtStart cannot be later than createdAtEnd');
      }

      const whereClauses = [];
      const whereArgs = [];
      if (normalizedStatusFilter !== null) {
        whereClauses.push('o.status = ?');
        whereArgs.push(normalizedStatusFilter);
      }
      if (normalizedOrgName.length > 0) {
        whereClauses.push('LOWER(o.name) LIKE ?');
        whereArgs.push(`%${escapeSqlLikePattern(normalizedOrgName.toLowerCase())}%`);
      }
      if (normalizedOwner.length > 0) {
        whereClauses.push(
          `(
            u.phone = ?
            OR EXISTS (
              SELECT 1
              FROM tenant_memberships ut_owner_name
              WHERE ut_owner_name.user_id = o.owner_user_id
                AND LOWER(COALESCE(ut_owner_name.display_name, '')) LIKE ?
            )
          )`
        );
        whereArgs.push(
          normalizedOwner,
          `%${escapeSqlLikePattern(normalizedOwner.toLowerCase())}%`
        );
      }
      if (normalizedCreatedAtStart !== null) {
        whereClauses.push('o.created_at >= ?');
        whereArgs.push(normalizedCreatedAtStart);
      }
      if (normalizedCreatedAtEnd !== null) {
        whereClauses.push('o.created_at <= ?');
        whereArgs.push(normalizedCreatedAtEnd);
      }
      const whereSql = whereClauses.length > 0
        ? `WHERE ${whereClauses.join(' AND ')}`
        : '';

      const countRows = await dbClient.query(
        `
          SELECT COUNT(*) AS total
          FROM tenants o
          INNER JOIN iam_users u
            ON u.id = o.owner_user_id
          ${whereSql}
        `,
        whereArgs
      );
      const total = Number(countRows?.[0]?.total || 0);

      const offset = (resolvedPage - 1) * resolvedPageSize;
      const rows = await dbClient.query(
        `
          SELECT o.id AS org_id,
                 o.name AS org_name,
                 o.status AS status,
                 o.created_at AS created_at,
                 u.phone AS owner_phone,
                 (
                   SELECT ut_owner.display_name
                   FROM tenant_memberships ut_owner
                   WHERE ut_owner.user_id = o.owner_user_id
                     AND ut_owner.display_name IS NOT NULL
                     AND TRIM(ut_owner.display_name) <> ''
                   ORDER BY ut_owner.joined_at DESC, ut_owner.membership_id DESC
                   LIMIT 1
                 ) AS owner_name
          FROM tenants o
          INNER JOIN iam_users u
            ON u.id = o.owner_user_id
          ${whereSql}
          ORDER BY o.id ASC
          LIMIT ? OFFSET ?
        `,
        [...whereArgs, resolvedPageSize, offset]
      );

      const items = (Array.isArray(rows) ? rows : []).map((row) => {
        const normalizedStatus = normalizeOrgStatus(row.status);
        if (!VALID_ORG_STATUS.has(normalizedStatus)) {
          throw new Error('listPlatformOrgs returned invalid status');
        }

        const resolvedOrgId = String(row.org_id || '').trim();
        const resolvedOrgName = String(row.org_name || '').trim();
        const resolvedOwnerPhone = String(row.owner_phone || '').trim();
        const resolvedOwnerName = row.owner_name === null || row.owner_name === undefined
          ? null
          : String(row.owner_name).trim();
        const resolvedCreatedAt = normalizeStoreIsoTimestamp(row.created_at);
        if (
          !resolvedOrgId
          || !resolvedOrgName
          || !resolvedOwnerPhone
          || !resolvedCreatedAt
        ) {
          throw new Error('listPlatformOrgs returned invalid org record');
        }
        if (
          resolvedOwnerName !== null
          && (
            !resolvedOwnerName
            || resolvedOwnerName.length > MAX_TENANT_USER_DISPLAY_NAME_LENGTH
            || CONTROL_CHAR_PATTERN.test(resolvedOwnerName)
          )
        ) {
          throw new Error('listPlatformOrgs returned invalid owner_name');
        }

        return {
          org_id: resolvedOrgId,
          org_name: resolvedOrgName,
          owner_name: resolvedOwnerName,
          owner_phone: resolvedOwnerPhone,
          status: normalizedStatus,
          created_at: resolvedCreatedAt
        };
      });

      return {
        total,
        items
      };
    },

    upsertPlatformUserProfile: async ({
      userId,
      name,
      department = null
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        throw new Error('upsertPlatformUserProfile requires userId');
      }
      const normalizedName = normalizeRequiredPlatformUserProfileField({
        value: name,
        maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
        fieldName: 'name'
      });
      const normalizedDepartment = normalizeOptionalPlatformUserProfileField({
        value: department,
        maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
        fieldName: 'department'
      });

      await dbClient.query(
        `
          INSERT INTO platform_users (
            user_id,
            name,
            department
          )
          VALUES (?, ?, ?)
          ON DUPLICATE KEY UPDATE
            name = VALUES(name),
            department = VALUES(department),
            updated_at = CURRENT_TIMESTAMP(3)
        `,
        [
          normalizedUserId,
          normalizedName,
          normalizedDepartment
        ]
      );

      const rows = await dbClient.query(
        `
          SELECT user_id,
                 name,
                 department
          FROM platform_users
          WHERE user_id = ?
          LIMIT 1
        `,
        [normalizedUserId]
      );
      const row = rows?.[0];
      if (!row) {
        throw new Error('upsertPlatformUserProfile write not applied');
      }
      return {
        user_id: String(row.user_id || '').trim(),
        name: normalizeRequiredPlatformUserProfileField({
          value: row.name,
          maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
          fieldName: 'name'
        }),
        department: normalizeOptionalPlatformUserProfileField({
          value: row.department,
          maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
          fieldName: 'department'
        })
      };
    },

  };
};

module.exports = {
  createPlatformMysqlAuthStoreRepositoryOrgProfileGovernance
};
