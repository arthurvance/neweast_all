const createMySqlAuthStoreCapabilities = ({
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
    findUserByPhone: async (phone) => {
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM iam_users
          WHERE phone = ?
          LIMIT 1
        `,
        [phone]
      );
      return toUserRecord(rows[0]);
    },

    findUserById: async (userId) => {
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM iam_users
          WHERE id = ?
          LIMIT 1
        `,
        [userId]
      );
      return toUserRecord(rows[0]);
    },

    updateUserPhone: async ({
      userId,
      phone
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedPhone = String(phone || '').trim();
      if (
        !normalizedUserId
        || !normalizedPhone
        || !MAINLAND_PHONE_PATTERN.test(normalizedPhone)
        || CONTROL_CHAR_PATTERN.test(normalizedPhone)
      ) {
        throw new Error('updateUserPhone requires valid userId and mainland phone');
      }

      try {
        const updateResult = await dbClient.query(
          `
            UPDATE iam_users
            SET phone = ?
            WHERE id = ?
            LIMIT 1
          `,
          [normalizedPhone, normalizedUserId]
        );
        const affectedRows = Number(updateResult?.affectedRows || 0);
        if (affectedRows >= 1) {
          return {
            reason: 'ok',
            user_id: normalizedUserId,
            phone: normalizedPhone
          };
        }

        const rows = await dbClient.query(
          `
            SELECT phone
            FROM iam_users
            WHERE id = ?
            LIMIT 1
          `,
          [normalizedUserId]
        );
        const row = rows?.[0];
        if (!row) {
          return {
            reason: 'invalid-user-id'
          };
        }
        const currentPhone = String(row.phone || '').trim();
        if (currentPhone === normalizedPhone) {
          return {
            reason: 'no-op',
            user_id: normalizedUserId,
            phone: normalizedPhone
          };
        }
        return {
          reason: 'unknown'
        };
      } catch (error) {
        if (isDuplicateEntryError(error)) {
          return {
            reason: 'phone-conflict'
          };
        }
        throw error;
      }
    },

    listPlatformUsers: async ({
      page = 1,
      pageSize = 20,
      status = null,
      keyword = null,
      phone = null,
      name = null,
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
        throw new Error('listPlatformUsers requires positive integer page and pageSize');
      }

      const normalizedStatusFilter =
        status === null || status === undefined || String(status).trim() === ''
          ? null
          : normalizeOrgStatus(status);
      if (
        normalizedStatusFilter !== null
        && !VALID_PLATFORM_USER_STATUS.has(normalizedStatusFilter)
      ) {
        throw new Error('listPlatformUsers status filter must be active or disabled');
      }

      const normalizedKeyword = keyword === null || keyword === undefined
        ? ''
        : String(keyword).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedKeyword)) {
        throw new Error('listPlatformUsers keyword cannot contain control chars');
      }
      const normalizedPhone = phone === null || phone === undefined
        ? ''
        : String(phone).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedPhone)) {
        throw new Error('listPlatformUsers phone cannot contain control chars');
      }
      const normalizedName = name === null || name === undefined
        ? ''
        : String(name).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedName)) {
        throw new Error('listPlatformUsers name cannot contain control chars');
      }
      const normalizedCreatedAtStart = createdAtStart === null || createdAtStart === undefined
        ? null
        : new Date(String(createdAtStart).trim());
      if (
        normalizedCreatedAtStart !== null
        && Number.isNaN(normalizedCreatedAtStart.getTime())
      ) {
        throw new Error('listPlatformUsers createdAtStart must be valid datetime');
      }
      const normalizedCreatedAtEnd = createdAtEnd === null || createdAtEnd === undefined
        ? null
        : new Date(String(createdAtEnd).trim());
      if (
        normalizedCreatedAtEnd !== null
        && Number.isNaN(normalizedCreatedAtEnd.getTime())
      ) {
        throw new Error('listPlatformUsers createdAtEnd must be valid datetime');
      }
      if (
        normalizedCreatedAtStart !== null
        && normalizedCreatedAtEnd !== null
        && normalizedCreatedAtStart.getTime() > normalizedCreatedAtEnd.getTime()
      ) {
        throw new Error('listPlatformUsers createdAtStart cannot be later than createdAtEnd');
      }

      const whereClauses = [];
      const whereArgs = [];
      if (normalizedStatusFilter !== null) {
        if (normalizedStatusFilter === 'active') {
          whereClauses.push("pup.status IN ('active', 'enabled')");
        } else {
          whereClauses.push('pup.status = ?');
          whereArgs.push(normalizedStatusFilter);
        }
      }
      if (normalizedKeyword.length > 0) {
        whereClauses.push('(u.id LIKE ? OR u.phone LIKE ?)');
        const keywordLike = `%${normalizedKeyword}%`;
        whereArgs.push(keywordLike, keywordLike);
      }
      if (normalizedPhone.length > 0) {
        whereClauses.push('u.phone = ?');
        whereArgs.push(normalizedPhone);
      }
      if (normalizedName.length > 0) {
        whereClauses.push('LOWER(COALESCE(pup.name, \'\')) LIKE ?');
        whereArgs.push(`%${escapeSqlLikePattern(normalizedName.toLowerCase())}%`);
      }
      if (normalizedCreatedAtStart !== null) {
        whereClauses.push('u.created_at >= ?');
        whereArgs.push(normalizedCreatedAtStart);
      }
      if (normalizedCreatedAtEnd !== null) {
        whereClauses.push('u.created_at <= ?');
        whereArgs.push(normalizedCreatedAtEnd);
      }
      const whereSql = whereClauses.length > 0
        ? `WHERE ${whereClauses.join(' AND ')}`
        : '';

      const countRows = await dbClient.query(
        `
          SELECT COUNT(*) AS total
          FROM platform_users pup
          INNER JOIN iam_users u
            ON pup.user_id = u.id
          ${whereSql}
        `,
        whereArgs
      );
      const total = Number(countRows?.[0]?.total || 0);

      const offset = (resolvedPage - 1) * resolvedPageSize;
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
          ${whereSql}
          ORDER BY u.id ASC
          LIMIT ? OFFSET ?
        `,
        [...whereArgs, resolvedPageSize, offset]
      );

      const items = (Array.isArray(rows) ? rows : []).map((row) => {
        const normalizedStatus = normalizeOrgStatus(row.platform_status);
        if (!VALID_PLATFORM_USER_STATUS.has(normalizedStatus)) {
          throw new Error('listPlatformUsers returned invalid platform status');
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
          throw new Error('listPlatformUsers returned invalid created_at');
        }
        return {
          user_id: String(row.user_id || '').trim(),
          phone: String(row.phone || '').trim(),
          name: resolvedName,
          department: resolvedDepartment,
          status: normalizedStatus,
          created_at: resolvedCreatedAt,
          roles: []
        };
      });

      const listedUserIds = [...new Set(items.map((item) => item.user_id))];
      if (listedUserIds.length > 0) {
        const placeholders = buildSqlInPlaceholders(listedUserIds.length);
        const roleRows = await dbClient.query(
          `
            SELECT upr.user_id,
                   upr.role_id,
                   prc.code AS role_code,
                   prc.name AS role_name,
                   prc.status AS role_status
            FROM platform_user_roles upr
            LEFT JOIN platform_roles prc
              ON prc.role_id = upr.role_id
             AND prc.scope = 'platform'
             AND prc.tenant_id = ''
            WHERE upr.user_id IN (${placeholders})
              AND upr.status IN ('active', 'enabled')
            ORDER BY upr.user_id ASC, upr.role_id ASC
          `,
          listedUserIds
        );
        const rolesByUserId = new Map();
        for (const row of Array.isArray(roleRows) ? roleRows : []) {
          const normalizedUserId = String(row.user_id || '').trim();
          const normalizedRoleId = normalizePlatformRoleCatalogRoleId(row.role_id);
          if (!normalizedUserId || !normalizedRoleId) {
            throw new Error('listPlatformUsers returned invalid role binding');
          }
          const roleCode = row.role_code === null || row.role_code === undefined
            ? null
            : normalizeRequiredPlatformUserProfileField({
              value: row.role_code,
              maxLength: MAX_PLATFORM_ROLE_CODE_LENGTH,
              fieldName: 'role_code'
            });
          const roleName = row.role_name === null || row.role_name === undefined
            ? null
            : normalizeRequiredPlatformUserProfileField({
              value: row.role_name,
              maxLength: MAX_PLATFORM_ROLE_NAME_LENGTH,
              fieldName: 'role_name'
            });
          const normalizedRoleStatus = normalizePlatformRoleCatalogStatus(
            row.role_status || 'disabled'
          );
          const roleStatus = VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedRoleStatus)
            ? normalizedRoleStatus
            : 'disabled';
          const existingRoles = rolesByUserId.get(normalizedUserId) || [];
          existingRoles.push({
            role_id: normalizedRoleId,
            code: roleCode,
            name: roleName,
            status: roleStatus
          });
          rolesByUserId.set(normalizedUserId, existingRoles);
        }
        for (const item of items) {
          item.roles = rolesByUserId.get(item.user_id) || [];
        }
      }

      return {
        total,
        items
      };
    },

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

    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { inserted: false };
      }
      const result = await dbClient.query(
        `
          INSERT IGNORE INTO platform_users (user_id, name, department, status)
          VALUES (?, NULL, NULL, 'active')
        `,
        [normalizedUserId]
      );

      return { inserted: Number(result?.affectedRows || 0) > 0 };
    },

    ensureTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { inserted: false };
      }
      const tenantCountRows = await runTenantUsershipQuery({
        sqlWithOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
        `,
        sqlWithoutOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
        `,
        params: [normalizedUserId]
      });
      const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
      return {
        inserted: false,
        has_active_tenant_membership: tenantCount > 0
      };
    },

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId);
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      const rows = await runTenantUsershipQuery({
        sqlWithOrgGuard: `
            SELECT tenant_id,
                   tenant_name,
                   can_view_user_management,
                   can_operate_user_management,
                   can_view_role_management,
                   can_operate_role_management
            FROM tenant_memberships ut
            LEFT JOIN tenants o ON o.id = ut.tenant_id
            WHERE ut.user_id = ?
              AND ut.tenant_id = ?
              AND ut.status IN ('active', 'enabled')
              AND o.status IN ('active', 'enabled')
            LIMIT 1
          `,
        sqlWithoutOrgGuard: `
            SELECT tenant_id,
                   tenant_name,
                   can_view_user_management,
                   can_operate_user_management,
                   can_view_role_management,
                   can_operate_role_management
            FROM tenant_memberships ut
            WHERE ut.user_id = ?
              AND ut.tenant_id = ?
              AND ut.status IN ('active', 'enabled')
            LIMIT 1
          `,
        params: [normalizedUserId, normalizedTenantId]
      });
      const row = rows?.[0];
      if (!row) {
        return null;
      }
      return {
        scopeLabel: `组织权限（${String(row.tenant_name || normalizedTenantId)}）`,
        canViewUserManagement: toBoolean(row.can_view_user_management),
        canOperateUserManagement: toBoolean(row.can_operate_user_management),
        canViewRoleManagement: toBoolean(row.can_view_role_management),
        canOperateRoleManagement: toBoolean(row.can_operate_role_management)
      };
    },

    listTenantOptionsByUserId: async (userId) => {
      const normalizedUserId = String(userId);
      const rows = await runTenantUsershipQuery({
        sqlWithOrgGuard: `
            SELECT tenant_id,
                   tenant_name,
                   u.phone AS owner_phone,
                   (
                     SELECT ut_owner.display_name
                     FROM tenant_memberships ut_owner
                     WHERE ut_owner.user_id = o.owner_user_id
                       AND ut_owner.tenant_id = o.id
                       AND ut_owner.display_name IS NOT NULL
                       AND TRIM(ut_owner.display_name) <> ''
                     ORDER BY ut_owner.joined_at DESC, ut_owner.membership_id DESC
                     LIMIT 1
                   ) AS owner_name
            FROM tenant_memberships ut
            LEFT JOIN tenants o ON o.id = ut.tenant_id
            LEFT JOIN iam_users u ON u.id = o.owner_user_id
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
              AND o.status IN ('active', 'enabled')
            ORDER BY tenant_id ASC
          `,
        sqlWithoutOrgGuard: `
            SELECT tenant_id,
                   tenant_name,
                   NULL AS owner_phone,
                   NULL AS owner_name
            FROM tenant_memberships ut
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
            ORDER BY tenant_id ASC
          `,
        params: [normalizedUserId]
      });

      return (Array.isArray(rows) ? rows : [])
        .map((row) => {
          const ownerName = row.owner_name ? String(row.owner_name).trim() : null;
          const ownerPhone = row.owner_phone ? String(row.owner_phone).trim() : null;
          return {
            tenantId: String(row.tenant_id || '').trim(),
            tenantName: row.tenant_name ? String(row.tenant_name) : null,
            ...(ownerName ? { ownerName } : {}),
            ...(ownerPhone ? { ownerPhone } : {})
          };
        })
        .filter((row) => row.tenantId.length > 0);
    },

    hasAnyTenantRelationshipByUserId: async (userId) => {
      const normalizedUserId = String(userId);
      const rows = await dbClient.query(
        `
          SELECT COUNT(*) AS tenant_count
          FROM tenant_memberships
          WHERE user_id = ?
        `,
        [normalizedUserId]
      );
      return Number(rows?.[0]?.tenant_count || 0) > 0;
    },

    findPlatformPermissionByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }

      return resolveActivePlatformPermissionSnapshotByUserIdTx({
        txClient: dbClient,
        userId: normalizedUserId
      });
    },

    hasPlatformPermissionByUserId: async ({
      userId,
      permissionCode
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedPermissionCode = toPlatformPermissionCodeKey(permissionCode);
      if (
        !normalizedUserId
        || !PLATFORM_ROLE_MANAGEMENT_PERMISSION_CODE_SET.has(normalizedPermissionCode)
      ) {
        return deniedRoleManagementPermission;
      }

      const platformAccessRows = await dbClient.query(
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
      const platformAccess = platformAccessRows?.[0] || null;
      const platformStatus = normalizeOrgStatus(platformAccess?.platform_status || '');
      const userStatus = normalizeUserStatus(platformAccess?.user_status || '');
      if (
        !platformAccess
        || platformStatus !== 'active'
        || userStatus !== 'active'
      ) {
        return deniedRoleManagementPermission;
      }

      const rows = await dbClient.query(
        `
          SELECT MAX(
                   CASE
                     WHEN prg.permission_code = ? THEN 1
                     ELSE 0
                   END
                 ) AS can_view_role_management,
                 MAX(
                   CASE
                     WHEN prg.permission_code = ? THEN 1
                     ELSE 0
                   END
                 ) AS can_operate_role_management
          FROM platform_user_roles upr
          INNER JOIN platform_roles prc
            ON prc.role_id = upr.role_id
           AND prc.scope = 'platform'
           AND prc.tenant_id = ''
           AND prc.status IN ('active', 'enabled')
          LEFT JOIN platform_role_permission_grants prg
            ON prg.role_id = upr.role_id
           AND prg.permission_code IN (?, ?)
          WHERE upr.user_id = ?
            AND upr.status IN ('active', 'enabled')
        `,
        [
          PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
          PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
          PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
          PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
          normalizedUserId
        ]
      );
      const row = rows?.[0] || null;
      const canOperateRoleManagement = toBoolean(row?.can_operate_role_management);
      const canViewRoleManagement =
        canOperateRoleManagement || toBoolean(row?.can_view_role_management);
      const granted =
        normalizedPermissionCode === PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
          ? canOperateRoleManagement
          : canViewRoleManagement;
      return {
        canViewRoleManagement,
        canOperateRoleManagement,
        granted
      };
    },

    syncPlatformPermissionSnapshotByUserId: async ({
      userId,
      forceWhenNoRoleFacts = false
    }) =>
      syncPlatformPermissionSnapshotByUserIdImpl({
        userId,
        forceWhenNoRoleFacts
      }),

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      await dbClient.query(
        `
          INSERT INTO auth_refresh_tokens (token_hash, session_id, user_id, status, expires_at)
          VALUES (?, ?, ?, 'active', FROM_UNIXTIME(? / 1000.0))
        `,
        [tokenHash, sessionId, String(userId), Number(expiresAt)]
      );
    },

    findRefreshTokenByHash: async (tokenHash) => {
      const rows = await dbClient.query(
        `
          SELECT token_hash,
                 session_id,
                 user_id,
                 status,
                 rotated_from_token_hash,
                 rotated_to_token_hash,
                 CAST(ROUND(UNIX_TIMESTAMP(expires_at) * 1000) AS UNSIGNED) AS expires_at_epoch_ms
          FROM auth_refresh_tokens
          WHERE token_hash = ?
          LIMIT 1
        `,
        [tokenHash]
      );
      return toRefreshRecord(rows[0]);
    },

    markRefreshTokenStatus: async ({ tokenHash, status }) => {
      await dbClient.query(
        `
          UPDATE auth_refresh_tokens
          SET status = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [status, tokenHash]
      );
    },

    linkRefreshRotation: async ({ previousTokenHash, nextTokenHash }) => {
      await dbClient.query(
        `
          UPDATE auth_refresh_tokens
          SET rotated_to_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [nextTokenHash, previousTokenHash]
      );

      await dbClient.query(
        `
          UPDATE auth_refresh_tokens
          SET rotated_from_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [previousTokenHash, nextTokenHash]
      );
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) =>
      dbClient.inTransaction(async (tx) => {
        const normalizedSessionId = String(sessionId);
        const normalizedUserId = String(userId);
        const rows = await tx.query(
          `
            SELECT token_hash, status, session_id, user_id
            FROM auth_refresh_tokens
            WHERE token_hash = ?
            LIMIT 1
            FOR UPDATE
          `,
          [previousTokenHash]
        );
        const previous = rows[0];

        if (
          !previous
          || String(previous.status).toLowerCase() !== 'active'
          || String(previous.session_id || '') !== normalizedSessionId
          || String(previous.user_id || '') !== normalizedUserId
        ) {
          return { ok: false };
        }

        const updated = await tx.query(
          `
            UPDATE auth_refresh_tokens
            SET status = 'rotated',
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ? AND status = 'active' AND session_id = ? AND user_id = ?
          `,
          [previousTokenHash, normalizedSessionId, normalizedUserId]
        );

        if (!updated || Number(updated.affectedRows || 0) !== 1) {
          return { ok: false };
        }

        await tx.query(
          `
            INSERT INTO auth_refresh_tokens (token_hash, session_id, user_id, status, expires_at, rotated_from_token_hash)
            VALUES (?, ?, ?, 'active', FROM_UNIXTIME(? / 1000.0), ?)
          `,
          [nextTokenHash, normalizedSessionId, normalizedUserId, Number(expiresAt), previousTokenHash]
        );

        await tx.query(
          `
            UPDATE auth_refresh_tokens
            SET rotated_to_token_hash = ?,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ?
          `,
          [nextTokenHash, previousTokenHash]
        );

        return { ok: true };
      }),

    revokeSession: async ({ sessionId, reason }) => {
      await dbClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE session_id = ? AND status = 'active'
        `,
        [reason || null, sessionId]
      );

      await dbClient.query(
        `
          UPDATE auth_refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE session_id = ? AND status = 'active'
        `,
        [sessionId]
      );
    },

    revokeAllUserSessions: async ({ userId, reason }) => {
      await dbClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [reason || null, String(userId)]
      );

      await dbClient.query(
        `
          UPDATE auth_refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [String(userId)]
      );
    },

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) =>
      dbClient.inTransaction(async (tx) =>
        bumpSessionVersionAndConvergeSessionsTx({
          txClient: tx,
          userId,
          passwordHash,
          reason: 'password-changed',
          revokeRefreshTokens: false,
          revokeAuthSessions: false
        })),

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) =>
      dbClient.inTransaction(async (tx) =>
        bumpSessionVersionAndConvergeSessionsTx({
          txClient: tx,
          userId,
          passwordHash,
          reason: reason || 'password-changed',
          revokeRefreshTokens: true,
          revokeAuthSessions: true
        }))
  };
};

module.exports = {
  createMySqlAuthStoreCapabilities
};
