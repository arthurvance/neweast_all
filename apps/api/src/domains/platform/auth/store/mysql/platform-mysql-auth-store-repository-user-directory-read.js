'use strict';

const createPlatformMysqlAuthStoreRepositoryUserDirectoryRead = ({
  dbClient,
  escapeSqlLikePattern,
  buildSqlInPlaceholders,
  normalizeOrgStatus,
  normalizeStoreIsoTimestamp,
  normalizeRequiredPlatformUserProfileField,
  normalizeOptionalPlatformUserProfileField,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogStatus,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_PLATFORM_ROLE_CODE_LENGTH,
  MAX_PLATFORM_ROLE_NAME_LENGTH,
  CONTROL_CHAR_PATTERN,
  VALID_PLATFORM_USER_STATUS,
  VALID_PLATFORM_ROLE_CATALOG_STATUS
} = {}) => ({
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
});

module.exports = {
  createPlatformMysqlAuthStoreRepositoryUserDirectoryRead
};
