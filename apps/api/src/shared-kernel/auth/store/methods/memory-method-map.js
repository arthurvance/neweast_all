const createMemoryAuthStoreCapabilities = ({
  clone,
  usersByPhone,
  usersById,
  orgsById,
  systemSensitiveConfigsByKey,
  sessionsById,
  refreshTokensByHash,
  domainsByUserId,
  platformDomainKnownByUserId,
  tenantsByUserId,
  platformProfilesByUserId,
  platformRoleCatalogById,
  platformRolesByUserId,
  platformPermissionsByUserId,
  cloneSystemSensitiveConfigRecord,
  clonePlatformRoleCatalogRecord,
  isTenantUsershipActiveForAuth,
  isActiveLikeStatus,
  resolvePlatformUserReadModel,
  resolveLatestTenantUserProfileByUserId,
  normalizeSystemSensitiveConfigKey,
  normalizeSystemSensitiveConfigStatus,
  normalizeOrgStatus,
  normalizeDateTimeFilterToEpoch,
  normalizeRequiredPlatformUserProfileField,
  normalizeOptionalPlatformUserProfileField,
  findPlatformRoleCatalogRecordStateByRoleId,
  normalizePlatformRoleCatalogRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantId,
  normalizePlatformRoleCatalogTenantIdForScope,
  normalizePlatformRoleCatalogStatus,
  listPlatformRolePermissionGrantsForRoleId,
  toPlatformPermissionCodeKey,
  syncPlatformPermissionFromRoleFacts,
  bumpSessionVersionAndConvergeSessions,
  MAINLAND_PHONE_PATTERN,
  CONTROL_CHAR_PATTERN,
  ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = {}) => {
  return {
    findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

    findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

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

      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return {
          reason: 'invalid-user-id'
        };
      }
      if (String(existingUser.phone || '').trim() === normalizedPhone) {
        return {
          reason: 'no-op',
          user_id: normalizedUserId,
          phone: normalizedPhone
        };
      }

      const phoneOwner = usersByPhone.get(normalizedPhone);
      if (
        phoneOwner
        && String(phoneOwner.id || '').trim() !== normalizedUserId
      ) {
        return {
          reason: 'phone-conflict'
        };
      }

      usersByPhone.delete(String(existingUser.phone || '').trim());
      const updatedUser = {
        ...existingUser,
        phone: normalizedPhone
      };
      usersById.set(normalizedUserId, updatedUser);
      usersByPhone.set(normalizedPhone, updatedUser);
      return {
        reason: 'ok',
        user_id: normalizedUserId,
        phone: normalizedPhone
      };
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
      const normalizedKeywordForMatch = normalizedKeyword.toLowerCase();
      if (CONTROL_CHAR_PATTERN.test(normalizedKeyword)) {
        throw new Error('listPlatformUsers keyword cannot contain control chars');
      }
      const normalizedPhoneFilter = phone === null || phone === undefined
        ? ''
        : String(phone).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedPhoneFilter)) {
        throw new Error('listPlatformUsers phone cannot contain control chars');
      }
      const normalizedNameFilter = name === null || name === undefined
        ? ''
        : String(name).trim();
      const normalizedNameFilterForMatch = normalizedNameFilter.toLowerCase();
      if (CONTROL_CHAR_PATTERN.test(normalizedNameFilter)) {
        throw new Error('listPlatformUsers name cannot contain control chars');
      }
      const createdAtStartEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtStart,
        fieldName: 'createdAtStart'
      });
      const createdAtEndEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtEnd,
        fieldName: 'createdAtEnd'
      });
      if (
        createdAtStartEpoch !== null
        && createdAtEndEpoch !== null
        && createdAtStartEpoch > createdAtEndEpoch
      ) {
        throw new Error('listPlatformUsers createdAtStart cannot be later than createdAtEnd');
      }

      const rows = [];
      for (const [userId, userRecord] of usersById.entries()) {
        if (!platformDomainKnownByUserId.has(userId)) {
          continue;
        }
        const resolvedUser = resolvePlatformUserReadModel({
          userId,
          userRecord
        });
        const platformStatus = resolvedUser.status;
        if (
          normalizedStatusFilter !== null
          && platformStatus !== normalizedStatusFilter
        ) {
          continue;
        }
        if (normalizedPhoneFilter && resolvedUser.phone !== normalizedPhoneFilter) {
          continue;
        }
        if (normalizedNameFilterForMatch) {
          const resolvedName = String(resolvedUser.name || '').toLowerCase();
          if (!resolvedName.includes(normalizedNameFilterForMatch)) {
            continue;
          }
        }
        const createdAtEpoch = new Date(resolvedUser.created_at).getTime();
        if (
          createdAtStartEpoch !== null
          && createdAtEpoch < createdAtStartEpoch
        ) {
          continue;
        }
        if (
          createdAtEndEpoch !== null
          && createdAtEpoch > createdAtEndEpoch
        ) {
          continue;
        }
        if (normalizedKeywordForMatch) {
          const userIdForMatch = String(userId).toLowerCase();
          const phoneForMatch = resolvedUser.phone.toLowerCase();
          const matched =
            userIdForMatch.includes(normalizedKeywordForMatch)
            || phoneForMatch.includes(normalizedKeywordForMatch);
          if (!matched) {
            continue;
          }
        }
        rows.push(resolvedUser);
      }

      rows.sort((left, right) =>
        String(left.user_id).localeCompare(String(right.user_id))
      );

      const total = rows.length;
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return {
        total,
        items: rows.slice(offset, offset + resolvedPageSize)
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

      const normalizedOrgNameFilter = orgName === null || orgName === undefined
        ? ''
        : String(orgName).trim();
      if (CONTROL_CHAR_PATTERN.test(normalizedOrgNameFilter)) {
        throw new Error('listPlatformOrgs orgName cannot contain control chars');
      }

      const normalizedOwnerFilter = owner === null || owner === undefined
        ? ''
        : String(owner).trim();
      const normalizedOwnerFilterForMatch = normalizedOwnerFilter.toLowerCase();
      if (CONTROL_CHAR_PATTERN.test(normalizedOwnerFilter)) {
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

      const createdAtStartEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtStart,
        fieldName: 'createdAtStart'
      });
      const createdAtEndEpoch = normalizeDateTimeFilterToEpoch({
        value: createdAtEnd,
        fieldName: 'createdAtEnd'
      });
      if (
        createdAtStartEpoch !== null
        && createdAtEndEpoch !== null
        && createdAtStartEpoch > createdAtEndEpoch
      ) {
        throw new Error('listPlatformOrgs createdAtStart cannot be later than createdAtEnd');
      }

      const rows = [];
      for (const org of orgsById.values()) {
        const orgId = String(org?.id || '').trim();
        const resolvedOrgName = String(org?.name || '').trim();
        const normalizedStatus = normalizeOrgStatus(org?.status);
        const ownerUserId = String(org?.ownerUserId || '').trim();
        const ownerUser = usersById.get(ownerUserId);
        const ownerPhone = String(ownerUser?.phone || '').trim();
        const ownerProfile = resolveLatestTenantUserProfileByUserId(ownerUserId);
        const ownerName = ownerProfile.name;
        const createdAtRaw = org?.createdAt ?? org?.created_at ?? null;
        const createdAtDate = createdAtRaw ? new Date(createdAtRaw) : null;
        const createdAt = createdAtDate && !Number.isNaN(createdAtDate.getTime())
          ? createdAtDate.toISOString()
          : '';

        if (
          !orgId
          || !resolvedOrgName
          || !ownerUserId
          || !ownerPhone
          || !VALID_ORG_STATUS.has(normalizedStatus)
          || !createdAt
        ) {
          throw new Error('listPlatformOrgs returned invalid organization shape');
        }

        if (
          normalizedStatusFilter !== null
          && normalizedStatus !== normalizedStatusFilter
        ) {
          continue;
        }
        if (
          normalizedOrgNameFilter
          && !resolvedOrgName.toLowerCase().includes(normalizedOrgNameFilter.toLowerCase())
        ) {
          continue;
        }
        if (normalizedOwnerFilter) {
          const ownerNameForMatch = String(ownerName || '').toLowerCase();
          const ownerNameMatched = ownerNameForMatch.includes(normalizedOwnerFilterForMatch);
          const ownerPhoneMatched = ownerPhone === normalizedOwnerFilter;
          if (!ownerNameMatched && !ownerPhoneMatched) {
            continue;
          }
        }

        const createdAtEpoch = new Date(createdAt).getTime();
        if (
          createdAtStartEpoch !== null
          && createdAtEpoch < createdAtStartEpoch
        ) {
          continue;
        }
        if (
          createdAtEndEpoch !== null
          && createdAtEpoch > createdAtEndEpoch
        ) {
          continue;
        }

        rows.push({
          org_id: orgId,
          org_name: resolvedOrgName,
          owner_name: ownerName,
          owner_phone: ownerPhone,
          status: normalizedStatus,
          created_at: createdAt
        });
      }

      rows.sort((left, right) =>
        String(left.org_id).localeCompare(String(right.org_id))
      );

      const total = rows.length;
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return {
        total,
        items: rows.slice(offset, offset + resolvedPageSize)
      };
    },

    upsertPlatformUserProfile: async ({
      userId,
      name,
      department = null
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId || !usersById.has(normalizedUserId)) {
        throw new Error('upsertPlatformUserProfile requires existing userId');
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
      const nextProfile = {
        name: normalizedName,
        department: normalizedDepartment
      };
      platformProfilesByUserId.set(normalizedUserId, nextProfile);
      return {
        user_id: normalizedUserId,
        ...nextProfile
      };
    },

    getSystemSensitiveConfig: async ({ configKey } = {}) => {
      const normalizedConfigKey = normalizeSystemSensitiveConfigKey(configKey);
      if (!normalizedConfigKey || !ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS.has(normalizedConfigKey)) {
        return null;
      }
      return cloneSystemSensitiveConfigRecord(
        systemSensitiveConfigsByKey.get(normalizedConfigKey) || null
      );
    },

    upsertSystemSensitiveConfig: async ({
      configKey,
      encryptedValue,
      expectedVersion,
      updatedByUserId,
      status = 'active'
    } = {}) => {
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
      const normalizedUpdatedByUserId = String(updatedByUserId || '').trim();
      if (!normalizedUpdatedByUserId || !usersById.has(normalizedUpdatedByUserId)) {
        throw new Error('upsertSystemSensitiveConfig requires existing updatedByUserId');
      }
      const normalizedStatus = normalizeSystemSensitiveConfigStatus(status);
      if (!normalizedStatus) {
        throw new Error('upsertSystemSensitiveConfig received unsupported status');
      }
      const parsedExpectedVersion = Number(expectedVersion);
      if (
        !Number.isInteger(parsedExpectedVersion)
        || parsedExpectedVersion < 0
      ) {
        throw new Error('upsertSystemSensitiveConfig requires expectedVersion >= 0');
      }

      const existingRecord = systemSensitiveConfigsByKey.get(normalizedConfigKey) || null;
      const currentVersion = existingRecord ? Number(existingRecord.version || 0) : 0;
      if (parsedExpectedVersion !== currentVersion) {
        const conflictError = new Error('system sensitive config version conflict');
        conflictError.code = 'ERR_SYSTEM_SENSITIVE_CONFIG_VERSION_CONFLICT';
        conflictError.currentVersion = currentVersion;
        conflictError.expectedVersion = parsedExpectedVersion;
        conflictError.configKey = normalizedConfigKey;
        throw conflictError;
      }

      const nextVersion = currentVersion + 1;
      const nowIso = new Date().toISOString();
      const nextRecord = {
        configKey: normalizedConfigKey,
        encryptedValue: normalizedEncryptedValue,
        version: nextVersion,
        previousVersion: currentVersion,
        status: normalizedStatus,
        updatedByUserId: normalizedUpdatedByUserId,
        updatedAt: nowIso,
        createdByUserId: existingRecord?.createdByUserId || normalizedUpdatedByUserId,
        createdAt: existingRecord?.createdAt || nowIso
      };
      systemSensitiveConfigsByKey.set(normalizedConfigKey, nextRecord);
      return cloneSystemSensitiveConfigRecord(nextRecord);
    },

    countPlatformRoleCatalogEntries: async () => platformRoleCatalogById.size,

    listPlatformRoleCatalogEntries: async ({
      scope = 'platform',
      tenantId = null
    } = {}) => {
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      return [...platformRoleCatalogById.values()]
        .filter((entry) => {
          if (normalizePlatformRoleCatalogScope(entry.scope) !== normalizedScope) {
            return false;
          }
          if (normalizedScope === 'tenant') {
            return String(entry.tenantId || '') === normalizedTenantId;
          }
          return String(entry.tenantId || '') === '';
        })
        .sort((left, right) => {
          const leftCreatedAt = new Date(left.createdAt).getTime();
          const rightCreatedAt = new Date(right.createdAt).getTime();
          if (leftCreatedAt !== rightCreatedAt) {
            return leftCreatedAt - rightCreatedAt;
          }
          return String(left.roleId || '').localeCompare(String(right.roleId || ''));
        })
        .map((entry) => clonePlatformRoleCatalogRecord(entry));
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
      const normalizedTenantId = hasScopeFilter
        ? normalizePlatformRoleCatalogTenantIdForScope({
          scope: normalizedScope,
          tenantId
        })
        : null;
      const existingState = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      );
      const existing = existingState?.record || null;
      if (!existing) {
        return null;
      }
      if (
        hasScopeFilter
        && normalizePlatformRoleCatalogScope(existing.scope) !== normalizedScope
      ) {
        return null;
      }
      if (
        hasScopeFilter
        && normalizedScope === 'tenant'
        && String(existing.tenantId || '') !== normalizedTenantId
      ) {
        return null;
      }
      if (
        hasScopeFilter
        && normalizedScope !== 'tenant'
        && String(existing.tenantId || '') !== ''
      ) {
        return null;
      }
      return clonePlatformRoleCatalogRecord(existing);
    },

    findPlatformRoleCatalogEntriesByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIdKeys = new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
          .map((roleId) => roleId.toLowerCase())
      );
      if (normalizedRoleIdKeys.size === 0) {
        return [];
      }
      const matches = [];
      for (const [roleId, entry] of platformRoleCatalogById.entries()) {
        if (!normalizedRoleIdKeys.has(String(roleId).toLowerCase())) {
          continue;
        }
        matches.push(clonePlatformRoleCatalogRecord(entry));
      }
      return matches;
    },

    getPlatformUserById: async ({ userId } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }
      if (!platformDomainKnownByUserId.has(normalizedUserId)) {
        return null;
      }
      const userRecord = usersById.get(normalizedUserId);
      if (!userRecord) {
        return null;
      }
      return resolvePlatformUserReadModel({
        userId: normalizedUserId,
        userRecord
      });
    },

    createSession: async ({
      sessionId,
      userId,
      sessionVersion,
      entryDomain = 'platform',
      activeTenantId = null
    }) => {
      sessionsById.set(sessionId, {
        sessionId,
        userId: String(userId),
        sessionVersion: Number(sessionVersion),
        entryDomain: String(entryDomain || 'platform').toLowerCase(),
        activeTenantId: activeTenantId ? String(activeTenantId) : null,
        status: 'active',
        revokedReason: null,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findSessionById: async (sessionId) => clone(sessionsById.get(sessionId) || null),

    updateSessionContext: async ({ sessionId, entryDomain, activeTenantId }) => {
      const session = sessionsById.get(sessionId);
      if (!session) {
        return false;
      }

      if (entryDomain !== undefined) {
        session.entryDomain = String(entryDomain || 'platform').toLowerCase();
      }
      if (activeTenantId !== undefined) {
        session.activeTenantId = activeTenantId ? String(activeTenantId) : null;
      }
      session.updatedAt = Date.now();
      sessionsById.set(sessionId, session);
      return true;
    },

    findDomainAccessByUserId: async (userId) => {
      const userDomains = domainsByUserId.get(String(userId)) || new Set();
      return {
        platform: userDomains.has('platform'),
        tenant: userDomains.has('tenant')
      };
    },

    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (userDomains.has('platform')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        platformDomainKnownByUserId.add(normalizedUserId);
        return { inserted: false };
      }
      if (platformDomainKnownByUserId.has(normalizedUserId)) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }
      userDomains.add('platform');
      domainsByUserId.set(normalizedUserId, userDomains);
      platformDomainKnownByUserId.add(normalizedUserId);
      return { inserted: true };
    },

    ensureTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      const hasActiveTenantUsership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantUsershipActiveForAuth(tenant)
      );
      if (!hasActiveTenantUsership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      userDomains.add('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: true };
    },

    listTenantOptionsByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || [])
        .filter((tenant) => isTenantUsershipActiveForAuth(tenant))
        .map((tenant) => ({ ...tenant })),

    hasAnyTenantRelationshipByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || []).length > 0,

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      const tenant = (tenantsByUserId.get(String(userId)) || []).find(
        (item) =>
          String(item.tenantId) === normalizedTenantId
          && isTenantUsershipActiveForAuth(item)
      );
      if (!tenant) {
        return null;
      }
      if (tenant.permission) {
        return {
          scopeLabel: tenant.permission.scopeLabel || `组织权限（${tenant.tenantName || tenant.tenantId}）`,
          canViewUserManagement: Boolean(tenant.permission.canViewUserManagement),
          canOperateUserManagement: Boolean(tenant.permission.canOperateUserManagement),
          canViewRoleManagement: Boolean(tenant.permission.canViewRoleManagement),
          canOperateRoleManagement: Boolean(tenant.permission.canOperateRoleManagement)
        };
      }
      return null;
    },

    findPlatformPermissionByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return null;
      }
      const permission = platformPermissionsByUserId.get(normalizedUserId);
      return permission ? { ...permission } : null;
    },

    hasPlatformPermissionByUserId: async ({
      userId,
      permissionCode
    } = {}) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedPermissionCode = toPlatformPermissionCodeKey(permissionCode);
      if (
        !normalizedUserId
        || !normalizedPermissionCode
        || (
          normalizedPermissionCode !== PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE
          && normalizedPermissionCode !== PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
        )
      ) {
        return {
          canViewRoleManagement: false,
          canOperateRoleManagement: false,
          granted: false
        };
      }

      const roles = platformRolesByUserId.get(normalizedUserId) || [];
      let canViewRoleManagement = false;
      let canOperateRoleManagement = false;

      for (const role of roles) {
        if (!role || !isActiveLikeStatus(role.status)) {
          continue;
        }
        const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
          role.roleId
        )?.record || null;
        if (roleCatalogEntry) {
          const roleCatalogScope = normalizePlatformRoleCatalogScope(
            roleCatalogEntry.scope
          );
          const roleCatalogTenantId = normalizePlatformRoleCatalogTenantId(
            roleCatalogEntry.tenantId
          );
          const roleCatalogStatus = normalizePlatformRoleCatalogStatus(
            roleCatalogEntry.status
          );
          if (
            roleCatalogScope !== 'platform'
            || roleCatalogTenantId !== ''
            || !isActiveLikeStatus(roleCatalogStatus)
          ) {
            continue;
          }
        }
        const permission = role.permission || {};
        if (Boolean(permission.canViewRoleManagement ?? permission.can_view_role_management)) {
          canViewRoleManagement = true;
        }
        if (Boolean(permission.canOperateRoleManagement ?? permission.can_operate_role_management)) {
          canOperateRoleManagement = true;
          canViewRoleManagement = true;
        }

        const grantCodes = listPlatformRolePermissionGrantsForRoleId(role.roleId);
        if (grantCodes.includes(PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE)) {
          canOperateRoleManagement = true;
          canViewRoleManagement = true;
        } else if (grantCodes.includes(PLATFORM_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE)) {
          canViewRoleManagement = true;
        }

        if (canViewRoleManagement && canOperateRoleManagement) {
          break;
        }
      }

      const granted = normalizedPermissionCode === PLATFORM_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
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
      syncPlatformPermissionFromRoleFacts({
        userId,
        forceWhenNoRoleFacts
      }),

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      refreshTokensByHash.set(tokenHash, {
        tokenHash,
        sessionId,
        userId: String(userId),
        status: 'active',
        rotatedFrom: null,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });
    },

    findRefreshTokenByHash: async (tokenHash) => clone(refreshTokensByHash.get(tokenHash) || null),

    markRefreshTokenStatus: async ({ tokenHash, status }) => {
      const token = refreshTokensByHash.get(tokenHash);
      if (!token) {
        return;
      }

      token.status = status;
      token.updatedAt = Date.now();
    },

    linkRefreshRotation: async ({ previousTokenHash, nextTokenHash }) => {
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (previous) {
        previous.rotatedTo = nextTokenHash;
        previous.updatedAt = Date.now();
      }

      const next = refreshTokensByHash.get(nextTokenHash);
      if (next) {
        next.rotatedFrom = previousTokenHash;
        next.updatedAt = Date.now();
      }
    },

    rotateRefreshToken: async ({ previousTokenHash, nextTokenHash, sessionId, userId, expiresAt }) => {
      const normalizedSessionId = String(sessionId);
      const normalizedUserId = String(userId);
      const previous = refreshTokensByHash.get(previousTokenHash);
      if (
        !previous
        || previous.status !== 'active'
        || String(previous.sessionId || '') !== normalizedSessionId
        || String(previous.userId || '') !== normalizedUserId
      ) {
        return { ok: false };
      }

      previous.status = 'rotated';
      previous.rotatedTo = nextTokenHash;
      previous.updatedAt = Date.now();

      refreshTokensByHash.set(nextTokenHash, {
        tokenHash: nextTokenHash,
        sessionId: normalizedSessionId,
        userId: normalizedUserId,
        status: 'active',
        rotatedFrom: previousTokenHash,
        rotatedTo: null,
        expiresAt,
        createdAt: Date.now(),
        updatedAt: Date.now()
      });

      return { ok: true };
    },

    revokeSession: async ({ sessionId, reason }) => {
      const session = sessionsById.get(sessionId);
      if (session && session.status === 'active') {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.sessionId === sessionId && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    revokeAllUserSessions: async ({ userId, reason }) => {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }

      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    },

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: 'password-changed',
        revokeRefreshTokens: false,
        revokeAuthSessions: false
      });
      return clone(user);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) => {
      const user = bumpSessionVersionAndConvergeSessions({
        userId,
        passwordHash,
        reason: reason || 'password-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
      return clone(user);
    }
  };
};

module.exports = {
  createMemoryAuthStoreCapabilities
};
