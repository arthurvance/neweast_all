'use strict';

const createPlatformMemoryAuthStoreRepositoryGovernanceRead = ({
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
  const MAX_SYSTEM_SENSITIVE_CONFIG_REMARK_LENGTH = 255;
  return {
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
      remark,
      hasRemark = false,
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
      let normalizedRemark = '';
      if (hasRemark) {
        if (remark === null || remark === undefined) {
          normalizedRemark = '';
        } else if (typeof remark === 'string') {
          normalizedRemark = remark.trim();
        } else {
          throw new Error('upsertSystemSensitiveConfig received invalid remark');
        }
        if (
          CONTROL_CHAR_PATTERN.test(normalizedRemark)
          || normalizedRemark.length > MAX_SYSTEM_SENSITIVE_CONFIG_REMARK_LENGTH
        ) {
          throw new Error('upsertSystemSensitiveConfig received invalid remark');
        }
      }
      const nextRecord = {
        key: normalizedConfigKey,
        configKey: normalizedConfigKey,
        value: normalizedEncryptedValue,
        encryptedValue: normalizedEncryptedValue,
        remark: hasRemark
          ? (normalizedRemark || null)
          : (existingRecord?.remark || null),
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
  };
};

module.exports = {
  createPlatformMemoryAuthStoreRepositoryGovernanceRead
};
