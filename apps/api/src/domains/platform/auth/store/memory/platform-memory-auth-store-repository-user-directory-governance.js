'use strict';

const createPlatformMemoryAuthStoreRepositoryUserDirectoryGovernance = ({
  CONTROL_CHAR_PATTERN,
  MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
  MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
  VALID_ORG_STATUS,
  VALID_PLATFORM_USER_STATUS,
  normalizeDateTimeFilterToEpoch,
  normalizeOptionalPlatformUserProfileField,
  normalizeOrgStatus,
  normalizeRequiredPlatformUserProfileField,
  orgsById,
  platformDomainKnownByUserId,
  platformProfilesByUserId,
  resolveLatestTenantUserProfileByUserId,
  resolvePlatformUserReadModel,
  usersById
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
});

module.exports = {
  createPlatformMemoryAuthStoreRepositoryUserDirectoryGovernance
};
