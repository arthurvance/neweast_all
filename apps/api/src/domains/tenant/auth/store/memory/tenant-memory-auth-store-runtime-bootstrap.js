'use strict';

const createTenantMemoryAuthStoreRuntimeBootstrap = (dependencies = {}) => {
  const {
    CONTROL_CHAR_PATTERN,
    KNOWN_TENANT_PERMISSION_CODES,
    KNOWN_TENANT_PERMISSION_CODE_SET,
    MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH,
    MAX_TENANT_USER_DISPLAY_NAME_LENGTH,
    ROLE_ID_ADDRESSABLE_PATTERN,
    VALID_TENANT_MEMBERSHIP_STATUS,
    findPlatformRoleCatalogRecordStateByRoleId,
    isActiveLikeStatus,
    isSamePlatformPermission,
    mergePlatformPermission,
    normalizePlatformPermission,
    normalizeOrgStatus,
    normalizePlatformRoleCatalogRoleId,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogTenantId,
    orgsById,
    revokeTenantSessionsForUser,
    tenantRolePermissionGrantsByRoleId,
    tenantUsershipHistoryByPair,
    tenantUsershipRolesByMembershipId,
    tenantsByUserId,
    toTenantPermissionSnapshotFromCodes
  } = dependencies;

  const normalizeTenantUsershipStatus = (status) => {
    const normalizedStatus = String(status ?? '').trim().toLowerCase();
    if (!normalizedStatus) {
      return 'active';
    }
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedStatus)
      ? normalizedStatus
      : '';
  };
  const normalizeTenantUsershipStatusForRead = (status) => {
    const normalizedStatus = String(status ?? '').trim().toLowerCase();
    if (!normalizedStatus) {
      return '';
    }
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedStatus)
      ? normalizedStatus
      : '';
  };
  const normalizeOptionalTenantUserProfileField = ({
    value,
    maxLength
  } = {}) => {
    if (value === null || value === undefined) {
      return null;
    }
    if (typeof value !== 'string') {
      return null;
    }
    const normalized = value.trim();
    if (
      !normalized
      || normalized.length > maxLength
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return null;
    }
    return normalized;
  };
  const resolveOptionalTenantUserProfileField = (value) =>
    value === null || value === undefined
      ? null
      : value;
  const isStrictOptionalTenantUserProfileField = ({
    value,
    maxLength
  } = {}) => {
    const resolvedRawValue = resolveOptionalTenantUserProfileField(value);
    if (resolvedRawValue === null) {
      return true;
    }
    if (typeof resolvedRawValue !== 'string') {
      return false;
    }
    const normalized = normalizeOptionalTenantUserProfileField({
      value: resolvedRawValue,
      maxLength
    });
    return normalized !== null && normalized === resolvedRawValue;
  };
  const appendTenantUsershipHistory = ({
    membership = null,
    reason = null,
    operatorUserId = null
  } = {}) => {
    const normalizedTenantId = String(
      membership?.tenantId || membership?.tenant_id || ''
    ).trim();
    const normalizedUserId = String(
      membership?.userId || membership?.user_id || ''
    ).trim();
    if (!normalizedTenantId || !normalizedUserId) {
      return;
    }
    const pairKey = `${normalizedTenantId}::${normalizedUserId}`;
    const history = tenantUsershipHistoryByPair.get(pairKey) || [];
    history.push({
      membershipId: String(
        membership?.membershipId || membership?.membership_id || ''
      ).trim(),
      userId: normalizedUserId,
      tenantId: normalizedTenantId,
      tenantName:
        membership?.tenantName === null || membership?.tenantName === undefined
          ? null
          : String(membership.tenantName || '').trim() || null,
      status: normalizeTenantUsershipStatusForRead(membership?.status),
      archivedReason: reason ? String(reason).trim() : null,
      archivedByUserId:
        operatorUserId === null || operatorUserId === undefined
          ? null
          : String(operatorUserId).trim() || null,
      archivedAt: new Date().toISOString()
    });
    tenantUsershipHistoryByPair.set(pairKey, history);
  };
  const isTenantUsershipActiveForAuth = (tenantUsership) => {
    if (!isActiveLikeStatus(normalizeTenantUsershipStatusForRead(tenantUsership?.status))) {
      return false;
    }
    const tenantId = String(
      tenantUsership?.tenantId || tenantUsership?.tenant_id || ''
    ).trim();
    if (!tenantId) {
      return false;
    }
    const org = orgsById.get(tenantId);
    if (!org) {
      return orgsById.size === 0;
    }
    return isActiveLikeStatus(normalizeOrgStatus(org.status));
  };
  const normalizeTenantPermissionCode = (permissionCode) =>
    String(permissionCode || '').trim();
  const toTenantPermissionCodeKey = (permissionCode) =>
    normalizeTenantPermissionCode(permissionCode).toLowerCase();
  const normalizeTenantPermissionCodes = (permissionCodes = []) => {
    const deduped = new Map();
    for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
      const normalizedCode = normalizeTenantPermissionCode(permissionCode);
      if (!normalizedCode) {
        continue;
      }
      const permissionCodeKey = toTenantPermissionCodeKey(normalizedCode);
      deduped.set(permissionCodeKey, permissionCodeKey);
    }
    return [...deduped.values()];
  };
  const createTenantRolePermissionGrantDataError = (
    reason = 'tenant-role-permission-grants-invalid'
  ) => {
    const error = new Error('tenant role permission grants invalid');
    error.code = 'ERR_TENANT_ROLE_PERMISSION_GRANTS_INVALID';
    error.reason = String(reason || 'tenant-role-permission-grants-invalid')
      .trim()
      .toLowerCase();
    return error;
  };
  const normalizeStrictTenantPermissionCodeFromGrantRow = (
    permissionCode,
    reason = 'tenant-role-permission-grants-invalid'
  ) => {
    if (typeof permissionCode !== 'string') {
      throw createTenantRolePermissionGrantDataError(reason);
    }
    const normalizedPermissionCode = normalizeTenantPermissionCode(permissionCode);
    const permissionCodeKey = toTenantPermissionCodeKey(normalizedPermissionCode);
    if (
      permissionCode !== normalizedPermissionCode
      || !normalizedPermissionCode
      || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
      || !KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCodeKey)
    ) {
      throw createTenantRolePermissionGrantDataError(reason);
    }
    return permissionCodeKey;
  };
  const normalizeStrictTenantRolePermissionGrantIdentity = (
    identityValue,
    reason = 'tenant-role-permission-grants-invalid-identity'
  ) => {
    if (typeof identityValue !== 'string') {
      throw createTenantRolePermissionGrantDataError(reason);
    }
    const normalizedIdentity = identityValue.trim();
    if (
      !normalizedIdentity
      || identityValue !== normalizedIdentity
      || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
    ) {
      throw createTenantRolePermissionGrantDataError(reason);
    }
    return normalizedIdentity;
  };
  const createTenantUsershipRoleBindingDataError = (
    reason = 'tenant-membership-role-bindings-invalid'
  ) => {
    const error = new Error('tenant usership role bindings invalid');
    error.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID';
    error.reason = String(reason || 'tenant-membership-role-bindings-invalid')
      .trim()
      .toLowerCase();
    return error;
  };
  const normalizeStrictTenantUsershipRoleIdFromBindingRow = (
    roleId,
    reason = 'tenant-membership-role-bindings-invalid-role-id'
  ) => {
    if (typeof roleId !== 'string') {
      throw createTenantUsershipRoleBindingDataError(reason);
    }
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (
      roleId !== roleId.trim()
      || !normalizedRoleId
      || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
      || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
    ) {
      throw createTenantUsershipRoleBindingDataError(reason);
    }
    return normalizedRoleId;
  };
  const normalizeStrictTenantUsershipRoleBindingIdentity = (
    identityValue,
    reason = 'tenant-membership-role-bindings-invalid-identity'
  ) => {
    if (typeof identityValue !== 'string') {
      throw createTenantUsershipRoleBindingDataError(reason);
    }
    const normalizedIdentity = identityValue.trim();
    if (
      !normalizedIdentity
      || identityValue !== normalizedIdentity
      || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
    ) {
      throw createTenantUsershipRoleBindingDataError(reason);
    }
    return normalizedIdentity;
  };
  const buildEmptyTenantPermission = (scopeLabel = '组织权限（角色并集）') => ({
    scopeLabel,
    canViewUserManagement: false,
    canOperateUserManagement: false,
    canViewAccountManagement: false,
    canOperateAccountManagement: false,
    canViewRoleManagement: false,
    canOperateRoleManagement: false
  });
  const resolveTenantPermissionFromGrantCodes = (permissionCodes = []) => {
    return {
      ...buildEmptyTenantPermission(),
      ...toTenantPermissionSnapshotFromCodes(
        normalizeTenantPermissionCodes(permissionCodes)
      )
    };
  };
  const listTenantRolePermissionGrantsForRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return [];
    }
    const normalizedPermissionCodeKeys = [];
    const seenPermissionCodeKeys = new Set();
    for (const permissionCode of tenantRolePermissionGrantsByRoleId.get(normalizedRoleId) || []) {
      const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
        permissionCode,
        'tenant-role-permission-grants-invalid-permission-code'
      );
      if (seenPermissionCodeKeys.has(permissionCodeKey)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-duplicate-permission-code'
        );
      }
      seenPermissionCodeKeys.add(permissionCodeKey);
      normalizedPermissionCodeKeys.push(permissionCodeKey);
    }
    return normalizedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
  };
  const replaceTenantRolePermissionGrantsForRoleId = ({
    roleId,
    permissionCodes = []
  }) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      throw new Error('replaceTenantRolePermissionGrants requires roleId');
    }
    const normalizedPermissionCodes = normalizeTenantPermissionCodes(permissionCodes)
      .filter((permissionCode) =>
        KNOWN_TENANT_PERMISSION_CODES.includes(permissionCode)
      );
    tenantRolePermissionGrantsByRoleId.set(
      normalizedRoleId,
      normalizedPermissionCodes
    );
    return listTenantRolePermissionGrantsForRoleId(normalizedRoleId);
  };
  const findTenantUsershipStateByMembershipId = (membershipId) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return null;
    }
    for (const [userId, memberships] of tenantsByUserId.entries()) {
      for (const membership of Array.isArray(memberships) ? memberships : []) {
        if (String(membership?.membershipId || '').trim() !== normalizedMembershipId) {
          continue;
        }
        return {
          userId: String(userId || '').trim(),
          memberships,
          membership
        };
      }
    }
    return null;
  };

  const listTenantUsershipRoleBindingsForMembershipId = ({
    membershipId,
    tenantId = undefined
  } = {}) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return [];
    }
    const membershipState = findTenantUsershipStateByMembershipId(normalizedMembershipId);
    if (!membershipState) {
      return [];
    }
    if (tenantId !== undefined && tenantId !== null) {
      const normalizedTenantId = String(tenantId || '').trim();
      const membershipTenantId = String(
        membershipState.membership?.tenantId || membershipState.membership?.tenant_id || ''
      ).trim();
      if (membershipTenantId !== normalizedTenantId) {
        return [];
      }
    }
    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const rawRoleId of tenantUsershipRolesByMembershipId.get(normalizedMembershipId) || []) {
      const normalizedRoleId = normalizeStrictTenantUsershipRoleIdFromBindingRow(
        rawRoleId,
        'tenant-membership-role-bindings-invalid-role-id'
      );
      if (seenRoleIds.has(normalizedRoleId)) {
        throw createTenantUsershipRoleBindingDataError(
          'tenant-membership-role-bindings-duplicate-role-id'
        );
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const replaceTenantUsershipRoleBindingsForMembershipId = ({
    membershipId,
    roleIds = []
  } = {}) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      throw new Error('replaceTenantUsershipRoleBindings requires membershipId');
    }
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
        .filter((roleId) => roleId.length > 0)
    )].sort((left, right) => left.localeCompare(right));
    tenantUsershipRolesByMembershipId.set(normalizedMembershipId, normalizedRoleIds);
    return listTenantUsershipRoleBindingsForMembershipId({
      membershipId: normalizedMembershipId
    });
  };

  const toTenantUsershipScopeLabel = (membership = null) => {
    const tenantId = String(
      membership?.tenantId || membership?.tenant_id || ''
    ).trim();
    const tenantName = membership?.tenantName === null || membership?.tenantName === undefined
      ? null
      : String(membership?.tenantName || '').trim() || null;
    return `组织权限（${tenantName || tenantId || '未知组织'}）`;
  };

  const resolveEffectiveTenantPermissionForMembership = ({
    membership = null,
    roleIds = []
  } = {}) => {
    const scopeLabel = toTenantUsershipScopeLabel(membership);
    if (!membership || !isTenantUsershipActiveForAuth(membership)) {
      return buildEmptyTenantPermission(scopeLabel);
    }
    const membershipTenantId = String(
      membership?.tenantId || membership?.tenant_id || ''
    ).trim();
    let mergedPermission = null;
    for (const roleId of Array.isArray(roleIds) ? roleIds : []) {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        continue;
      }
      const catalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      )?.record;
      if (!catalogEntry) {
        continue;
      }
      const normalizedCatalogScope = normalizePlatformRoleCatalogScope(catalogEntry.scope);
      const normalizedCatalogTenantId = normalizePlatformRoleCatalogTenantId(
        catalogEntry.tenantId
      );
      const normalizedCatalogStatus = normalizePlatformRoleCatalogStatus(
        catalogEntry.status
      );
      if (
        normalizedCatalogScope !== 'tenant'
        || normalizedCatalogTenantId !== membershipTenantId
        || !isActiveLikeStatus(normalizedCatalogStatus)
      ) {
        continue;
      }
      const rolePermission = resolveTenantPermissionFromGrantCodes(
        listTenantRolePermissionGrantsForRoleId(normalizedRoleId)
      );
      mergedPermission = mergePlatformPermission(mergedPermission, rolePermission);
    }
    if (!mergedPermission) {
      return buildEmptyTenantPermission(scopeLabel);
    }
    return {
      ...mergedPermission,
      scopeLabel
    };
  };

  const syncTenantUsershipPermissionSnapshot = ({
    membershipState = null,
    reason = 'tenant-membership-permission-changed',
    revokeSessions = true
  } = {}) => {
    const targetMembershipState = membershipState
      || null;
    if (
      !targetMembershipState
      || !targetMembershipState.membership
      || !targetMembershipState.memberships
    ) {
      return {
        synced: false,
        reason: 'membership-not-found',
        changed: false,
        permission: null,
        roleIds: []
      };
    }
    const membership = targetMembershipState.membership;
    const membershipId = String(membership.membershipId || '').trim();
    const tenantId = String(membership.tenantId || '').trim();
    const userId = String(targetMembershipState.userId || '').trim();
    const roleIds = listTenantUsershipRoleBindingsForMembershipId({
      membershipId,
      tenantId
    });
    const previousPermission = normalizePlatformPermission(
      membership.permission,
      toTenantUsershipScopeLabel(membership)
    ) || buildEmptyTenantPermission(toTenantUsershipScopeLabel(membership));
    const nextPermission = resolveEffectiveTenantPermissionForMembership({
      membership,
      roleIds
    });
    const changed = !isSamePlatformPermission(previousPermission, nextPermission);
    membership.permission = { ...nextPermission };
    if (revokeSessions && changed && userId && tenantId) {
      revokeTenantSessionsForUser({
        userId,
        reason,
        activeTenantId: tenantId
      });
    }
    return {
      synced: true,
      reason: 'ok',
      changed,
      permission: { ...nextPermission },
      roleIds: [...roleIds],
      userId,
      membershipId,
      tenantId
    };
  };
  const resolveLatestTenantUserProfileByUserId = (userId) => {
    const memberships = Array.isArray(tenantsByUserId.get(userId))
      ? tenantsByUserId.get(userId)
      : [];
    if (memberships.length < 1) {
      return {
        name: null,
        department: null
      };
    }
    const sortedMemberships = [...memberships].sort((left, right) => {
      const leftJoinedAt = new Date(
        left?.joinedAt || left?.joined_at || 0
      ).getTime();
      const rightJoinedAt = new Date(
        right?.joinedAt || right?.joined_at || 0
      ).getTime();
      return rightJoinedAt - leftJoinedAt;
    });
    for (const membership of sortedMemberships) {
      const resolvedName = normalizeOptionalTenantUserProfileField({
        value: membership?.displayName ?? membership?.display_name ?? null,
        maxLength: MAX_TENANT_USER_DISPLAY_NAME_LENGTH
      });
      const resolvedDepartment = normalizeOptionalTenantUserProfileField({
        value: membership?.departmentName ?? membership?.department_name ?? null,
        maxLength: MAX_TENANT_USER_DEPARTMENT_NAME_LENGTH
      });
      if (resolvedName !== null || resolvedDepartment !== null) {
        return {
          name: resolvedName,
          department: resolvedDepartment
        };
      }
    }
    return {
      name: null,
      department: null
    };
  };

  return {
    normalizeTenantUsershipStatus,
    normalizeTenantUsershipStatusForRead,
    normalizeOptionalTenantUserProfileField,
    resolveOptionalTenantUserProfileField,
    isStrictOptionalTenantUserProfileField,
    appendTenantUsershipHistory,
    isTenantUsershipActiveForAuth,
    normalizeTenantPermissionCode,
    toTenantPermissionCodeKey,
    normalizeTenantPermissionCodes,
    createTenantRolePermissionGrantDataError,
    normalizeStrictTenantPermissionCodeFromGrantRow,
    normalizeStrictTenantRolePermissionGrantIdentity,
    createTenantUsershipRoleBindingDataError,
    normalizeStrictTenantUsershipRoleIdFromBindingRow,
    normalizeStrictTenantUsershipRoleBindingIdentity,
    buildEmptyTenantPermission,
    resolveTenantPermissionFromGrantCodes,
    listTenantRolePermissionGrantsForRoleId,
    replaceTenantRolePermissionGrantsForRoleId,
    findTenantUsershipStateByMembershipId,
    listTenantUsershipRoleBindingsForMembershipId,
    replaceTenantUsershipRoleBindingsForMembershipId,
    toTenantUsershipScopeLabel,
    resolveEffectiveTenantPermissionForMembership,
    syncTenantUsershipPermissionSnapshot,
    resolveLatestTenantUserProfileByUserId,
  };
};

module.exports = {
  createTenantMemoryAuthStoreRuntimeBootstrap
};
