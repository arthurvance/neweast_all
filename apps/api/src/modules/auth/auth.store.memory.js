const { randomUUID } = require('node:crypto');
const { normalizeTraceparent } = require('../../common/trace-context');

const createInMemoryAuthStore = ({
  seedUsers = [],
  hashPassword,
  faultInjector = null
}) => {
  const usersByPhone = new Map();
  const usersById = new Map();
  const sessionsById = new Map();
  const refreshTokensByHash = new Map();
  const domainsByUserId = new Map();
  const platformDomainKnownByUserId = new Set();
  const tenantsByUserId = new Map();
  const platformRolesByUserId = new Map();
  const platformPermissionsByUserId = new Map();
  const platformRoleCatalogById = new Map();
  const platformRoleCatalogCodeIndex = new Map();
  const platformRolePermissionGrantsByRoleId = new Map();
  const tenantRolePermissionGrantsByRoleId = new Map();
  const tenantMembershipRolesByMembershipId = new Map();
  const systemSensitiveConfigsByKey = new Map();
  const orgsById = new Map();
  const tenantMembershipHistoryByPair = new Map();
  const ownerTransferLocksByOrgId = new Map();
  const orgIdByName = new Map();
  const membershipsByOrgId = new Map();
  const auditEvents = [];
  const AUDIT_EVENT_ALLOWED_DOMAINS = new Set(['platform', 'tenant']);
  const AUDIT_EVENT_ALLOWED_RESULTS = new Set(['success', 'rejected', 'failed']);
  const AUDIT_EVENT_REDACTION_KEY_PATTERN =
    /(password|token|secret|credential|private[_-]?key|access[_-]?key|api[_-]?key|signing[_-]?key)/i;
  const MAX_AUDIT_QUERY_PAGE_SIZE = 200;
  const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);
  const VALID_PLATFORM_ROLE_CATALOG_STATUS = new Set(['active', 'disabled']);
  const VALID_PLATFORM_ROLE_CATALOG_SCOPE = new Set(['platform', 'tenant']);
  const VALID_ORG_STATUS = new Set(['active', 'disabled']);
  const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
  const VALID_SYSTEM_SENSITIVE_CONFIG_STATUS = new Set(['active', 'disabled']);
  const ALLOWED_SYSTEM_SENSITIVE_CONFIG_KEYS = new Set(['auth.default_password']);
  const VALID_TENANT_MEMBERSHIP_STATUS = new Set(['active', 'disabled', 'left']);
  const MAX_ORG_NAME_LENGTH = 128;
  const MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH = 64;
  const MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH = 128;
  const KNOWN_PLATFORM_PERMISSION_CODES = Object.freeze([
    'platform.member_admin.view',
    'platform.member_admin.operate',
    'platform.system_config.view',
    'platform.system_config.operate',
    'platform.billing.view',
    'platform.billing.operate'
  ]);
  const KNOWN_TENANT_PERMISSION_CODES = Object.freeze([
    'tenant.member_admin.view',
    'tenant.member_admin.operate',
    'tenant.billing.view',
    'tenant.billing.operate'
  ]);
  const invokeFaultInjector = (hookName, payload = {}) => {
    if (!faultInjector || typeof faultInjector !== 'object') {
      return;
    }
    const hook = faultInjector[hookName];
    if (typeof hook === 'function') {
      hook(payload);
    }
  };
  const KNOWN_TENANT_PERMISSION_CODE_SET = new Set(KNOWN_TENANT_PERMISSION_CODES);
  const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
  const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
  const MAINLAND_PHONE_PATTERN = /^1\d{10}$/;
  const normalizeSystemSensitiveConfigKey = (configKey) =>
    String(configKey || '').trim().toLowerCase();
  const normalizeSystemSensitiveConfigStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return VALID_SYSTEM_SENSITIVE_CONFIG_STATUS.has(normalizedStatus)
      ? normalizedStatus
      : '';
  };
  const cloneSystemSensitiveConfigRecord = (record = null) =>
    record
      ? {
        configKey: record.configKey,
        encryptedValue: record.encryptedValue,
        version: Number(record.version),
        previousVersion: Number(record.previousVersion || 0),
        status: record.status,
        updatedByUserId: record.updatedByUserId,
        updatedAt: record.updatedAt,
        createdByUserId: record.createdByUserId,
        createdAt: record.createdAt
      }
      : null;

  const isActiveLikeStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    return normalizedStatus === 'active' || normalizedStatus === 'enabled';
  };
  const normalizeOrgStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    return normalizedStatus;
  };
  const normalizeTenantMembershipStatus = (status) => {
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
  const normalizeTenantMembershipStatusForRead = (status) => {
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
  const normalizeOptionalTenantMemberProfileField = ({
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
  const resolveOptionalTenantMemberProfileField = (value) =>
    value === null || value === undefined
      ? null
      : value;
  const isStrictOptionalTenantMemberProfileField = ({
    value,
    maxLength
  } = {}) => {
    const resolvedRawValue = resolveOptionalTenantMemberProfileField(value);
    if (resolvedRawValue === null) {
      return true;
    }
    if (typeof resolvedRawValue !== 'string') {
      return false;
    }
    const normalized = normalizeOptionalTenantMemberProfileField({
      value: resolvedRawValue,
      maxLength
    });
    return normalized !== null && normalized === resolvedRawValue;
  };
  const appendTenantMembershipHistory = ({
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
    const history = tenantMembershipHistoryByPair.get(pairKey) || [];
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
      status: normalizeTenantMembershipStatusForRead(membership?.status),
      archivedReason: reason ? String(reason).trim() : null,
      archivedByUserId:
        operatorUserId === null || operatorUserId === undefined
          ? null
          : String(operatorUserId).trim() || null,
      archivedAt: new Date().toISOString()
    });
    tenantMembershipHistoryByPair.set(pairKey, history);
  };
  const isTenantMembershipActiveForAuth = (tenantMembership) => {
    if (!isActiveLikeStatus(normalizeTenantMembershipStatusForRead(tenantMembership?.status))) {
      return false;
    }
    const tenantId = String(
      tenantMembership?.tenantId || tenantMembership?.tenant_id || ''
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

  const normalizePlatformRoleStatus = (status) => {
    if (status === null || status === undefined) {
      return 'active';
    }
    if (typeof status !== 'string') {
      throw new Error(`invalid platform role status: ${String(status)}`);
    }
    const normalizedStatus = status.trim().toLowerCase();
    if (!normalizedStatus) {
      throw new Error('invalid platform role status:');
    }
    if (!VALID_PLATFORM_ROLE_FACT_STATUS.has(normalizedStatus)) {
      throw new Error(`invalid platform role status: ${normalizedStatus}`);
    }
    return normalizedStatus;
  };
  const normalizePlatformRoleCatalogStatus = (status) => {
    const normalizedStatus = String(status || 'active').trim().toLowerCase();
    if (normalizedStatus === 'enabled') {
      return 'active';
    }
    if (!VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)) {
      throw new Error(`invalid platform role catalog status: ${normalizedStatus}`);
    }
    return normalizedStatus;
  };
  const normalizePlatformRoleCatalogScope = (scope) => {
    const normalizedScope = String(scope || 'platform').trim().toLowerCase();
    if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
      throw new Error(`invalid platform role catalog scope: ${normalizedScope}`);
    }
    return normalizedScope;
  };
  const normalizePlatformRoleCatalogTenantId = (tenantId) =>
    String(tenantId ?? '').trim();
  const normalizePlatformRoleCatalogTenantIdForScope = ({
    scope = 'platform',
    tenantId
  } = {}) => {
    const normalizedScope = normalizePlatformRoleCatalogScope(scope);
    const normalizedTenantId = normalizePlatformRoleCatalogTenantId(tenantId);
    if (normalizedScope === 'tenant') {
      if (!normalizedTenantId) {
        throw new Error('tenant role catalog entry requires tenantId');
      }
      return normalizedTenantId;
    }
    return '';
  };
  const normalizePlatformRoleCatalogRoleId = (roleId) =>
    String(roleId || '').trim().toLowerCase();
  const toPlatformRoleCatalogRoleIdKey = (roleId) =>
    normalizePlatformRoleCatalogRoleId(roleId).toLowerCase();
  const normalizePlatformRoleCatalogCode = (code) =>
    String(code || '').trim();
  const toPlatformRoleCatalogCodeKey = (code) =>
    normalizePlatformRoleCatalogCode(code).toLowerCase();
  const toPlatformRoleCatalogCodeIndexKey = ({
    scope = 'platform',
    tenantId = '',
    code = ''
  } = {}) =>
    [
      normalizePlatformRoleCatalogScope(scope),
      normalizePlatformRoleCatalogTenantIdForScope({ scope, tenantId }),
      toPlatformRoleCatalogCodeKey(code)
    ].join('::');
  const normalizePlatformPermissionCode = (permissionCode) =>
    String(permissionCode || '').trim();
  const toPlatformPermissionCodeKey = (permissionCode) =>
    normalizePlatformPermissionCode(permissionCode).toLowerCase();
  const createDuplicatePlatformRoleCatalogEntryError = ({ target = 'code' } = {}) => {
    const normalizedTarget = String(target || '').trim().toLowerCase();
    const resolvedTarget = normalizedTarget === 'role_id' ? 'role_id' : 'code';
    const error = new Error(
      resolvedTarget === 'role_id'
        ? 'duplicate platform role catalog role_id'
        : 'duplicate platform role catalog code'
    );
    error.code = 'ER_DUP_ENTRY';
    error.errno = 1062;
    error.conflictTarget = resolvedTarget;
    error.platformRoleCatalogConflictTarget = resolvedTarget;
    return error;
  };
  const toPlatformRoleCatalogRecord = (entry = {}) => ({
    roleId: String(entry.roleId || entry.role_id || '').trim(),
    tenantId: normalizePlatformRoleCatalogTenantIdForScope({
      scope: entry.scope,
      tenantId: entry.tenantId || entry.tenant_id
    }),
    code: String(entry.code || '').trim(),
    name: String(entry.name || '').trim(),
    status: normalizePlatformRoleCatalogStatus(entry.status),
    scope: normalizePlatformRoleCatalogScope(entry.scope),
    isSystem: Boolean(entry.isSystem ?? entry.is_system),
    createdByUserId: entry.createdByUserId || entry.created_by_user_id || null,
    updatedByUserId: entry.updatedByUserId || entry.updated_by_user_id || null,
    createdAt: entry.createdAt || entry.created_at || new Date().toISOString(),
    updatedAt: entry.updatedAt || entry.updated_at || new Date().toISOString()
  });
  const clonePlatformRoleCatalogRecord = (entry = null) =>
    entry
      ? {
        roleId: entry.roleId,
        tenantId: entry.tenantId,
        code: entry.code,
        name: entry.name,
        status: entry.status,
        scope: entry.scope,
        isSystem: entry.isSystem,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;

  const findPlatformRoleCatalogRecordStateByRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return null;
    }
    if (platformRoleCatalogById.has(normalizedRoleId)) {
      return {
        roleId: normalizedRoleId,
        record: platformRoleCatalogById.get(normalizedRoleId)
      };
    }
    const normalizedRoleIdKey = toPlatformRoleCatalogRoleIdKey(normalizedRoleId);
    for (const [existingRoleId, entry] of platformRoleCatalogById.entries()) {
      if (toPlatformRoleCatalogRoleIdKey(existingRoleId) !== normalizedRoleIdKey) {
        continue;
      }
      return {
        roleId: existingRoleId,
        record: entry
      };
    }
    return null;
  };

  const normalizePlatformPermission = (
    permission,
    fallbackScopeLabel = '平台权限快照（服务端）'
  ) => {
    if (!permission || typeof permission !== 'object') {
      return null;
    }
    return {
      scopeLabel: permission.scopeLabel || permission.scope_label || fallbackScopeLabel,
      canViewMemberAdmin: Boolean(
        permission.canViewMemberAdmin ?? permission.can_view_member_admin
      ),
      canOperateMemberAdmin: Boolean(
        permission.canOperateMemberAdmin ?? permission.can_operate_member_admin
      ),
      canViewBilling: Boolean(permission.canViewBilling ?? permission.can_view_billing),
      canOperateBilling: Boolean(
        permission.canOperateBilling ?? permission.can_operate_billing
      ),
      canViewSystemConfig: Boolean(
        permission.canViewSystemConfig ?? permission.can_view_system_config
      ),
      canOperateSystemConfig: Boolean(
        permission.canOperateSystemConfig ?? permission.can_operate_system_config
      )
    };
  };

  const mergePlatformPermission = (left, right) => {
    if (!left && !right) {
      return null;
    }
    if (!left) {
      return { ...right };
    }
    if (!right) {
      return { ...left };
    }
    return {
      scopeLabel: left.scopeLabel || right.scopeLabel || '平台权限快照（服务端）',
      canViewMemberAdmin:
        Boolean(left.canViewMemberAdmin) || Boolean(right.canViewMemberAdmin),
      canOperateMemberAdmin:
        Boolean(left.canOperateMemberAdmin) || Boolean(right.canOperateMemberAdmin),
      canViewBilling: Boolean(left.canViewBilling) || Boolean(right.canViewBilling),
      canOperateBilling:
        Boolean(left.canOperateBilling) || Boolean(right.canOperateBilling),
      canViewSystemConfig:
        Boolean(left.canViewSystemConfig) || Boolean(right.canViewSystemConfig),
      canOperateSystemConfig:
        Boolean(left.canOperateSystemConfig) || Boolean(right.canOperateSystemConfig)
    };
  };

  const buildEmptyPlatformPermission = (scopeLabel = '平台权限（角色并集）') => ({
    scopeLabel,
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false,
    canViewSystemConfig: false,
    canOperateSystemConfig: false
  });

  const normalizePlatformPermissionCodes = (permissionCodes = []) => {
    const deduped = new Map();
    for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
      const normalizedCode = normalizePlatformPermissionCode(permissionCode);
      if (!normalizedCode) {
        continue;
      }
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedCode);
      deduped.set(permissionCodeKey, permissionCodeKey);
    }
    return [...deduped.values()];
  };

  const resolvePlatformPermissionFromGrantCodes = (permissionCodes = []) => {
    const permission = buildEmptyPlatformPermission();
    for (const permissionCode of normalizePlatformPermissionCodes(permissionCodes)) {
      switch (toPlatformPermissionCodeKey(permissionCode)) {
        case 'platform.member_admin.view':
          permission.canViewMemberAdmin = true;
          break;
        case 'platform.member_admin.operate':
          permission.canViewMemberAdmin = true;
          permission.canOperateMemberAdmin = true;
          break;
        case 'platform.system_config.view':
          permission.canViewSystemConfig = true;
          break;
        case 'platform.system_config.operate':
          permission.canViewSystemConfig = true;
          permission.canOperateSystemConfig = true;
          break;
        case 'platform.billing.view':
          permission.canViewBilling = true;
          break;
        case 'platform.billing.operate':
          permission.canViewBilling = true;
          permission.canOperateBilling = true;
          break;
        default:
          break;
      }
    }
    return permission;
  };

  const listPlatformRolePermissionGrantsForRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return [];
    }
    return [
      ...new Set(
        (platformRolePermissionGrantsByRoleId.get(normalizedRoleId) || [])
          .map((permissionCode) => normalizePlatformPermissionCode(permissionCode))
          .filter((permissionCode) => permissionCode.length > 0)
      )
    ].sort((left, right) => left.localeCompare(right));
  };

  const replacePlatformRolePermissionGrantsForRoleId = ({
    roleId,
    permissionCodes = []
  }) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      throw new Error('replacePlatformRolePermissionGrants requires roleId');
    }
    const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes)
      .filter((permissionCode) =>
        KNOWN_PLATFORM_PERMISSION_CODES.includes(permissionCode)
      );
    platformRolePermissionGrantsByRoleId.set(
      normalizedRoleId,
      normalizedPermissionCodes
    );
    return listPlatformRolePermissionGrantsForRoleId(normalizedRoleId);
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
  const createTenantMembershipRoleBindingDataError = (
    reason = 'tenant-membership-role-bindings-invalid'
  ) => {
    const error = new Error('tenant membership role bindings invalid');
    error.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_INVALID';
    error.reason = String(reason || 'tenant-membership-role-bindings-invalid')
      .trim()
      .toLowerCase();
    return error;
  };
  const normalizeStrictTenantMembershipRoleIdFromBindingRow = (
    roleId,
    reason = 'tenant-membership-role-bindings-invalid-role-id'
  ) => {
    if (typeof roleId !== 'string') {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (
      roleId !== roleId.trim()
      || !normalizedRoleId
      || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
      || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
    ) {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    return normalizedRoleId;
  };
  const normalizeStrictTenantMembershipRoleBindingIdentity = (
    identityValue,
    reason = 'tenant-membership-role-bindings-invalid-identity'
  ) => {
    if (typeof identityValue !== 'string') {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    const normalizedIdentity = identityValue.trim();
    if (
      !normalizedIdentity
      || identityValue !== normalizedIdentity
      || CONTROL_CHAR_PATTERN.test(normalizedIdentity)
    ) {
      throw createTenantMembershipRoleBindingDataError(reason);
    }
    return normalizedIdentity;
  };
  const buildEmptyTenantPermission = (scopeLabel = '组织权限（角色并集）') => ({
    scopeLabel,
    canViewMemberAdmin: false,
    canOperateMemberAdmin: false,
    canViewBilling: false,
    canOperateBilling: false
  });
  const resolveTenantPermissionFromGrantCodes = (permissionCodes = []) => {
    const permission = buildEmptyTenantPermission();
    for (const permissionCode of normalizeTenantPermissionCodes(permissionCodes)) {
      switch (toTenantPermissionCodeKey(permissionCode)) {
        case 'tenant.member_admin.view':
          permission.canViewMemberAdmin = true;
          break;
        case 'tenant.member_admin.operate':
          permission.canViewMemberAdmin = true;
          permission.canOperateMemberAdmin = true;
          break;
        case 'tenant.billing.view':
          permission.canViewBilling = true;
          break;
        case 'tenant.billing.operate':
          permission.canViewBilling = true;
          permission.canOperateBilling = true;
          break;
        default:
          break;
      }
    }
    return permission;
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

  const isSamePlatformPermission = (left, right) => {
    const normalizedLeft = left || buildEmptyPlatformPermission();
    const normalizedRight = right || buildEmptyPlatformPermission();
    return (
      Boolean(normalizedLeft.canViewMemberAdmin) === Boolean(normalizedRight.canViewMemberAdmin)
      && Boolean(normalizedLeft.canOperateMemberAdmin) === Boolean(normalizedRight.canOperateMemberAdmin)
      && Boolean(normalizedLeft.canViewBilling) === Boolean(normalizedRight.canViewBilling)
      && Boolean(normalizedLeft.canOperateBilling) === Boolean(normalizedRight.canOperateBilling)
      && Boolean(normalizedLeft.canViewSystemConfig) === Boolean(normalizedRight.canViewSystemConfig)
      && Boolean(normalizedLeft.canOperateSystemConfig)
        === Boolean(normalizedRight.canOperateSystemConfig)
    );
  };

  const normalizePlatformRole = (role) => {
    const roleId = String(role?.roleId || role?.role_id || '').trim();
    if (!roleId) {
      return null;
    }
    const permissionSource = role?.permission || role;
    const hasExplicitPermissionPayload = Boolean(
      role?.permission
      || permissionSource?.canViewMemberAdmin !== undefined
      || permissionSource?.can_view_member_admin !== undefined
      || permissionSource?.canOperateMemberAdmin !== undefined
      || permissionSource?.can_operate_member_admin !== undefined
      || permissionSource?.canViewBilling !== undefined
      || permissionSource?.can_view_billing !== undefined
      || permissionSource?.canOperateBilling !== undefined
      || permissionSource?.can_operate_billing !== undefined
    );
    const rolePermissionFromPayload = normalizePlatformPermission(
      permissionSource,
      '平台权限（角色并集）'
    );
    const rolePermissionFromGrants = resolvePlatformPermissionFromGrantCodes(
      listPlatformRolePermissionGrantsForRoleId(roleId)
    );
    return {
      roleId,
      status: normalizePlatformRoleStatus(role?.status),
      permission: hasExplicitPermissionPayload
        ? rolePermissionFromPayload
        : rolePermissionFromGrants
    };
  };

  const dedupePlatformRolesByRoleId = (roles = []) => {
    const dedupedByRoleId = new Map();
    for (const role of Array.isArray(roles) ? roles : []) {
      const roleId = String(role?.roleId || '').trim();
      const dedupeKey = roleId.toLowerCase();
      if (!dedupeKey) {
        continue;
      }
      dedupedByRoleId.set(dedupeKey, role);
    }
    return [...dedupedByRoleId.values()];
  };

  const mergePlatformPermissionFromRoles = (roles) => {
    let merged = null;
    const normalizedRoles = Array.isArray(roles) ? roles : [];
    for (const role of normalizedRoles) {
      if (!role || !isActiveLikeStatus(role.status)) {
        continue;
      }
      merged = mergePlatformPermission(merged, role.permission);
    }
    return merged;
  };

  const syncPlatformPermissionFromRoleFacts = ({
    userId,
    forceWhenNoRoleFacts = false
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId || !usersById.has(normalizedUserId)) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const roles = platformRolesByUserId.get(normalizedUserId) || [];
    if (roles.length === 0 && !forceWhenNoRoleFacts) {
      return {
        synced: false,
        reason: 'no-role-facts',
        permission: null
      };
    }

    let permission = mergePlatformPermissionFromRoles(roles);
    if (!permission) {
      permission = buildEmptyPlatformPermission();
    }
    platformPermissionsByUserId.set(normalizedUserId, { ...permission });

    return {
      synced: true,
      reason: 'ok',
      permission: { ...permission }
    };
  };

  const upsertPlatformRoleCatalogRecord = (entry = {}) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(
      entry.roleId || entry.role_id
    );
    const normalizedCode = normalizePlatformRoleCatalogCode(entry.code);
    const normalizedName = String(entry.name || '').trim();
    const normalizedScope = normalizePlatformRoleCatalogScope(
      entry.scope || 'platform'
    );
    const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
      scope: normalizedScope,
      tenantId: entry.tenantId || entry.tenant_id
    });
    if (!normalizedRoleId || !normalizedCode || !normalizedName) {
      throw new Error('platform role catalog entry requires roleId, code, and name');
    }
    const codeIndexKey = toPlatformRoleCatalogCodeIndexKey({
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      code: normalizedCode
    });
    const existingState = findPlatformRoleCatalogRecordStateByRoleId(
      normalizedRoleId
    );
    const persistedRoleId = existingState?.roleId || normalizedRoleId;
    const existing = existingState?.record || null;
    const existingRoleIdForCode = platformRoleCatalogCodeIndex.get(codeIndexKey);
    if (
      existingRoleIdForCode
      && toPlatformRoleCatalogRoleIdKey(existingRoleIdForCode)
        !== toPlatformRoleCatalogRoleIdKey(persistedRoleId)
    ) {
      throw createDuplicatePlatformRoleCatalogEntryError({
        target: 'code'
      });
    }
    if (existing) {
      const existingCodeIndexKey = toPlatformRoleCatalogCodeIndexKey({
        scope: existing.scope,
        tenantId: existing.tenantId,
        code: existing.code
      });
      if (existingCodeIndexKey !== codeIndexKey) {
        platformRoleCatalogCodeIndex.delete(existingCodeIndexKey);
      }
    }

    const nowIso = new Date().toISOString();
    const merged = toPlatformRoleCatalogRecord({
      ...existing,
      ...entry,
      roleId: persistedRoleId,
      scope: normalizedScope,
      tenantId: normalizedTenantId,
      code: normalizedCode,
      name: normalizedName,
      createdAt: existing?.createdAt || entry.createdAt || nowIso,
      updatedAt: entry.updatedAt || nowIso
    });
    platformRoleCatalogById.set(persistedRoleId, merged);
    platformRoleCatalogCodeIndex.set(codeIndexKey, persistedRoleId);
    return clonePlatformRoleCatalogRecord(merged);
  };

  upsertPlatformRoleCatalogRecord({
    roleId: 'sys_admin',
    code: 'sys_admin',
    name: '系统管理员',
    status: 'active',
    scope: 'platform',
    isSystem: true,
    createdByUserId: null,
    updatedByUserId: null
  });
  replacePlatformRolePermissionGrantsForRoleId({
    roleId: 'sys_admin',
    permissionCodes: KNOWN_PLATFORM_PERMISSION_CODES
  });

  for (const user of seedUsers) {
    const normalizedUser = {
      id: String(user.id),
      phone: user.phone,
      status: (user.status || 'active').toLowerCase(),
      sessionVersion: Number(user.sessionVersion || 1),
      passwordHash: user.passwordHash || hashPassword(user.password)
    };

    usersByPhone.set(normalizedUser.phone, normalizedUser);
    usersById.set(normalizedUser.id, normalizedUser);

    const rawDomains = Array.isArray(user.domains) ? user.domains : ['platform', 'tenant'];
    const domainSet = new Set(
      rawDomains
        .map((domain) => String(domain || '').trim().toLowerCase())
        .filter((domain) => domain === 'platform' || domain === 'tenant')
    );
    domainsByUserId.set(normalizedUser.id, domainSet);
    if (domainSet.has('platform')) {
      platformDomainKnownByUserId.add(normalizedUser.id);
    }

    const rawTenants = Array.isArray(user.tenants) ? user.tenants : [];
    tenantsByUserId.set(
      normalizedUser.id,
      rawTenants
        .filter((tenant) => tenant && tenant.tenantId)
        .map((tenant) => ({
          membershipId: tenant.membershipId
            ? String(tenant.membershipId)
            : randomUUID(),
          tenantId: String(tenant.tenantId),
          tenantName: tenant.tenantName ? String(tenant.tenantName) : null,
          status: normalizeTenantMembershipStatus(tenant.status || 'active'),
          displayName: resolveOptionalTenantMemberProfileField(
            tenant.displayName ?? tenant.display_name ?? null
          ),
          departmentName: resolveOptionalTenantMemberProfileField(
            tenant.departmentName ?? tenant.department_name ?? null
          ),
          joinedAt: tenant.joinedAt || tenant.joined_at || new Date().toISOString(),
          leftAt: tenant.leftAt || tenant.left_at || null,
          permission: tenant.permission
            ? {
              scopeLabel: tenant.permission.scopeLabel || null,
              canViewMemberAdmin: Boolean(tenant.permission.canViewMemberAdmin),
              canOperateMemberAdmin: Boolean(tenant.permission.canOperateMemberAdmin),
              canViewBilling: Boolean(tenant.permission.canViewBilling),
              canOperateBilling: Boolean(tenant.permission.canOperateBilling)
            }
            : null
        }))
    );

    const rawPlatformRoles = Array.isArray(user.platformRoles) ? user.platformRoles : [];
    const normalizedPlatformRoles = dedupePlatformRolesByRoleId(
      rawPlatformRoles
        .map((role) => normalizePlatformRole(role))
        .filter(Boolean)
    );
    platformRolesByUserId.set(normalizedUser.id, normalizedPlatformRoles);

    let platformPermission = normalizePlatformPermission(user.platformPermission);
    platformPermission = mergePlatformPermission(
      platformPermission,
      mergePlatformPermissionFromRoles(normalizedPlatformRoles)
    );

    if (platformPermission) {
      platformPermissionsByUserId.set(normalizedUser.id, { ...platformPermission });
    }
  }

  const clone = (value) => (value ? { ...value } : null);

  const normalizeAuditDomain = (domain) => {
    const normalized = String(domain || '').trim().toLowerCase();
    return AUDIT_EVENT_ALLOWED_DOMAINS.has(normalized) ? normalized : '';
  };

  const normalizeAuditResult = (result) => {
    const normalized = String(result || '').trim().toLowerCase();
    return AUDIT_EVENT_ALLOWED_RESULTS.has(normalized) ? normalized : '';
  };

  const normalizeAuditStringOrNull = (value, maxLength = 256) => {
    if (value === null || value === undefined) {
      return null;
    }
    const normalized = String(value).trim();
    if (!normalized || normalized.length > maxLength) {
      return null;
    }
    return normalized;
  };

  const normalizeAuditTraceparentOrNull = (value) => {
    const normalized = normalizeAuditStringOrNull(value, 128);
    if (!normalized) {
      return null;
    }
    return normalizeTraceparent(normalized);
  };

  const normalizeAuditOccurredAt = (value) => {
    if (value === null || value === undefined) {
      return new Date().toISOString();
    }
    const dateValue = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(dateValue.getTime())) {
      return new Date().toISOString();
    }
    return dateValue.toISOString();
  };

  const safeParseJsonValue = (value) => {
    if (value === null || value === undefined) {
      return null;
    }
    if (typeof value === 'object') {
      return value;
    }
    if (typeof value !== 'string') {
      return null;
    }
    const trimmed = value.trim();
    if (!trimmed) {
      return null;
    }
    try {
      return JSON.parse(trimmed);
    } catch (_error) {
      return null;
    }
  };

  const sanitizeAuditState = (value, depth = 0) => {
    if (value === null || value === undefined) {
      return null;
    }
    if (depth > 8) {
      return null;
    }
    if (Array.isArray(value)) {
      return value.map((item) => sanitizeAuditState(item, depth + 1));
    }
    if (typeof value === 'object') {
      const sanitized = {};
      for (const [key, itemValue] of Object.entries(value)) {
        if (AUDIT_EVENT_REDACTION_KEY_PATTERN.test(String(key))) {
          sanitized[key] = '[REDACTED]';
          continue;
        }
        sanitized[key] = sanitizeAuditState(itemValue, depth + 1);
      }
      return sanitized;
    }
    return value;
  };

  const cloneJsonValue = (value) => {
    if (value === null || value === undefined) {
      return null;
    }
    try {
      return JSON.parse(JSON.stringify(value));
    } catch (_error) {
      return null;
    }
  };

  const toAuditEventRecord = (event = {}) => ({
    event_id: normalizeAuditStringOrNull(event.event_id, 64) || '',
    domain: normalizeAuditDomain(event.domain),
    tenant_id: normalizeAuditStringOrNull(event.tenant_id, 64),
    request_id: normalizeAuditStringOrNull(event.request_id, 128) || 'request_id_unset',
    traceparent: normalizeAuditTraceparentOrNull(event.traceparent),
    event_type: normalizeAuditStringOrNull(event.event_type, 128) || '',
    actor_user_id: normalizeAuditStringOrNull(event.actor_user_id, 64),
    actor_session_id: normalizeAuditStringOrNull(event.actor_session_id, 128),
    target_type: normalizeAuditStringOrNull(event.target_type, 64) || '',
    target_id: normalizeAuditStringOrNull(event.target_id, 128),
    result: normalizeAuditResult(event.result) || 'failed',
    before_state: safeParseJsonValue(cloneJsonValue(event.before_state)),
    after_state: safeParseJsonValue(cloneJsonValue(event.after_state)),
    metadata: safeParseJsonValue(cloneJsonValue(event.metadata)),
    occurred_at: normalizeAuditOccurredAt(event.occurred_at)
  });

  const bumpSessionVersionAndConvergeSessions = ({
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const user = usersById.get(String(userId));
    if (!user) {
      return null;
    }

    if (passwordHash !== null && passwordHash !== undefined) {
      user.passwordHash = passwordHash;
    }
    user.sessionVersion += 1;
    usersByPhone.set(user.phone, user);
    usersById.set(user.id, user);

    if (revokeAuthSessions) {
      for (const session of sessionsById.values()) {
        if (session.userId === String(userId) && session.status === 'active') {
          session.status = 'revoked';
          session.revokedReason = reason;
          session.updatedAt = Date.now();
        }
      }
    }

    if (revokeRefreshTokens) {
      for (const refreshRecord of refreshTokensByHash.values()) {
        if (refreshRecord.userId === String(userId) && refreshRecord.status === 'active') {
          refreshRecord.status = 'revoked';
          refreshRecord.updatedAt = Date.now();
        }
      }
    }

    return clone(user);
  };

  const revokeSessionsForUserByEntryDomain = ({
    userId,
    entryDomain,
    reason,
    activeTenantId = null
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedEntryDomain = String(entryDomain || '').trim().toLowerCase();
    const normalizedActiveTenantId = activeTenantId === null || activeTenantId === undefined
      ? null
      : String(activeTenantId).trim() || null;
    if (!normalizedUserId) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }
    if (!normalizedEntryDomain) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }

    const revokedSessionIds = new Set();
    for (const session of sessionsById.values()) {
      if (
        session.userId === normalizedUserId
        && session.status === 'active'
        && String(session.entryDomain || '').trim().toLowerCase() === normalizedEntryDomain
        && (
          normalizedActiveTenantId === null
          || String(session.activeTenantId || '').trim() === normalizedActiveTenantId
        )
      ) {
        session.status = 'revoked';
        session.revokedReason = reason;
        session.updatedAt = Date.now();
        revokedSessionIds.add(String(session.sessionId || '').trim());
      }
    }

    if (revokedSessionIds.size === 0) {
      return {
        revokedSessionCount: 0,
        revokedRefreshTokenCount: 0
      };
    }

    let revokedRefreshTokenCount = 0;
    for (const refreshRecord of refreshTokensByHash.values()) {
      if (
        refreshRecord.status === 'active'
        && revokedSessionIds.has(String(refreshRecord.sessionId || '').trim())
      ) {
        refreshRecord.status = 'revoked';
        refreshRecord.updatedAt = Date.now();
        revokedRefreshTokenCount += 1;
      }
    }
    return {
      revokedSessionCount: revokedSessionIds.size,
      revokedRefreshTokenCount
    };
  };

  const revokePlatformSessionsForUser = ({
    userId,
    reason = 'platform-user-status-changed'
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'platform',
      reason
    });

  const revokeTenantSessionsForUser = ({
    userId,
    reason = 'org-status-changed',
    activeTenantId = null
  }) =>
    revokeSessionsForUserByEntryDomain({
      userId,
      entryDomain: 'tenant',
      reason,
      activeTenantId
    });

  const findTenantMembershipStateByMembershipId = (membershipId) => {
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

  const listTenantMembershipRoleBindingsForMembershipId = ({
    membershipId,
    tenantId = undefined
  } = {}) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return [];
    }
    const membershipState = findTenantMembershipStateByMembershipId(normalizedMembershipId);
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
    for (const rawRoleId of tenantMembershipRolesByMembershipId.get(normalizedMembershipId) || []) {
      const normalizedRoleId = normalizeStrictTenantMembershipRoleIdFromBindingRow(
        rawRoleId,
        'tenant-membership-role-bindings-invalid-role-id'
      );
      if (seenRoleIds.has(normalizedRoleId)) {
        throw createTenantMembershipRoleBindingDataError(
          'tenant-membership-role-bindings-duplicate-role-id'
        );
      }
      seenRoleIds.add(normalizedRoleId);
      normalizedRoleIds.push(normalizedRoleId);
    }
    return normalizedRoleIds.sort((left, right) => left.localeCompare(right));
  };

  const replaceTenantMembershipRoleBindingsForMembershipId = ({
    membershipId,
    roleIds = []
  } = {}) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      throw new Error('replaceTenantMembershipRoleBindings requires membershipId');
    }
    const normalizedRoleIds = [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
        .filter((roleId) => roleId.length > 0)
    )].sort((left, right) => left.localeCompare(right));
    tenantMembershipRolesByMembershipId.set(normalizedMembershipId, normalizedRoleIds);
    return listTenantMembershipRoleBindingsForMembershipId({
      membershipId: normalizedMembershipId
    });
  };

  const toTenantMembershipScopeLabel = (membership = null) => {
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
    const scopeLabel = toTenantMembershipScopeLabel(membership);
    if (!membership || !isTenantMembershipActiveForAuth(membership)) {
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

  const syncTenantMembershipPermissionSnapshot = ({
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
    const roleIds = listTenantMembershipRoleBindingsForMembershipId({
      membershipId,
      tenantId
    });
    const previousPermission = normalizePlatformPermission(
      membership.permission,
      toTenantMembershipScopeLabel(membership)
    ) || buildEmptyTenantPermission(toTenantMembershipScopeLabel(membership));
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

  const createForeignKeyConstraintError = () => {
    const error = new Error('Cannot delete or update a parent row: a foreign key constraint fails');
    error.code = 'ER_ROW_IS_REFERENCED_2';
    error.errno = 1451;
    return error;
  };

  const createDataTooLongError = () => {
    const error = new Error('Data too long for column');
    error.code = 'ER_DATA_TOO_LONG';
    error.errno = 1406;
    return error;
  };

  const hasOrgReferenceForUser = (userId) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return false;
    }

    for (const org of orgsById.values()) {
      if (
        String(org?.ownerUserId || '').trim() === normalizedUserId
        || String(org?.createdByUserId || '').trim() === normalizedUserId
      ) {
        return true;
      }
    }
    for (const memberships of membershipsByOrgId.values()) {
      if (!Array.isArray(memberships)) {
        continue;
      }
      if (
        memberships.some(
          (membership) => String(membership?.userId || '').trim() === normalizedUserId
        )
      ) {
        return true;
      }
    }
    return false;
  };

  const restoreMapFromSnapshot = (targetMap, snapshotMap) => {
    targetMap.clear();
    for (const [key, value] of snapshotMap.entries()) {
      targetMap.set(key, value);
    }
  };

  const restoreAuditEventsFromSnapshot = (snapshotEvents = []) => {
    auditEvents.length = 0;
    for (const event of snapshotEvents) {
      auditEvents.push(event);
    }
  };

  const persistAuditEvent = ({
    eventId = null,
    domain,
    tenantId = null,
    requestId = 'request_id_unset',
    traceparent = null,
    eventType,
    actorUserId = null,
    actorSessionId = null,
    targetType,
    targetId = null,
    result = 'success',
    beforeState = null,
    afterState = null,
    metadata = null,
    occurredAt = null
  } = {}) => {
    const normalizedDomain = normalizeAuditDomain(domain);
    const normalizedResult = normalizeAuditResult(result);
    const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
    const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
    if (
      !normalizedDomain
      || !normalizedResult
      || !normalizedEventType
      || !normalizedTargetType
    ) {
      throw new Error('recordAuditEvent requires valid domain, result, eventType and targetType');
    }
    const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
    if (normalizedDomain === 'tenant' && !normalizedTenantId) {
      throw new Error('recordAuditEvent tenant domain requires tenantId');
    }
    const eventRecord = toAuditEventRecord({
      event_id: normalizeAuditStringOrNull(eventId, 64) || randomUUID(),
      domain: normalizedDomain,
      tenant_id: normalizedTenantId,
      request_id: normalizeAuditStringOrNull(requestId, 128) || 'request_id_unset',
      traceparent: normalizeAuditTraceparentOrNull(traceparent),
      event_type: normalizedEventType,
      actor_user_id: normalizeAuditStringOrNull(actorUserId, 64),
      actor_session_id: normalizeAuditStringOrNull(actorSessionId, 128),
      target_type: normalizedTargetType,
      target_id: normalizeAuditStringOrNull(targetId, 128),
      result: normalizedResult,
      before_state: sanitizeAuditState(beforeState),
      after_state: sanitizeAuditState(afterState),
      metadata: sanitizeAuditState(metadata),
      occurred_at: normalizeAuditOccurredAt(occurredAt)
    });
    auditEvents.push(eventRecord);
    if (auditEvents.length > 5000) {
      auditEvents.splice(0, auditEvents.length - 5000);
    }
    return toAuditEventRecord(eventRecord);
  };

  return {
    findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

    findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

    recordAuditEvent: async (payload = {}) =>
      persistAuditEvent(payload),

    listAuditEvents: async ({
      domain,
      tenantId = null,
      page = 1,
      pageSize = 50,
      from = null,
      to = null,
      eventType = null,
      result = null,
      requestId = null,
      traceparent = null,
      actorUserId = null,
      targetType = null,
      targetId = null
    } = {}) => {
      const normalizedDomain = normalizeAuditDomain(domain);
      if (!normalizedDomain) {
        throw new Error('listAuditEvents requires valid domain');
      }
      const normalizedTenantId = normalizeAuditStringOrNull(tenantId, 64);
      if (normalizedDomain === 'tenant' && !normalizedTenantId) {
        throw new Error('listAuditEvents tenant domain requires tenantId');
      }
      const normalizedEventType = normalizeAuditStringOrNull(eventType, 128);
      const normalizedResult = normalizeAuditResult(result);
      const normalizedRequestId = normalizeAuditStringOrNull(requestId, 128);
      let normalizedTraceparent = null;
      if (traceparent !== null && traceparent !== undefined) {
        normalizedTraceparent = normalizeAuditTraceparentOrNull(traceparent);
        if (!normalizedTraceparent) {
          throw new Error('listAuditEvents requires valid traceparent');
        }
      }
      const normalizedActorUserId = normalizeAuditStringOrNull(actorUserId, 64);
      const normalizedTargetType = normalizeAuditStringOrNull(targetType, 64);
      const normalizedTargetId = normalizeAuditStringOrNull(targetId, 128);
      const fromDate = from ? new Date(from) : null;
      const toDate = to ? new Date(to) : null;
      if (
        fromDate && toDate
        && !Number.isNaN(fromDate.getTime())
        && !Number.isNaN(toDate.getTime())
        && fromDate.getTime() > toDate.getTime()
      ) {
        throw new Error('listAuditEvents requires from <= to');
      }
      const filtered = auditEvents.filter((event) => {
        if (normalizeAuditDomain(event.domain) !== normalizedDomain) {
          return false;
        }
        if (normalizedTenantId && normalizeAuditStringOrNull(event.tenant_id, 64) !== normalizedTenantId) {
          return false;
        }
        if (normalizedEventType && normalizeAuditStringOrNull(event.event_type, 128) !== normalizedEventType) {
          return false;
        }
        if (normalizedResult && normalizeAuditResult(event.result) !== normalizedResult) {
          return false;
        }
        if (normalizedRequestId && normalizeAuditStringOrNull(event.request_id, 128) !== normalizedRequestId) {
          return false;
        }
        if (
          normalizedTraceparent
          && normalizeAuditTraceparentOrNull(event.traceparent) !== normalizedTraceparent
        ) {
          return false;
        }
        if (normalizedActorUserId && normalizeAuditStringOrNull(event.actor_user_id, 64) !== normalizedActorUserId) {
          return false;
        }
        if (normalizedTargetType && normalizeAuditStringOrNull(event.target_type, 64) !== normalizedTargetType) {
          return false;
        }
        if (normalizedTargetId && normalizeAuditStringOrNull(event.target_id, 128) !== normalizedTargetId) {
          return false;
        }
        const occurredAt = new Date(event.occurred_at);
        if (fromDate && !Number.isNaN(fromDate.getTime()) && occurredAt < fromDate) {
          return false;
        }
        if (toDate && !Number.isNaN(toDate.getTime()) && occurredAt > toDate) {
          return false;
        }
        return true;
      });
      filtered.sort((left, right) => {
        const leftTime = new Date(left.occurred_at).getTime();
        const rightTime = new Date(right.occurred_at).getTime();
        if (rightTime !== leftTime) {
          return rightTime - leftTime;
        }
        return String(right.event_id || '').localeCompare(String(left.event_id || ''));
      });
      const total = filtered.length;
      const resolvedPage = Math.max(1, Math.floor(Number(page || 1)));
      const resolvedPageSize = Math.min(
        MAX_AUDIT_QUERY_PAGE_SIZE,
        Math.max(1, Math.floor(Number(pageSize || 50)))
      );
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return {
        total,
        events: filtered
          .slice(offset, offset + resolvedPageSize)
          .map((event) => toAuditEventRecord(event))
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

    createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      if (usersByPhone.has(normalizedPhone)) {
        return null;
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const user = {
        id: randomUUID(),
        phone: normalizedPhone,
        passwordHash: normalizedPasswordHash,
        status: normalizedStatus,
        sessionVersion: 1
      };
      usersByPhone.set(normalizedPhone, user);
      usersById.set(user.id, user);
      if (!domainsByUserId.has(user.id)) {
        domainsByUserId.set(user.id, new Set());
      }
      if (!tenantsByUserId.has(user.id)) {
        tenantsByUserId.set(user.id, []);
      }
      return clone(user);
    },

    createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerUserId,
      operatorUserId,
      operatorSessionId = null,
      auditContext = null
    }) => {
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          orgsById: structuredClone(orgsById),
          orgIdByName: structuredClone(orgIdByName),
          membershipsByOrgId: structuredClone(membershipsByOrgId),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const normalizedOrgId = String(orgId || '').trim() || randomUUID();
        const normalizedOrgName = String(orgName || '').trim();
        const normalizedOwnerUserId = String(ownerUserId || '').trim();
        const normalizedOperatorUserId = String(operatorUserId || '').trim();
        if (
          !normalizedOrgName
          || !normalizedOwnerUserId
          || !normalizedOperatorUserId
        ) {
          throw new Error(
            'createOrganizationWithOwner requires orgName, ownerUserId, and operatorUserId'
          );
        }
        if (!usersById.has(normalizedOwnerUserId) || !usersById.has(normalizedOperatorUserId)) {
          throw new Error('createOrganizationWithOwner requires existing owner and operator users');
        }
        if (normalizedOrgName.length > MAX_ORG_NAME_LENGTH) {
          throw createDataTooLongError();
        }

        const orgNameDedupeKey = normalizedOrgName.toLowerCase();
        if (orgIdByName.has(orgNameDedupeKey)) {
          const duplicateError = new Error('duplicate org name');
          duplicateError.code = 'ER_DUP_ENTRY';
          duplicateError.errno = 1062;
          throw duplicateError;
        }
        if (orgsById.has(normalizedOrgId)) {
          const duplicateError = new Error('duplicate org id');
          duplicateError.code = 'ER_DUP_ENTRY';
          duplicateError.errno = 1062;
          throw duplicateError;
        }

        orgsById.set(normalizedOrgId, {
          id: normalizedOrgId,
          name: normalizedOrgName,
          ownerUserId: normalizedOwnerUserId,
          createdByUserId: normalizedOperatorUserId,
          status: 'active'
        });
        orgIdByName.set(orgNameDedupeKey, normalizedOrgId);
        membershipsByOrgId.set(normalizedOrgId, [
          {
            orgId: normalizedOrgId,
            userId: normalizedOwnerUserId,
            membershipRole: 'owner',
            status: 'active'
          }
        ]);
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.create.succeeded',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || operatorSessionId,
              targetType: 'org',
              targetId: normalizedOrgId,
              result: 'success',
              beforeState: null,
              afterState: {
                org_id: normalizedOrgId,
                org_name: normalizedOrgName,
                owner_user_id: normalizedOwnerUserId
              },
              metadata: {
                operator_user_id: normalizedOperatorUserId
              }
            });
            auditRecorded = true;
          } catch (error) {
            const auditWriteError = new Error('organization create audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
        }

        return {
          org_id: normalizedOrgId,
          owner_user_id: normalizedOwnerUserId,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(orgsById, snapshot.orgsById);
          restoreMapFromSnapshot(orgIdByName, snapshot.orgIdByName);
          restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    findOrganizationById: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return null;
      }
      const org = orgsById.get(normalizedOrgId);
      if (!org) {
        return null;
      }
      return {
        org_id: normalizedOrgId,
        org_name: String(org.name || '').trim(),
        owner_user_id: String(org.ownerUserId || '').trim(),
        status: normalizeOrgStatus(org.status),
        created_by_user_id: org.createdByUserId
          ? String(org.createdByUserId).trim()
          : null
      };
    },

    acquireOwnerTransferLock: async ({
      orgId,
      requestId,
      operatorUserId
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      if (ownerTransferLocksByOrgId.has(normalizedOrgId)) {
        return false;
      }
      ownerTransferLocksByOrgId.set(normalizedOrgId, {
        request_id: String(requestId || '').trim() || 'request_id_unset',
        operator_user_id: String(operatorUserId || '').trim() || 'unknown',
        started_at: new Date().toISOString()
      });
      return true;
    },

    releaseOwnerTransferLock: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      return ownerTransferLocksByOrgId.delete(normalizedOrgId);
    },

    executeOwnerTransferTakeover: async ({
      requestId = 'request_id_unset',
      orgId,
      oldOwnerUserId,
      newOwnerUserId,
      operatorUserId = null,
      operatorSessionId = null,
      reason = null,
      takeoverRoleId = 'tenant_owner',
      takeoverRoleCode = 'TENANT_OWNER',
      takeoverRoleName = '组织负责人',
      requiredPermissionCodes = [],
      auditContext = null
    } = {}) => {
      const normalizedRequestId = String(requestId || '').trim() || 'request_id_unset';
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOldOwnerUserId = String(oldOwnerUserId || '').trim();
      const normalizedNewOwnerUserId = String(newOwnerUserId || '').trim();
      const normalizedOperatorUserId = operatorUserId === null || operatorUserId === undefined
        ? null
        : String(operatorUserId || '').trim() || null;
      const normalizedOperatorSessionId =
        operatorSessionId === null || operatorSessionId === undefined
          ? null
          : String(operatorSessionId || '').trim() || null;
      const normalizedReason = reason === null || reason === undefined
        ? null
        : String(reason || '').trim() || null;
      const normalizedTakeoverRoleId = normalizePlatformRoleCatalogRoleId(
        takeoverRoleId
      );
      const normalizedTakeoverRoleCode = normalizePlatformRoleCatalogCode(
        takeoverRoleCode
      );
      const normalizedTakeoverRoleName = String(takeoverRoleName || '').trim();
      const normalizedRequiredPermissionCodes = normalizeTenantPermissionCodes(
        requiredPermissionCodes
      );
      const missingRequiredPermissionCodes = [
        'tenant.member_admin.view',
        'tenant.member_admin.operate'
      ].filter(
        (permissionCode) =>
          !normalizedRequiredPermissionCodes.includes(permissionCode)
      );
      const hasUnsupportedRequiredPermissionCode = normalizedRequiredPermissionCodes.some(
        (permissionCode) =>
          !KNOWN_TENANT_PERMISSION_CODE_SET.has(permissionCode)
      );
      if (
        !normalizedOrgId
        || !normalizedOldOwnerUserId
        || !normalizedNewOwnerUserId
        || !normalizedTakeoverRoleId
        || !normalizedTakeoverRoleCode
        || !normalizedTakeoverRoleName
        || hasUnsupportedRequiredPermissionCode
        || missingRequiredPermissionCodes.length > 0
      ) {
        const invalidInputError = new Error(
          'executeOwnerTransferTakeover requires valid takeover payload'
        );
        invalidInputError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_INVALID_INPUT';
        throw invalidInputError;
      }

      const snapshot = {
        orgsById: structuredClone(orgsById),
        tenantsByUserId: structuredClone(tenantsByUserId),
        domainsByUserId: structuredClone(domainsByUserId),
        platformRoleCatalogById: structuredClone(platformRoleCatalogById),
        platformRoleCatalogCodeIndex: structuredClone(platformRoleCatalogCodeIndex),
        tenantRolePermissionGrantsByRoleId: structuredClone(
          tenantRolePermissionGrantsByRoleId
        ),
        tenantMembershipRolesByMembershipId: structuredClone(
          tenantMembershipRolesByMembershipId
        ),
        tenantMembershipHistoryByPair: structuredClone(tenantMembershipHistoryByPair),
        sessionsById: structuredClone(sessionsById),
        refreshTokensByHash: structuredClone(refreshTokensByHash)
      };
      const restoreMap = (target, source) => {
        target.clear();
        for (const [key, value] of source.entries()) {
          target.set(key, value);
        }
      };

      try {
        const org = orgsById.get(normalizedOrgId) || null;
        if (!org) {
          const orgNotFoundError = new Error(
            'owner transfer takeover organization not found'
          );
          orgNotFoundError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_FOUND';
          throw orgNotFoundError;
        }
        const currentOrgStatus = normalizeOrgStatus(org.status);
        const currentOwnerUserId = String(org.ownerUserId || '').trim();
        if (!isActiveLikeStatus(currentOrgStatus)) {
          const orgInactiveError = new Error(
            'owner transfer takeover organization not active'
          );
          orgInactiveError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ORG_NOT_ACTIVE';
          throw orgInactiveError;
        }
        if (currentOwnerUserId !== normalizedOldOwnerUserId) {
          const preconditionFailedError = new Error(
            'owner transfer takeover precondition failed'
          );
          preconditionFailedError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PRECONDITION_FAILED';
          throw preconditionFailedError;
        }
        if (normalizedNewOwnerUserId === normalizedOldOwnerUserId) {
          const sameOwnerError = new Error(
            'owner transfer takeover new owner equals current owner'
          );
          sameOwnerError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SAME_OWNER';
          throw sameOwnerError;
        }

        const newOwner = usersById.get(normalizedNewOwnerUserId) || null;
        if (!newOwner) {
          const newOwnerNotFoundError = new Error(
            'owner transfer takeover new owner not found'
          );
          newOwnerNotFoundError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_NOT_FOUND';
          throw newOwnerNotFoundError;
        }
        if (
          !isActiveLikeStatus(
            String(newOwner?.status || '').trim().toLowerCase() || 'disabled'
          )
        ) {
          const newOwnerInactiveError = new Error(
            'owner transfer takeover new owner inactive'
          );
          newOwnerInactiveError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_NEW_OWNER_INACTIVE';
          throw newOwnerInactiveError;
        }

        const createRoleInvalidError = () => {
          const roleInvalidError = new Error(
            'owner transfer takeover role definition invalid'
          );
          roleInvalidError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_INVALID';
          return roleInvalidError;
        };

        const existingRoleState = findPlatformRoleCatalogRecordStateByRoleId(
          normalizedTakeoverRoleId
        );
        const existingRole = existingRoleState?.record || null;
        if (!existingRole) {
          try {
            upsertPlatformRoleCatalogRecord({
              roleId: normalizedTakeoverRoleId,
              code: normalizedTakeoverRoleCode,
              name: normalizedTakeoverRoleName,
              status: 'active',
              scope: 'tenant',
              tenantId: normalizedOrgId,
              isSystem: true,
              createdByUserId: normalizedOperatorUserId,
              updatedByUserId: normalizedOperatorUserId
            });
          } catch (error) {
            if (String(error?.code || '').trim().toUpperCase() === 'ER_DUP_ENTRY') {
              throw createRoleInvalidError();
            }
            throw error;
          }
        } else {
          const roleScope = normalizePlatformRoleCatalogScope(existingRole.scope);
          const roleTenantId = normalizePlatformRoleCatalogTenantId(
            existingRole.tenantId
          );
          const roleCode = normalizePlatformRoleCatalogCode(existingRole.code);
          if (roleScope !== 'tenant' || roleTenantId !== normalizedOrgId) {
            throw createRoleInvalidError();
          }
          if (
            !roleCode
            || roleCode.toLowerCase() !== normalizedTakeoverRoleCode.toLowerCase()
          ) {
            throw createRoleInvalidError();
          }
          const roleStatus = normalizePlatformRoleCatalogStatus(
            existingRole.status || 'disabled'
          );
          if (!isActiveLikeStatus(roleStatus)) {
            upsertPlatformRoleCatalogRecord({
              ...existingRole,
              roleId: normalizedTakeoverRoleId,
              status: 'active',
              updatedByUserId: normalizedOperatorUserId
            });
          }
        }

        const grantCodes = new Set(
          listTenantRolePermissionGrantsForRoleId(normalizedTakeoverRoleId)
        );
        for (const permissionCode of normalizedRequiredPermissionCodes) {
          grantCodes.add(permissionCode);
        }
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedTakeoverRoleId,
          permissionCodes: [...grantCodes]
        });

        org.ownerUserId = normalizedNewOwnerUserId;
        orgsById.set(normalizedOrgId, org);
        invokeFaultInjector('afterOwnerTransferTakeoverOwnerSwitch', {
          requestId: normalizedRequestId,
          orgId: normalizedOrgId,
          oldOwnerUserId: normalizedOldOwnerUserId,
          newOwnerUserId: normalizedNewOwnerUserId
        });

        const tenantMemberships = tenantsByUserId.get(normalizedNewOwnerUserId) || [];
        let membership = tenantMemberships.find(
          (item) => String(item?.tenantId || '').trim() === normalizedOrgId
        ) || null;
        if (!membership) {
          membership = {
            membershipId: randomUUID(),
            tenantId: normalizedOrgId,
            tenantName: null,
            status: 'active',
            displayName: null,
            departmentName: null,
            joinedAt: new Date().toISOString(),
            leftAt: null,
            permission: buildEmptyTenantPermission(
              `组织权限（${normalizedOrgId}）`
            )
          };
          tenantMemberships.push(membership);
          tenantMembershipRolesByMembershipId.set(
            String(membership.membershipId || '').trim(),
            []
          );
        } else {
          const normalizedMembershipStatus = normalizeTenantMembershipStatusForRead(
            membership.status
          );
          if (
            normalizedMembershipStatus !== 'active'
            && normalizedMembershipStatus !== 'disabled'
            && normalizedMembershipStatus !== 'left'
          ) {
            const membershipInvalidError = new Error(
              'owner transfer takeover membership status invalid'
            );
            membershipInvalidError.code =
              'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
            throw membershipInvalidError;
          }
          if (normalizedMembershipStatus === 'left') {
            appendTenantMembershipHistory({
              membership: {
                ...membership,
                userId: normalizedNewOwnerUserId,
                tenantId: normalizedOrgId
              },
              reason: 'rejoin',
              operatorUserId: normalizedOperatorUserId
            });
            const previousMembershipId = String(
              membership.membershipId || ''
            ).trim();
            membership.membershipId = randomUUID();
            membership.status = 'active';
            membership.leftAt = null;
            membership.joinedAt = new Date().toISOString();
            membership.permission = buildEmptyTenantPermission(
              toTenantMembershipScopeLabel(membership)
            );
            if (previousMembershipId) {
              tenantMembershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantMembershipRolesByMembershipId.set(
              String(membership.membershipId || '').trim(),
              []
            );
          } else if (normalizedMembershipStatus === 'disabled') {
            membership.status = 'active';
            membership.leftAt = null;
            membership.permission = buildEmptyTenantPermission(
              toTenantMembershipScopeLabel(membership)
            );
          }
        }
        tenantsByUserId.set(normalizedNewOwnerUserId, tenantMemberships);

        const membershipId = String(membership?.membershipId || '').trim();
        if (!membershipId) {
          const membershipResolveError = new Error(
            'owner transfer takeover membership resolution failed'
          );
          membershipResolveError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_MEMBERSHIP_INVALID';
          throw membershipResolveError;
        }

        const userDomains = domainsByUserId.get(normalizedNewOwnerUserId) || new Set();
        userDomains.add('tenant');
        domainsByUserId.set(normalizedNewOwnerUserId, userDomains);

        const existingRoleIds = listTenantMembershipRoleBindingsForMembershipId({
          membershipId,
          tenantId: normalizedOrgId
        });
        const nextRoleIds = [...new Set([
          ...existingRoleIds,
          normalizedTakeoverRoleId
        ])].sort((left, right) => left.localeCompare(right));
        if (nextRoleIds.length < 1) {
          const roleBindingError = new Error(
            'owner transfer takeover role binding invalid'
          );
          roleBindingError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_ROLE_BINDINGS_INVALID';
          throw roleBindingError;
        }
        replaceTenantMembershipRoleBindingsForMembershipId({
          membershipId,
          roleIds: nextRoleIds
        });

        const membershipState = findTenantMembershipStateByMembershipId(
          membershipId
        );
        const syncResult = syncTenantMembershipPermissionSnapshot({
          membershipState,
          reason: 'owner-transfer-takeover'
        });
        const syncReason = String(syncResult?.reason || 'unknown')
          .trim()
          .toLowerCase();
        if (syncReason !== 'ok') {
          const syncError = new Error(
            `owner transfer takeover sync failed: ${syncReason || 'unknown'}`
          );
          syncError.code = 'ERR_OWNER_TRANSFER_TAKEOVER_SYNC_FAILED';
          syncError.syncReason = syncReason || 'unknown';
          throw syncError;
        }
        if (
          !Boolean(syncResult?.permission?.canViewMemberAdmin)
          || !Boolean(syncResult?.permission?.canOperateMemberAdmin)
        ) {
          const permissionInsufficientError = new Error(
            'owner transfer takeover permission insufficient'
          );
          permissionInsufficientError.code =
            'ERR_OWNER_TRANSFER_TAKEOVER_PERMISSION_INSUFFICIENT';
          throw permissionInsufficientError;
        }

        invokeFaultInjector('beforeOwnerTransferTakeoverCommit', {
          requestId: normalizedRequestId,
          orgId: normalizedOrgId,
          membershipId
        });

        let auditRecorded = false;
        if (auditContext && typeof auditContext === 'object') {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.owner_transfer.executed',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || normalizedOperatorSessionId,
              targetType: 'org',
              targetId: normalizedOrgId,
              result: 'success',
              beforeState: {
                owner_user_id: normalizedOldOwnerUserId
              },
              afterState: {
                owner_user_id: normalizedNewOwnerUserId
              },
              metadata: {
                old_owner_user_id: normalizedOldOwnerUserId,
                new_owner_user_id: normalizedNewOwnerUserId,
                reason:
                  auditContext.reason === null || auditContext.reason === undefined
                    ? null
                    : String(auditContext.reason).trim() || null
              }
            });
          } catch (error) {
            const auditWriteError = new Error(
              'owner transfer takeover audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          org_id: normalizedOrgId,
          old_owner_user_id: normalizedOldOwnerUserId,
          new_owner_user_id: normalizedNewOwnerUserId,
          membership_id: membershipId,
          role_ids: nextRoleIds,
          permission_codes: listTenantRolePermissionGrantsForRoleId(
            normalizedTakeoverRoleId
          ),
          audit_recorded: auditRecorded
        };
      } catch (error) {
        restoreMap(orgsById, snapshot.orgsById);
        restoreMap(tenantsByUserId, snapshot.tenantsByUserId);
        restoreMap(domainsByUserId, snapshot.domainsByUserId);
        restoreMap(platformRoleCatalogById, snapshot.platformRoleCatalogById);
        restoreMap(platformRoleCatalogCodeIndex, snapshot.platformRoleCatalogCodeIndex);
        restoreMap(
          tenantRolePermissionGrantsByRoleId,
          snapshot.tenantRolePermissionGrantsByRoleId
        );
        restoreMap(
          tenantMembershipRolesByMembershipId,
          snapshot.tenantMembershipRolesByMembershipId
        );
        restoreMap(
          tenantMembershipHistoryByPair,
          snapshot.tenantMembershipHistoryByPair
        );
        restoreMap(sessionsById, snapshot.sessionsById);
        restoreMap(refreshTokensByHash, snapshot.refreshTokensByHash);
        throw error;
      }
    },

    updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedOrgId
        || !normalizedOperatorUserId
        || !VALID_ORG_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
        );
      }
      const existingOrg = orgsById.get(normalizedOrgId);
      if (!existingOrg) {
        return null;
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          orgsById: structuredClone(orgsById),
          membershipsByOrgId: structuredClone(membershipsByOrgId),
          tenantsByUserId: structuredClone(tenantsByUserId),
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          platformRoleCatalogById: structuredClone(platformRoleCatalogById),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          domainsByUserId: structuredClone(domainsByUserId),
          auditEvents: structuredClone(auditEvents)
        }
        : null;

      try {
        const previousStatus = normalizeOrgStatus(existingOrg.status);
        let affectedMembershipCount = 0;
        let affectedRoleCount = 0;
        let affectedRoleBindingCount = 0;
        let revokedSessionCount = 0;
        let revokedRefreshTokenCount = 0;
        if (previousStatus !== normalizedNextStatus) {
          existingOrg.status = normalizedNextStatus;
          existingOrg.updatedAt = Date.now();
          orgsById.set(normalizedOrgId, existingOrg);

          if (normalizedNextStatus === 'disabled') {
            const affectedMembershipUserIds = new Set();
            const affectedUserIds = new Set();
            const orgMemberships = membershipsByOrgId.get(normalizedOrgId) || [];
            for (const membership of orgMemberships) {
              const membershipUserId = String(membership?.userId || '').trim();
              if (
                !membershipUserId
                || !isActiveLikeStatus(normalizeOrgStatus(membership?.status))
              ) {
                continue;
              }
              membership.status = 'disabled';
              affectedMembershipUserIds.add(membershipUserId);
              affectedUserIds.add(membershipUserId);
            }

            const tenantMembershipIdsByOrg = new Set();
            for (const [userId, tenantMemberships] of tenantsByUserId.entries()) {
              const normalizedUserId = String(userId || '').trim();
              let hasMutation = false;
              for (const membership of Array.isArray(tenantMemberships) ? tenantMemberships : []) {
                const membershipTenantId = String(membership?.tenantId || '').trim();
                if (membershipTenantId !== normalizedOrgId) {
                  continue;
                }
                const membershipId = String(membership?.membershipId || '').trim();
                if (membershipId) {
                  tenantMembershipIdsByOrg.add(membershipId);
                }
                if (
                  !isActiveLikeStatus(
                    normalizeTenantMembershipStatusForRead(membership?.status)
                  )
                ) {
                  continue;
                }
                membership.status = 'disabled';
                membership.permission = buildEmptyTenantPermission(
                  toTenantMembershipScopeLabel(membership)
                );
                affectedMembershipUserIds.add(normalizedUserId);
                affectedUserIds.add(normalizedUserId);
                hasMutation = true;
              }
              if (hasMutation) {
                tenantsByUserId.set(normalizedUserId, tenantMemberships);
              }
            }

            for (const membershipId of tenantMembershipIdsByOrg) {
              const existingRoleIds = tenantMembershipRolesByMembershipId.get(membershipId) || [];
              affectedRoleBindingCount += existingRoleIds.length;
              tenantMembershipRolesByMembershipId.delete(membershipId);
            }

            for (const [roleId, roleCatalogEntry] of platformRoleCatalogById.entries()) {
              if (
                normalizePlatformRoleCatalogScope(roleCatalogEntry?.scope) !== 'tenant'
                || normalizePlatformRoleCatalogTenantId(roleCatalogEntry?.tenantId)
                  !== normalizedOrgId
              ) {
                continue;
              }
              if (
                !isActiveLikeStatus(
                  normalizePlatformRoleCatalogStatus(roleCatalogEntry?.status)
                )
              ) {
                continue;
              }
              roleCatalogEntry.status = 'disabled';
              roleCatalogEntry.updatedByUserId = normalizedOperatorUserId;
              roleCatalogEntry.updatedAt = new Date().toISOString();
              platformRoleCatalogById.set(roleId, roleCatalogEntry);
              affectedRoleCount += 1;
            }

            const ownerUserId = String(existingOrg.ownerUserId || '').trim();
            if (ownerUserId) {
              affectedUserIds.add(ownerUserId);
            }

            affectedMembershipCount = affectedMembershipUserIds.size;
            for (const userId of affectedUserIds) {
              const revoked = revokeTenantSessionsForUser({
                userId,
                reason: 'org-status-changed',
                activeTenantId: normalizedOrgId
              });
              revokedSessionCount += Number(revoked?.revokedSessionCount || 0);
              revokedRefreshTokenCount += Number(
                revoked?.revokedRefreshTokenCount || 0
              );

              const userDomains = domainsByUserId.get(userId) || new Set();
              const hasAnyActiveMembership = (tenantsByUserId.get(userId) || []).some(
                (membership) => isTenantMembershipActiveForAuth(membership)
              );
              if (!hasAnyActiveMembership) {
                userDomains.delete('tenant');
              }
              domainsByUserId.set(userId, userDomains);
            }
          }
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedOrgId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.org.status.updated',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'org',
              targetId: normalizedOrgId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: normalizedNextStatus
              },
              metadata: {
                reason: normalizedAuditReason,
                affected_membership_count: affectedMembershipCount,
                affected_role_count: affectedRoleCount,
                affected_role_binding_count: affectedRoleBindingCount,
                revoked_session_count: revokedSessionCount,
                revoked_refresh_token_count: revokedRefreshTokenCount
              }
            });
          } catch (error) {
            const auditWriteError = new Error('organization status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }
        return {
          org_id: normalizedOrgId,
          previous_status: previousStatus,
          current_status: normalizedNextStatus,
          affected_membership_count: affectedMembershipCount,
          affected_role_count: affectedRoleCount,
          affected_role_binding_count: affectedRoleBindingCount,
          revoked_session_count: revokedSessionCount,
          revoked_refresh_token_count: revokedRefreshTokenCount,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(orgsById, snapshot.orgsById);
          restoreMapFromSnapshot(membershipsByOrgId, snapshot.membershipsByOrgId);
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(platformRoleCatalogById, snapshot.platformRoleCatalogById);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId,
      auditContext = null
    }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedOperatorUserId = String(operatorUserId || '').trim();
      const normalizedNextStatus = normalizeOrgStatus(nextStatus);
      if (
        !normalizedUserId
        || !normalizedOperatorUserId
        || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
        );
      }
      const existingUser = usersById.get(normalizedUserId);
      if (
        !existingUser
        || !platformDomainKnownByUserId.has(normalizedUserId)
      ) {
        return null;
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          domainsByUserId: structuredClone(domainsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
        const previousStatus = userDomains.has('platform') ? 'active' : 'disabled';
        if (previousStatus !== normalizedNextStatus) {
          if (normalizedNextStatus === 'active') {
            userDomains.add('platform');
          } else {
            userDomains.delete('platform');
            revokePlatformSessionsForUser({
              userId: normalizedUserId,
              reason: 'platform-user-status-changed'
            });
          }
          domainsByUserId.set(normalizedUserId, userDomains);
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'platform',
              tenantId: null,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.platform.user.status.updated',
              actorUserId: auditContext.actorUserId || normalizedOperatorUserId,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'user',
              targetId: normalizedUserId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: normalizedNextStatus
              },
              metadata: {
                reason: normalizedAuditReason
              }
            });
          } catch (error) {
            const auditWriteError = new Error('platform user status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          user_id: normalizedUserId,
          previous_status: previousStatus,
          current_status: normalizedNextStatus,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      const existingUser = usersById.get(normalizedUserId);
      if (!existingUser) {
        return { deleted: false };
      }
      if (hasOrgReferenceForUser(normalizedUserId)) {
        throw createForeignKeyConstraintError();
      }

      usersById.delete(normalizedUserId);
      usersByPhone.delete(String(existingUser.phone || ''));
      domainsByUserId.delete(normalizedUserId);
      platformDomainKnownByUserId.delete(normalizedUserId);
      for (const membership of tenantsByUserId.get(normalizedUserId) || []) {
        const membershipId = String(membership?.membershipId || '').trim();
        if (!membershipId) {
          continue;
        }
        tenantMembershipRolesByMembershipId.delete(membershipId);
      }
      tenantsByUserId.delete(normalizedUserId);
      platformRolesByUserId.delete(normalizedUserId);
      platformPermissionsByUserId.delete(normalizedUserId);

      for (const [sessionId, session] of sessionsById.entries()) {
        if (session.userId === normalizedUserId) {
          sessionsById.delete(sessionId);
        }
      }
      for (const [tokenHash, refreshToken] of refreshTokensByHash.entries()) {
        if (refreshToken.userId === normalizedUserId) {
          refreshTokensByHash.delete(tokenHash);
        }
      }

      return { deleted: true };
    },

    createTenantMembershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantMembershipForUser requires userId and tenantId');
      }
      if (!usersById.has(normalizedUserId)) {
        return { created: false };
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;

      const tenantMemberships = tenantsByUserId.get(normalizedUserId) || [];
      const existingMembership = tenantMemberships.find(
        (tenant) => String(tenant?.tenantId || '').trim() === normalizedTenantId
      );
      if (existingMembership) {
        const currentStatus = normalizeTenantMembershipStatusForRead(existingMembership.status);
        if (!VALID_TENANT_MEMBERSHIP_STATUS.has(currentStatus)) {
          throw new Error('createTenantMembershipForUser encountered unsupported existing status');
        }
        if (currentStatus !== 'left') {
          return { created: false };
        }
        appendTenantMembershipHistory({
          membership: {
            ...existingMembership,
            userId: normalizedUserId,
            tenantId: normalizedTenantId
          },
          reason: 'rejoin',
          operatorUserId: null
        });
        const previousMembershipId = String(existingMembership.membershipId || '').trim();
        existingMembership.membershipId = randomUUID();
        existingMembership.tenantName = normalizedTenantName;
        existingMembership.status = 'active';
        existingMembership.leftAt = null;
        existingMembership.joinedAt = new Date().toISOString();
        existingMembership.permission = {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        };
        if (previousMembershipId) {
          tenantMembershipRolesByMembershipId.delete(previousMembershipId);
        }
        tenantMembershipRolesByMembershipId.set(
          String(existingMembership.membershipId || '').trim(),
          []
        );
        tenantsByUserId.set(normalizedUserId, tenantMemberships);
        return { created: true };
      }

      const membershipId = randomUUID();
      tenantMemberships.push({
        membershipId,
        tenantId: normalizedTenantId,
        tenantName: normalizedTenantName,
        status: 'active',
        displayName: null,
        departmentName: null,
        joinedAt: new Date().toISOString(),
        leftAt: null,
        permission: {
          scopeLabel: `组织权限（${normalizedTenantName || normalizedTenantId}）`,
          canViewMemberAdmin: false,
          canOperateMemberAdmin: false,
          canViewBilling: false,
          canOperateBilling: false
        }
      });
      tenantMembershipRolesByMembershipId.set(membershipId, []);
      tenantsByUserId.set(normalizedUserId, tenantMemberships);
      return { created: true };
    },

    removeTenantMembershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantMembershipForUser requires userId and tenantId');
      }
      const tenantMemberships = tenantsByUserId.get(normalizedUserId);
      if (!Array.isArray(tenantMemberships) || tenantMemberships.length === 0) {
        return { removed: false };
      }
      const retainedMemberships = tenantMemberships.filter(
        (tenant) => String(tenant?.tenantId || '').trim() !== normalizedTenantId
      );
      const removed = retainedMemberships.length !== tenantMemberships.length;
      if (removed) {
        for (const membership of tenantMemberships) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          const membershipId = String(membership?.membershipId || '').trim();
          if (!membershipId) {
            continue;
          }
          tenantMembershipRolesByMembershipId.delete(membershipId);
        }
        tenantsByUserId.set(normalizedUserId, retainedMemberships);
      }
      return { removed };
    },

    removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
      if (!userDomains.has('tenant')) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      const hasActiveTenantMembership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantMembershipActiveForAuth(tenant)
      );
      if (hasActiveTenantMembership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { removed: false };
      }
      userDomains.delete('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { removed: true };
    },

    createSession: async ({ sessionId, userId, sessionVersion, entryDomain = 'platform', activeTenantId = null }) => {
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

      const hasActiveTenantMembership = (tenantsByUserId.get(normalizedUserId) || []).some(
        (tenant) => isTenantMembershipActiveForAuth(tenant)
      );
      if (!hasActiveTenantMembership) {
        domainsByUserId.set(normalizedUserId, userDomains);
        return { inserted: false };
      }

      userDomains.add('tenant');
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: true };
    },

    listTenantOptionsByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || [])
        .filter((tenant) => isTenantMembershipActiveForAuth(tenant))
        .map((tenant) => ({ ...tenant })),

    findTenantMembershipByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        return null;
      }
      const membership = (tenantsByUserId.get(normalizedUserId) || []).find(
        (item) => String(item?.tenantId || '').trim() === normalizedTenantId
      );
      if (!membership) {
        return null;
      }
      const user = usersById.get(normalizedUserId);
      return {
        membership_id: String(membership.membershipId || '').trim(),
        user_id: normalizedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership.tenantName ? String(membership.tenantName) : null,
        phone: user?.phone ? String(user.phone) : '',
        status: normalizeTenantMembershipStatusForRead(membership.status),
        display_name: resolveOptionalTenantMemberProfileField(membership.displayName),
        department_name: resolveOptionalTenantMemberProfileField(
          membership.departmentName
        ),
        joined_at: membership.joinedAt || null,
        left_at: membership.leftAt || null
      };
    },

    findTenantMembershipByMembershipIdAndTenantId: async ({
      membershipId,
      tenantId
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return null;
      }
      const membershipState = findTenantMembershipStateByMembershipId(
        normalizedMembershipId
      );
      if (!membershipState) {
        return null;
      }
      const membership = membershipState.membership;
      if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
        return null;
      }
      const resolvedUserId = String(membershipState.userId || '').trim();
      const user = usersById.get(resolvedUserId);
      return {
        membership_id: normalizedMembershipId,
        user_id: resolvedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
        phone: user?.phone ? String(user.phone) : '',
        status: normalizeTenantMembershipStatusForRead(membership?.status),
        display_name: resolveOptionalTenantMemberProfileField(
          membership?.displayName
        ),
        department_name: resolveOptionalTenantMemberProfileField(
          membership?.departmentName
        ),
        joined_at: membership?.joinedAt || null,
        left_at: membership?.leftAt || null
      };
    },

    listTenantMembersByTenantId: async ({ tenantId, page = 1, pageSize = 50 }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return [];
      }
      const normalizedPage = Number.parseInt(String(page || '1'), 10);
      const normalizedPageSize = Number.parseInt(String(pageSize || '50'), 10);
      const resolvedPage = Number.isFinite(normalizedPage) && normalizedPage > 0
        ? normalizedPage
        : 1;
      const resolvedPageSize = Number.isFinite(normalizedPageSize) && normalizedPageSize > 0
        ? Math.min(normalizedPageSize, 200)
        : 50;
      const members = [];
      for (const [userId, memberships] of tenantsByUserId.entries()) {
        const user = usersById.get(String(userId));
        if (!user) {
          continue;
        }
        for (const membership of Array.isArray(memberships) ? memberships : []) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          members.push({
            membership_id: String(membership.membershipId || '').trim(),
            user_id: String(userId),
            tenant_id: normalizedTenantId,
            tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
            phone: String(user.phone || ''),
            status: normalizeTenantMembershipStatusForRead(membership?.status),
            display_name: resolveOptionalTenantMemberProfileField(
              membership?.displayName
            ),
            department_name: resolveOptionalTenantMemberProfileField(
              membership?.departmentName
            ),
            joined_at: membership?.joinedAt || null,
            left_at: membership?.leftAt || null
          });
        }
      }
      members.sort((left, right) => {
        const leftJoinedAt = Date.parse(String(left.joined_at || ''));
        const rightJoinedAt = Date.parse(String(right.joined_at || ''));
        const normalizedLeftJoinedAt = Number.isFinite(leftJoinedAt) ? leftJoinedAt : 0;
        const normalizedRightJoinedAt = Number.isFinite(rightJoinedAt) ? rightJoinedAt : 0;
        if (normalizedLeftJoinedAt !== normalizedRightJoinedAt) {
          return normalizedRightJoinedAt - normalizedLeftJoinedAt;
        }
        return String(right.membership_id || '').localeCompare(
          String(left.membership_id || '')
        );
      });
      const offset = (resolvedPage - 1) * resolvedPageSize;
      return members.slice(offset, offset + resolvedPageSize);
    },

    updateTenantMembershipProfile: async ({
      membershipId,
      tenantId,
      displayName,
      departmentNameProvided = false,
      departmentName = null
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedDisplayName = normalizeOptionalTenantMemberProfileField({
        value: displayName,
        maxLength: MAX_TENANT_MEMBER_DISPLAY_NAME_LENGTH
      });
      if (
        !normalizedMembershipId
        || !normalizedTenantId
        || normalizedDisplayName === null
      ) {
        throw new Error(
          'updateTenantMembershipProfile requires membershipId, tenantId and displayName'
        );
      }
      const shouldUpdateDepartmentName = departmentNameProvided === true;
      let normalizedDepartmentName = null;
      if (shouldUpdateDepartmentName) {
        if (departmentName === null) {
          normalizedDepartmentName = null;
        } else {
          normalizedDepartmentName = normalizeOptionalTenantMemberProfileField({
            value: departmentName,
            maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
          });
          if (normalizedDepartmentName === null) {
            throw new Error('updateTenantMembershipProfile departmentName is invalid');
          }
        }
      }

      const membershipState = findTenantMembershipStateByMembershipId(
        normalizedMembershipId
      );
      if (!membershipState) {
        return null;
      }
      const membership = membershipState.membership;
      if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
        return null;
      }
      const resolvedUserId = String(membershipState.userId || '').trim();
      const user = usersById.get(resolvedUserId);
      const rawUserPhone = user?.phone === null || user?.phone === undefined
        ? ''
        : String(user.phone);
      const normalizedUserPhone = rawUserPhone.trim();
      if (
        !normalizedUserPhone
        || rawUserPhone !== normalizedUserPhone
        || !MAINLAND_PHONE_PATTERN.test(normalizedUserPhone)
      ) {
        const dependencyError = new Error(
          'updateTenantMembershipProfile dependency unavailable: user-profile-missing'
        );
        dependencyError.code =
          'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
        throw dependencyError;
      }
      if (
        !shouldUpdateDepartmentName
        && !isStrictOptionalTenantMemberProfileField({
          value: membership?.departmentName,
          maxLength: MAX_TENANT_MEMBER_DEPARTMENT_NAME_LENGTH
        })
      ) {
        const dependencyError = new Error(
          'updateTenantMembershipProfile dependency unavailable: membership-profile-invalid'
        );
        dependencyError.code =
          'ERR_TENANT_MEMBERSHIP_PROFILE_DEPENDENCY_UNAVAILABLE';
        throw dependencyError;
      }
      membership.displayName = normalizedDisplayName;
      if (shouldUpdateDepartmentName) {
        membership.departmentName = normalizedDepartmentName;
      }
      return {
        membership_id: normalizedMembershipId,
        user_id: resolvedUserId,
        tenant_id: normalizedTenantId,
        tenant_name: membership?.tenantName ? String(membership.tenantName) : null,
        phone: normalizedUserPhone,
        status: normalizeTenantMembershipStatusForRead(membership?.status),
        display_name: resolveOptionalTenantMemberProfileField(
          membership?.displayName
        ),
        department_name: resolveOptionalTenantMemberProfileField(
          membership?.departmentName
        ),
        joined_at: membership?.joinedAt || null,
        left_at: membership?.leftAt || null
      };
    },

    updateTenantMembershipStatus: async ({
      membershipId,
      tenantId,
      nextStatus,
      operatorUserId = null,
      reason = null,
      auditContext = null
    }) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedNextStatus = normalizeTenantMembershipStatusForRead(nextStatus);
      if (
        !normalizedMembershipId
        || !normalizedTenantId
        || !VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedNextStatus)
      ) {
        throw new Error(
          'updateTenantMembershipStatus requires membershipId, tenantId and supported nextStatus'
        );
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          tenantsByUserId: structuredClone(tenantsByUserId),
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          tenantMembershipHistoryByPair: structuredClone(tenantMembershipHistoryByPair),
          domainsByUserId: structuredClone(domainsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        let targetUserId = '';
        const tenantMembershipsByUser = [...tenantsByUserId.entries()];
        let targetMembership = null;
        let targetMemberships = null;

        for (const [userId, memberships] of tenantMembershipsByUser) {
          if (!Array.isArray(memberships)) {
            continue;
          }
          const match = memberships.find((membership) => {
            const membershipTenantId = String(membership?.tenantId || '').trim();
            const resolvedMembershipId = String(membership?.membershipId || '').trim();
            return (
              membershipTenantId === normalizedTenantId
              && resolvedMembershipId === normalizedMembershipId
            );
          });
          if (!match) {
            continue;
          }
          targetUserId = String(userId || '').trim();
          targetMembership = match;
          targetMemberships = memberships;
          break;
        }

        if (!targetMembership || !targetUserId || !targetMemberships) {
          return null;
        }

        const previousStatus = normalizeTenantMembershipStatusForRead(targetMembership.status);
        if (!VALID_TENANT_MEMBERSHIP_STATUS.has(previousStatus)) {
          throw new Error('updateTenantMembershipStatus encountered unsupported existing status');
        }
        if (previousStatus !== normalizedNextStatus) {
          let previousMembershipId = '';
          if (previousStatus === 'left' && normalizedNextStatus === 'active') {
            appendTenantMembershipHistory({
              membership: {
                ...targetMembership,
                userId: targetUserId,
                tenantId: normalizedTenantId
              },
              reason: reason || 'reactivate',
              operatorUserId
            });
            previousMembershipId = String(targetMembership.membershipId || '').trim();
            targetMembership.membershipId = randomUUID();
            targetMembership.joinedAt = new Date().toISOString();
            targetMembership.leftAt = null;
            if (targetMembership.permission) {
              targetMembership.permission = {
                ...targetMembership.permission,
                canViewMemberAdmin: false,
                canOperateMemberAdmin: false,
                canViewBilling: false,
                canOperateBilling: false
              };
            }
            if (previousMembershipId) {
              tenantMembershipRolesByMembershipId.delete(previousMembershipId);
            }
            tenantMembershipRolesByMembershipId.set(
              String(targetMembership.membershipId || '').trim(),
              []
            );
          } else if (normalizedNextStatus === 'left') {
            appendTenantMembershipHistory({
              membership: {
                ...targetMembership,
                userId: targetUserId,
                tenantId: normalizedTenantId
              },
              reason: reason || 'left',
              operatorUserId
            });
            targetMembership.leftAt = new Date().toISOString();
            if (targetMembership.permission) {
              targetMembership.permission = {
                ...targetMembership.permission,
                canViewMemberAdmin: false,
                canOperateMemberAdmin: false,
                canViewBilling: false,
                canOperateBilling: false
              };
            }
            const resolvedMembershipId = String(targetMembership.membershipId || '').trim();
            if (resolvedMembershipId) {
              tenantMembershipRolesByMembershipId.delete(resolvedMembershipId);
            }
          } else if (normalizedNextStatus === 'active') {
            targetMembership.leftAt = null;
          }

          targetMembership.status = normalizedNextStatus;
          tenantsByUserId.set(targetUserId, targetMemberships);

          if (normalizedNextStatus === 'active') {
            const userDomains = domainsByUserId.get(targetUserId) || new Set();
            userDomains.add('tenant');
            domainsByUserId.set(targetUserId, userDomains);
          } else {
            revokeTenantSessionsForUser({
              userId: targetUserId,
              reason: 'tenant-membership-status-changed',
              activeTenantId: normalizedTenantId
            });
            const userDomains = domainsByUserId.get(targetUserId) || new Set();
            const hasAnyActiveMembership = (tenantsByUserId.get(targetUserId) || []).some(
              (membership) => isTenantMembershipActiveForAuth(membership)
            );
            if (!hasAnyActiveMembership) {
              userDomains.delete('tenant');
            }
            domainsByUserId.set(targetUserId, userDomains);
          }

          if (normalizedNextStatus === 'active') {
            syncTenantMembershipPermissionSnapshot({
              membershipState: {
                userId: targetUserId,
                memberships: targetMemberships,
                membership: targetMembership
              },
              reason: 'tenant-membership-status-changed'
            });
          }
        }

        const resolvedMembershipId = String(targetMembership.membershipId || '').trim();
        const currentStatus = normalizeTenantMembershipStatusForRead(targetMembership.status);
        let auditRecorded = false;
        if (shouldRecordAudit) {
          const normalizedAuditReason =
            auditContext.reason === null || auditContext.reason === undefined
              ? null
              : String(auditContext.reason).trim() || null;
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedTenantId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.tenant.member.status.updated',
              actorUserId: auditContext.actorUserId || operatorUserId || null,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'membership',
              targetId: resolvedMembershipId,
              result: 'success',
              beforeState: {
                status: previousStatus
              },
              afterState: {
                status: currentStatus
              },
              metadata: {
                tenant_id: normalizedTenantId,
                membership_id: resolvedMembershipId,
                target_user_id: targetUserId,
                previous_status: previousStatus,
                current_status: currentStatus,
                reason: normalizedAuditReason
              }
            });
          } catch (error) {
            const auditWriteError = new Error('tenant membership status audit write failed');
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }

        return {
          membership_id: resolvedMembershipId,
          user_id: targetUserId,
          tenant_id: normalizedTenantId,
          previous_status: previousStatus,
          current_status: currentStatus,
          audit_recorded: auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(
            tenantMembershipHistoryByPair,
            snapshot.tenantMembershipHistoryByPair
          );
          restoreMapFromSnapshot(domainsByUserId, snapshot.domainsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    listTenantMembershipRoleBindings: async ({
      membershipId,
      tenantId
    } = {}) =>
      listTenantMembershipRoleBindingsForMembershipId({
        membershipId,
        tenantId
      }),

    replaceTenantMembershipRoleBindingsAndSyncSnapshot: async ({
      tenantId,
      membershipId,
      roleIds = [],
      auditContext = null
    } = {}) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedTenantId || !normalizedMembershipId) {
        throw new Error('replaceTenantMembershipRoleBindingsAndSyncSnapshot requires tenantId and membershipId');
      }
      const shouldRecordAudit = auditContext && typeof auditContext === 'object';
      const snapshot = shouldRecordAudit
        ? {
          tenantMembershipRolesByMembershipId: structuredClone(
            tenantMembershipRolesByMembershipId
          ),
          tenantsByUserId: structuredClone(tenantsByUserId),
          sessionsById: structuredClone(sessionsById),
          refreshTokensByHash: structuredClone(refreshTokensByHash),
          auditEvents: structuredClone(auditEvents)
        }
        : null;
      try {
        const membershipState = findTenantMembershipStateByMembershipId(
          normalizedMembershipId
        );
        if (!membershipState) {
          return null;
        }
        if (
          String(membershipState.membership?.tenantId || '').trim()
          !== normalizedTenantId
        ) {
          return null;
        }
        if (
          !isActiveLikeStatus(
            normalizeTenantMembershipStatusForRead(
              membershipState.membership?.status
            )
          )
        ) {
          const membershipStatusError = new Error(
            'tenant membership role bindings membership not active'
          );
          membershipStatusError.code =
            'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE';
          throw membershipStatusError;
        }
        const normalizedAffectedUserId =
          normalizeStrictTenantMembershipRoleBindingIdentity(
            membershipState?.userId,
            'tenant-membership-role-bindings-invalid-affected-user-id'
          );
        const normalizedRoleIds = [...new Set(
          (Array.isArray(roleIds) ? roleIds : [])
            .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
            .filter((roleId) => roleId.length > 0)
        )].sort((left, right) => left.localeCompare(right));
        for (const roleId of normalizedRoleIds) {
          const catalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
            roleId
          )?.record;
          const normalizedScope = normalizePlatformRoleCatalogScope(
            catalogEntry?.scope
          );
          const normalizedCatalogTenantId = normalizePlatformRoleCatalogTenantId(
            catalogEntry?.tenantId
          );
          let normalizedCatalogStatus = 'disabled';
          try {
            normalizedCatalogStatus = normalizePlatformRoleCatalogStatus(
              catalogEntry?.status || 'disabled'
            );
          } catch (_error) {}
          if (
            !catalogEntry
            || normalizedScope !== 'tenant'
            || normalizedCatalogTenantId !== normalizedTenantId
            || !isActiveLikeStatus(normalizedCatalogStatus)
          ) {
            const roleBindingError = new Error(
              'tenant membership role bindings role invalid'
            );
            roleBindingError.code =
              'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID';
            roleBindingError.roleId = roleId;
            throw roleBindingError;
          }
        }
        const previousRoleIds = listTenantMembershipRoleBindingsForMembershipId({
          membershipId: normalizedMembershipId,
          tenantId: normalizedTenantId
        });
        const resolvedRoleIds = replaceTenantMembershipRoleBindingsForMembershipId({
          membershipId: normalizedMembershipId,
          roleIds: normalizedRoleIds
        });
        const rollbackRoleBindings = () =>
          replaceTenantMembershipRoleBindingsForMembershipId({
            membershipId: normalizedMembershipId,
            roleIds: previousRoleIds
          });
        let syncResult;
        try {
          syncResult = syncTenantMembershipPermissionSnapshot({
            membershipState,
            reason: 'tenant-membership-role-bindings-changed'
          });
        } catch (error) {
          rollbackRoleBindings();
          throw error;
        }
        const syncReason = String(syncResult?.reason || 'unknown')
          .trim()
          .toLowerCase();
        if (syncReason !== 'ok') {
          rollbackRoleBindings();
          const syncError = new Error(
            `tenant membership role bindings sync failed: ${syncReason || 'unknown'}`
          );
          syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
          syncError.syncReason = syncReason || 'unknown';
          throw syncError;
        }
        let auditRecorded = false;
        if (shouldRecordAudit) {
          try {
            persistAuditEvent({
              domain: 'tenant',
              tenantId: normalizedTenantId,
              requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
              traceparent: auditContext.traceparent,
              eventType: 'auth.tenant_membership_roles.updated',
              actorUserId: auditContext.actorUserId || null,
              actorSessionId: auditContext.actorSessionId || null,
              targetType: 'membership_role_bindings',
              targetId: normalizedMembershipId,
              result: 'success',
              beforeState: {
                role_ids: previousRoleIds
              },
              afterState: {
                role_ids: resolvedRoleIds
              },
              metadata: {
                affected_user_count: 1
              }
            });
          } catch (error) {
            const auditWriteError = new Error(
              'tenant membership role bindings audit write failed'
            );
            auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
            auditWriteError.cause = error;
            throw auditWriteError;
          }
          auditRecorded = true;
        }
        return {
          membershipId: normalizedMembershipId,
          roleIds: resolvedRoleIds,
          affectedUserIds: [normalizedAffectedUserId],
          affectedUserCount: 1,
          auditRecorded
        };
      } catch (error) {
        if (snapshot) {
          restoreMapFromSnapshot(
            tenantMembershipRolesByMembershipId,
            snapshot.tenantMembershipRolesByMembershipId
          );
          restoreMapFromSnapshot(tenantsByUserId, snapshot.tenantsByUserId);
          restoreMapFromSnapshot(sessionsById, snapshot.sessionsById);
          restoreMapFromSnapshot(refreshTokensByHash, snapshot.refreshTokensByHash);
          restoreAuditEventsFromSnapshot(snapshot.auditEvents);
        }
        throw error;
      }
    },

    hasAnyTenantRelationshipByUserId: async (userId) =>
      (tenantsByUserId.get(String(userId)) || []).length > 0,

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      const tenant = (tenantsByUserId.get(String(userId)) || []).find(
        (item) =>
          String(item.tenantId) === normalizedTenantId &&
          isTenantMembershipActiveForAuth(item)
      );
      if (!tenant) {
        return null;
      }
      if (tenant.permission) {
        return {
          scopeLabel: tenant.permission.scopeLabel || `组织权限（${tenant.tenantName || tenant.tenantId}）`,
          canViewMemberAdmin: Boolean(tenant.permission.canViewMemberAdmin),
          canOperateMemberAdmin: Boolean(tenant.permission.canOperateMemberAdmin),
          canViewBilling: Boolean(tenant.permission.canViewBilling),
          canOperateBilling: Boolean(tenant.permission.canOperateBilling)
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
          normalizedPermissionCode !== 'platform.system_config.view'
          && normalizedPermissionCode !== 'platform.system_config.operate'
        )
      ) {
        return {
          canViewSystemConfig: false,
          canOperateSystemConfig: false,
          granted: false
        };
      }

      const roles = platformRolesByUserId.get(normalizedUserId) || [];
      let canViewSystemConfig = false;
      let canOperateSystemConfig = false;

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
        if (Boolean(permission.canViewSystemConfig ?? permission.can_view_system_config)) {
          canViewSystemConfig = true;
        }
        if (Boolean(permission.canOperateSystemConfig ?? permission.can_operate_system_config)) {
          canOperateSystemConfig = true;
          canViewSystemConfig = true;
        }

        const grantCodes = listPlatformRolePermissionGrantsForRoleId(role.roleId);
        if (grantCodes.includes('platform.system_config.operate')) {
          canOperateSystemConfig = true;
          canViewSystemConfig = true;
        } else if (grantCodes.includes('platform.system_config.view')) {
          canViewSystemConfig = true;
        }

        if (canViewSystemConfig && canOperateSystemConfig) {
          break;
        }
      }

      const granted = normalizedPermissionCode === 'platform.system_config.operate'
        ? canOperateSystemConfig
        : canViewSystemConfig;
      return {
        canViewSystemConfig,
        canOperateSystemConfig,
        granted
      };
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

    listPlatformRolePermissionGrants: async ({ roleId }) =>
      listPlatformRolePermissionGrantsForRoleId(roleId),

    listPlatformRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      return normalizedRoleIds.map((roleId) => ({
        roleId,
        permissionCodes: listPlatformRolePermissionGrantsForRoleId(roleId)
      }));
    },

    replacePlatformRolePermissionGrants: async ({
      roleId,
      permissionCodes = []
    }) =>
      replacePlatformRolePermissionGrantsForRoleId({
        roleId,
        permissionCodes
      }),

    listTenantRolePermissionGrants: async ({ roleId }) =>
      listTenantRolePermissionGrantsForRoleId(roleId),

    listTenantRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = [...new Set(
        (Array.isArray(roleIds) ? roleIds : [])
          .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
          .filter((roleId) => roleId.length > 0)
      )];
      return normalizedRoleIds.map((roleId) => ({
        roleId,
        permissionCodes: listTenantRolePermissionGrantsForRoleId(roleId)
      }));
    },

    replaceTenantRolePermissionGrantsAndSyncSnapshots: async ({
      tenantId,
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      operatorSessionId = null,
      auditContext = null,
      maxAffectedMemberships = 100
    }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedTenantId || !normalizedRoleId) {
        throw new Error('replaceTenantRolePermissionGrantsAndSyncSnapshots requires tenantId and roleId');
      }
      const roleCatalogEntry = findPlatformRoleCatalogRecordStateByRoleId(
        normalizedRoleId
      )?.record;
      if (!roleCatalogEntry) {
        return null;
      }
      if (
        normalizePlatformRoleCatalogScope(roleCatalogEntry.scope) !== 'tenant'
        || normalizePlatformRoleCatalogTenantId(roleCatalogEntry.tenantId) !== normalizedTenantId
      ) {
        return null;
      }
      const normalizedMaxAffectedMemberships = Math.max(
        1,
        Math.floor(Number(maxAffectedMemberships || 100))
      );
      const affectedMembershipStatesByMembershipId = new Map();
      for (const [userId, memberships] of tenantsByUserId.entries()) {
        for (const membership of Array.isArray(memberships) ? memberships : []) {
          if (String(membership?.tenantId || '').trim() !== normalizedTenantId) {
            continue;
          }
          if (!isTenantMembershipActiveForAuth(membership)) {
            continue;
          }
          const membershipId = normalizeStrictTenantRolePermissionGrantIdentity(
            membership?.membershipId || membership?.membership_id,
            'tenant-role-permission-grants-invalid-membership-id'
          );
          const boundRoleIds = listTenantMembershipRoleBindingsForMembershipId({
            membershipId,
            tenantId: normalizedTenantId
          });
          if (!boundRoleIds.includes(normalizedRoleId)) {
            continue;
          }
          affectedMembershipStatesByMembershipId.set(membershipId, {
            userId: normalizeStrictTenantRolePermissionGrantIdentity(
              userId,
              'tenant-role-permission-grants-invalid-affected-user-id'
            ),
            memberships,
            membership
          });
        }
      }
      if (
        affectedMembershipStatesByMembershipId.size
        > normalizedMaxAffectedMemberships
      ) {
        const limitError = new Error('tenant role permission affected memberships exceed limit');
        limitError.code = 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT';
        limitError.maxAffectedMemberships = normalizedMaxAffectedMemberships;
        limitError.affectedMemberships = affectedMembershipStatesByMembershipId.size;
        throw limitError;
      }
      const previousPermissionCodes = listTenantRolePermissionGrantsForRoleId(
        normalizedRoleId
      );
      const previousMembershipPermissionsByMembershipId = new Map();
      for (const [membershipId, membershipState] of affectedMembershipStatesByMembershipId.entries()) {
        const previousPermission =
          membershipState?.membership?.permission
          && typeof membershipState.membership.permission === 'object'
            ? { ...membershipState.membership.permission }
            : null;
        previousMembershipPermissionsByMembershipId.set(
          membershipId,
          previousPermission
        );
      }
      const savedPermissionCodes = replaceTenantRolePermissionGrantsForRoleId({
        roleId: normalizedRoleId,
        permissionCodes
      });
      const affectedUserIds = new Set();
      const tenantSessionRevocations = new Map();
      try {
        for (const [
          membershipId,
          membershipState
        ] of affectedMembershipStatesByMembershipId.entries()) {
          const resolvedUserId = normalizeStrictTenantRolePermissionGrantIdentity(
            membershipState?.userId,
            'tenant-role-permission-grants-invalid-affected-user-id'
          );
          affectedUserIds.add(resolvedUserId);
          invokeFaultInjector('beforeTenantRolePermissionSnapshotSync', {
            tenantId: normalizedTenantId,
            roleId: normalizedRoleId,
            membershipId,
            userId: resolvedUserId
          });
          const syncResult = syncTenantMembershipPermissionSnapshot({
            membershipState,
            reason: 'tenant-role-permission-grants-changed',
            revokeSessions: false
          });
          if (!syncResult?.synced || syncResult.reason !== 'ok') {
            const syncError = new Error(
              `tenant role permission sync failed: ${String(syncResult?.reason || 'unknown')}`
            );
            syncError.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
            syncError.syncReason = String(syncResult?.reason || 'unknown');
            throw syncError;
          }
          const syncUserId = String(syncResult?.userId || '').trim();
          const syncTenantId = String(syncResult?.tenantId || '').trim();
          if (syncResult.changed && syncUserId && syncTenantId) {
            tenantSessionRevocations.set(`${syncUserId}::${syncTenantId}`, {
              userId: syncUserId,
              tenantId: syncTenantId
            });
          }
        }
      } catch (error) {
        replaceTenantRolePermissionGrantsForRoleId({
          roleId: normalizedRoleId,
          permissionCodes: previousPermissionCodes
        });
        for (const [
          membershipId,
          membershipState
        ] of affectedMembershipStatesByMembershipId.entries()) {
          if (!membershipState?.membership || typeof membershipState.membership !== 'object') {
            continue;
          }
          const previousPermission =
            previousMembershipPermissionsByMembershipId.get(membershipId);
          membershipState.membership.permission = previousPermission
            ? { ...previousPermission }
            : null;
        }
        throw error;
      }
      for (const { userId, tenantId: activeTenantId } of tenantSessionRevocations.values()) {
        revokeTenantSessionsForUser({
          userId,
          reason: 'tenant-role-permission-grants-changed',
          activeTenantId
        });
      }
      let auditRecorded = false;
      if (auditContext && typeof auditContext === 'object') {
        try {
          persistAuditEvent({
            domain: 'tenant',
            tenantId: normalizedTenantId,
            requestId: String(auditContext.requestId || '').trim() || 'request_id_unset',
            traceparent: auditContext.traceparent,
            eventType: 'auth.tenant_role_permission_grants.updated',
            actorUserId: auditContext.actorUserId || operatorUserId || null,
            actorSessionId: auditContext.actorSessionId || operatorSessionId || null,
            targetType: 'role_permission_grants',
            targetId: normalizedRoleId,
            result: 'success',
            beforeState: {
              permission_codes: [...previousPermissionCodes]
            },
            afterState: {
              permission_codes: [...savedPermissionCodes]
            },
            metadata: {
              affected_user_count: affectedUserIds.size
            }
          });
        } catch (error) {
          const auditWriteError = new Error(
            'tenant role permission grants audit write failed'
          );
          auditWriteError.code = 'ERR_AUDIT_WRITE_FAILED';
          auditWriteError.cause = error;
          throw auditWriteError;
        }
        auditRecorded = true;
      }

      return {
        roleId: normalizedRoleId,
        permissionCodes: savedPermissionCodes,
        affectedUserIds: [...affectedUserIds],
        affectedUserCount: affectedUserIds.size,
        auditRecorded
      };
    },

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
    },

    syncPlatformPermissionSnapshotByUserId: async ({
      userId,
      forceWhenNoRoleFacts = false
    }) =>
      syncPlatformPermissionFromRoleFacts({
        userId,
        forceWhenNoRoleFacts
      }),

    replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId || !usersById.has(normalizedUserId)) {
        return {
          synced: false,
          reason: 'invalid-user-id',
          permission: null
        };
      }

      const previousRoles = platformRolesByUserId.get(normalizedUserId) || [];
      const previousPermission = platformPermissionsByUserId.get(normalizedUserId)
        || mergePlatformPermissionFromRoles(previousRoles)
        || buildEmptyPlatformPermission();

      const normalizedRoles = dedupePlatformRolesByRoleId(
        (Array.isArray(roles) ? roles : [])
          .map((role) => normalizePlatformRole(role))
          .filter(Boolean)
      );
      platformRolesByUserId.set(normalizedUserId, normalizedRoles);
      const syncResult = syncPlatformPermissionFromRoleFacts({
        userId: normalizedUserId,
        forceWhenNoRoleFacts: true
      });

      const nextPermission = syncResult?.permission || buildEmptyPlatformPermission();
      if (!isSamePlatformPermission(previousPermission, nextPermission)) {
        bumpSessionVersionAndConvergeSessions({
          userId: normalizedUserId,
          reason: 'platform-role-facts-changed',
          revokeRefreshTokens: true,
          revokeAuthSessions: true
        });
      }

      return syncResult;
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

module.exports = { createInMemoryAuthStore };
