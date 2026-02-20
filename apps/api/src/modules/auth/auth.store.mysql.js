const { setTimeout: sleep } = require('node:timers/promises');
const { createHash, randomUUID } = require('node:crypto');
const { log } = require('../../common/logger');

const DEFAULT_DEADLOCK_RETRY_CONFIG = Object.freeze({
  maxRetries: 2,
  baseDelayMs: 20,
  maxDelayMs: 200,
  jitterMs: 20
});
const DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS = 100;
const MYSQL_DUP_ENTRY_ERRNO = 1062;
const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const VALID_ORG_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_USER_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_STATUS = new Set(['active', 'disabled']);
const VALID_PLATFORM_ROLE_CATALOG_SCOPE = new Set(['platform', 'tenant']);
const VALID_TENANT_MEMBERSHIP_STATUS = new Set(['active', 'disabled', 'left']);
const KNOWN_TENANT_PERMISSION_CODES = Object.freeze([
  'tenant.member_admin.view',
  'tenant.member_admin.operate',
  'tenant.billing.view',
  'tenant.billing.operate'
]);
const KNOWN_TENANT_PERMISSION_CODE_SET = new Set(KNOWN_TENANT_PERMISSION_CODES);
const OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX = 30;
const OWNER_TRANSFER_LOCK_NAME_PREFIX = 'neweast:owner-transfer:';

const normalizeUserStatus = (status) => {
  if (typeof status !== 'string') {
    return 'disabled';
  }
  const value = status.trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};
const normalizeOrgName = (orgName) => {
  if (typeof orgName !== 'string') {
    return '';
  }
  return orgName.trim();
};
const normalizeOrgStatus = (status) => {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};
const normalizeTenantMembershipStatus = (status) => {
  const value = String(status ?? '').trim().toLowerCase();
  if (!value) {
    return 'active';
  }
  if (value === 'enabled') {
    return 'active';
  }
  return VALID_TENANT_MEMBERSHIP_STATUS.has(value) ? value : '';
};
const normalizeTenantMembershipStatusForRead = (status) => {
  const value = String(status ?? '').trim().toLowerCase();
  if (!value) {
    return '';
  }
  if (value === 'enabled') {
    return 'active';
  }
  return VALID_TENANT_MEMBERSHIP_STATUS.has(value) ? value : '';
};
const normalizePlatformRoleCatalogStatus = (status) => {
  const value = String(status || '').trim().toLowerCase();
  if (value === 'enabled') {
    return 'active';
  }
  return value;
};
const normalizePlatformRoleCatalogScope = (scope) =>
  String(scope || '').trim().toLowerCase();
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
const normalizeOwnerTransferLockTimeoutSeconds = (timeoutSeconds) => {
  const parsed = Number(timeoutSeconds);
  if (!Number.isFinite(parsed)) {
    return 0;
  }
  return Math.max(
    0,
    Math.min(
      OWNER_TRANSFER_LOCK_TIMEOUT_SECONDS_MAX,
      Math.floor(parsed)
    )
  );
};
const toOwnerTransferLockName = (orgId) => {
  const normalizedOrgId = String(orgId || '').trim();
  if (!normalizedOrgId) {
    return '';
  }
  const lockDigest = createHash('sha256')
    .update(normalizedOrgId)
    .digest('hex')
    .slice(0, 40);
  return `${OWNER_TRANSFER_LOCK_NAME_PREFIX}${lockDigest}`;
};
const DEFAULT_DEADLOCK_FALLBACK_RESULT = Object.freeze({
  synced: false,
  reason: 'db-deadlock',
  permission: null
});

const toSessionRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    sessionId: row.session_id,
    userId: String(row.user_id),
    sessionVersion: Number(row.session_version),
    entryDomain: row.entry_domain ? String(row.entry_domain) : 'platform',
    activeTenantId: row.active_tenant_id ? String(row.active_tenant_id) : null,
    status: row.status,
    revokedReason: row.revoked_reason || null
  };
};

const toRefreshRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    tokenHash: row.token_hash,
    sessionId: row.session_id,
    userId: String(row.user_id),
    status: row.status,
    rotatedFrom: row.rotated_from_token_hash || null,
    rotatedTo: row.rotated_to_token_hash || null,
    expiresAt: Number(row.expires_at_epoch_ms)
  };
};

const toUserRecord = (row) => {
  if (!row) {
    return null;
  }

  return {
    id: String(row.id),
    phone: row.phone,
    passwordHash: row.password_hash,
    status: normalizeUserStatus(row.status),
    sessionVersion: Number(row.session_version)
  };
};

const toPlatformRoleCatalogRecord = (row) => {
  if (!row) {
    return null;
  }
  return {
    roleId: String(row.role_id || '').trim(),
    tenantId: normalizePlatformRoleCatalogTenantId(row.tenant_id) || null,
    code: String(row.code || '').trim(),
    name: String(row.name || '').trim(),
    status: normalizePlatformRoleCatalogStatus(row.status || 'active'),
    scope: normalizePlatformRoleCatalogScope(row.scope || 'platform'),
    isSystem: toBoolean(row.is_system),
    createdByUserId: row.created_by_user_id ? String(row.created_by_user_id) : null,
    updatedByUserId: row.updated_by_user_id ? String(row.updated_by_user_id) : null,
    createdAt: row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at || ''),
    updatedAt: row.updated_at instanceof Date
      ? row.updated_at.toISOString()
      : String(row.updated_at || '')
  };
};

const toBoolean = (value) =>
  value === true || value === 1 || value === '1' || String(value || '').toLowerCase() === 'true';

const isActiveLikeStatus = (status) => {
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
  return normalizedStatus === 'active' || normalizedStatus === 'enabled';
};
const VALID_PLATFORM_ROLE_FACT_STATUS = new Set(['active', 'enabled', 'disabled']);

const toPlatformPermissionSnapshot = ({
  canViewMemberAdmin = false,
  canOperateMemberAdmin = false,
  canViewBilling = false,
  canOperateBilling = false
} = {}, scopeLabel = '平台权限（角色并集）') => ({
  scopeLabel,
  canViewMemberAdmin: Boolean(canViewMemberAdmin),
  canOperateMemberAdmin: Boolean(canOperateMemberAdmin),
  canViewBilling: Boolean(canViewBilling),
  canOperateBilling: Boolean(canOperateBilling)
});

const toPlatformPermissionSnapshotFromRow = (row, scopeLabel = '平台权限（角色并集）') =>
  toPlatformPermissionSnapshot(
    {
      canViewMemberAdmin: row?.can_view_member_admin ?? row?.canViewMemberAdmin,
      canOperateMemberAdmin: row?.can_operate_member_admin ?? row?.canOperateMemberAdmin,
      canViewBilling: row?.can_view_billing ?? row?.canViewBilling,
      canOperateBilling: row?.can_operate_billing ?? row?.canOperateBilling
    },
    scopeLabel
  );

const isEmptyPlatformPermissionSnapshot = (permission = {}) =>
  !Boolean(permission.canViewMemberAdmin)
  && !Boolean(permission.canOperateMemberAdmin)
  && !Boolean(permission.canViewBilling)
  && !Boolean(permission.canOperateBilling);

const isSamePlatformPermissionSnapshot = (left, right) => {
  const normalizedLeft = left || toPlatformPermissionSnapshot();
  const normalizedRight = right || toPlatformPermissionSnapshot();
  return (
    Boolean(normalizedLeft.canViewMemberAdmin) === Boolean(normalizedRight.canViewMemberAdmin)
    && Boolean(normalizedLeft.canOperateMemberAdmin) === Boolean(normalizedRight.canOperateMemberAdmin)
    && Boolean(normalizedLeft.canViewBilling) === Boolean(normalizedRight.canViewBilling)
    && Boolean(normalizedLeft.canOperateBilling) === Boolean(normalizedRight.canOperateBilling)
  );
};

const toEpochMilliseconds = (value) => {
  if (value === null || value === undefined) {
    return 0;
  }
  if (typeof value === 'number') {
    return Number.isFinite(value) ? value : 0;
  }
  if (value instanceof Date) {
    const timestamp = value.getTime();
    return Number.isFinite(timestamp) ? timestamp : 0;
  }
  const timestamp = new Date(value).getTime();
  return Number.isFinite(timestamp) ? timestamp : 0;
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

const aggregatePlatformPermissionFromRoleRows = (rows) => {
  const normalizedRows = Array.isArray(rows) ? rows : [];
  const activeRows = normalizedRows.filter((row) =>
    isActiveLikeStatus(row?.status)
  );

  return {
    hasRoleFacts: normalizedRows.length > 0,
    hasActiveRoleFacts: activeRows.length > 0,
    permission: toPlatformPermissionSnapshot({
      canViewMemberAdmin: activeRows.some((row) =>
        toBoolean(row?.can_view_member_admin ?? row?.canViewMemberAdmin)
      ),
      canOperateMemberAdmin: activeRows.some((row) =>
        toBoolean(row?.can_operate_member_admin ?? row?.canOperateMemberAdmin)
      ),
      canViewBilling: activeRows.some((row) =>
        toBoolean(row?.can_view_billing ?? row?.canViewBilling)
      ),
      canOperateBilling: activeRows.some((row) =>
        toBoolean(row?.can_operate_billing ?? row?.canOperateBilling)
      )
    })
  };
};

const normalizePlatformRoleFactPayload = (role) => {
  const roleId = String(role?.roleId || role?.role_id || '').trim();
  if (!roleId) {
    return null;
  }
  const permissionSource = role?.permission || role;
  return {
    roleId,
    status: normalizePlatformRoleStatus(role?.status),
    canViewMemberAdmin: toBoolean(
      permissionSource?.canViewMemberAdmin ?? permissionSource?.can_view_member_admin
    ),
    canOperateMemberAdmin: toBoolean(
      permissionSource?.canOperateMemberAdmin ?? permissionSource?.can_operate_member_admin
    ),
    canViewBilling: toBoolean(
      permissionSource?.canViewBilling ?? permissionSource?.can_view_billing
    ),
    canOperateBilling: toBoolean(
      permissionSource?.canOperateBilling ?? permissionSource?.can_operate_billing
    )
  };
};

const dedupePlatformRoleFacts = (roles = []) => {
  const dedupedByRoleId = new Map();
  for (const role of Array.isArray(roles) ? roles : []) {
    const normalizedRole = normalizePlatformRoleFactPayload(role);
    if (!normalizedRole) {
      continue;
    }
    const dedupeKey = String(normalizedRole.roleId || '').trim().toLowerCase();
    if (!dedupeKey) {
      continue;
    }
    dedupedByRoleId.set(dedupeKey, normalizedRole);
  }
  return [...dedupedByRoleId.values()];
};

const isTableMissingError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_NO_SUCH_TABLE'
  || Number(error?.errno || 0) === 1146;

const isDeadlockError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_LOCK_DEADLOCK'
  || Number(error?.errno || 0) === 1213
  || String(error?.sqlState || '').trim() === '40001';
const isDuplicateEntryError = (error) =>
  String(error?.code || '').toUpperCase() === 'ER_DUP_ENTRY'
  || Number(error?.errno || 0) === MYSQL_DUP_ENTRY_ERRNO;
const isMissingTenantMembershipHistoryTableError = (error) =>
  isTableMissingError(error)
  && /auth_user_tenant_membership_history/i.test(String(error?.message || ''));
const isMissingOrgsTableError = (error) =>
  isTableMissingError(error)
  && /\borgs\b/i.test(String(error?.message || ''));
const TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE =
  'AUTH-503-TENANT-MEMBER-HISTORY-UNAVAILABLE';
const createTenantMembershipHistoryUnavailableError = () => {
  const error = new Error(
    'tenant membership history table is required but unavailable'
  );
  error.code = TENANT_MEMBERSHIP_HISTORY_UNAVAILABLE_CODE;
  return error;
};
const buildSqlInPlaceholders = (count) =>
  new Array(Math.max(0, Number(count) || 0)).fill('?').join(', ');
const normalizePlatformPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const normalizePlatformPermissionCodes = (permissionCodes = []) => {
  const deduped = new Map();
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    const normalizedCode = normalizePlatformPermissionCode(permissionCode);
    if (!normalizedCode) {
      continue;
    }
    const permissionCodeKey = normalizedCode.toLowerCase();
    deduped.set(permissionCodeKey, permissionCodeKey);
  }
  return [...deduped.values()];
};
const toPlatformPermissionSnapshotFromGrantCodes = (permissionCodes = []) => {
  const normalizedPermissionCodeSet = new Set(
    normalizePlatformPermissionCodes(permissionCodes)
  );
  return toPlatformPermissionSnapshot({
    canViewMemberAdmin: normalizedPermissionCodeSet.has('platform.member_admin.view')
      || normalizedPermissionCodeSet.has('platform.member_admin.operate'),
    canOperateMemberAdmin: normalizedPermissionCodeSet.has('platform.member_admin.operate'),
    canViewBilling: normalizedPermissionCodeSet.has('platform.billing.view')
      || normalizedPermissionCodeSet.has('platform.billing.operate'),
    canOperateBilling: normalizedPermissionCodeSet.has('platform.billing.operate')
  });
};
const normalizeTenantPermissionCode = (permissionCode) =>
  String(permissionCode || '').trim();
const normalizeTenantPermissionCodes = (permissionCodes = []) => {
  const deduped = new Map();
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    const normalizedCode = normalizeTenantPermissionCode(permissionCode);
    if (!normalizedCode) {
      continue;
    }
    const permissionCodeKey = normalizedCode.toLowerCase();
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
  const permissionCodeKey = normalizedPermissionCode.toLowerCase();
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
const normalizeStrictRoleIdFromTenantGrantRow = (
  roleId,
  reason = 'tenant-role-permission-grants-invalid-role-id'
) => {
  if (typeof roleId !== 'string') {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
  if (
    roleId !== roleId.trim()
    || !normalizedRoleId
    || CONTROL_CHAR_PATTERN.test(normalizedRoleId)
    || !ROLE_ID_ADDRESSABLE_PATTERN.test(normalizedRoleId)
  ) {
    throw createTenantRolePermissionGrantDataError(reason);
  }
  return normalizedRoleId;
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
const toTenantPermissionSnapshotFromGrantCodes = (permissionCodes = []) => {
  const normalizedPermissionCodeSet = new Set(
    normalizeTenantPermissionCodes(permissionCodes)
  );
  return toPlatformPermissionSnapshot({
    canViewMemberAdmin: normalizedPermissionCodeSet.has('tenant.member_admin.view')
      || normalizedPermissionCodeSet.has('tenant.member_admin.operate'),
    canOperateMemberAdmin: normalizedPermissionCodeSet.has('tenant.member_admin.operate'),
    canViewBilling: normalizedPermissionCodeSet.has('tenant.billing.view')
      || normalizedPermissionCodeSet.has('tenant.billing.operate'),
    canOperateBilling: normalizedPermissionCodeSet.has('tenant.billing.operate')
  }, '组织权限（角色并集）');
};
const isSameTenantPermissionSnapshot = (left, right) =>
  isSamePlatformPermissionSnapshot(
    toPlatformPermissionSnapshot(
      {
        canViewMemberAdmin: left?.canViewMemberAdmin,
        canOperateMemberAdmin: left?.canOperateMemberAdmin,
        canViewBilling: left?.canViewBilling,
        canOperateBilling: left?.canOperateBilling
      },
      '组织权限（角色并集）'
    ),
    toPlatformPermissionSnapshot(
      {
        canViewMemberAdmin: right?.canViewMemberAdmin,
        canOperateMemberAdmin: right?.canOperateMemberAdmin,
        canViewBilling: right?.canViewBilling,
        canOperateBilling: right?.canOperateBilling
      },
      '组织权限（角色并集）'
    )
  );

const createMySqlAuthStore = ({
  dbClient,
  random = Math.random,
  sleepFn = sleep,
  deadlockRetryConfig = {},
  onDeadlockMetric = null
}) => {
  if (!dbClient || typeof dbClient.query !== 'function') {
    throw new Error('createMySqlAuthStore requires dbClient.query');
  }
  if (typeof dbClient.inTransaction !== 'function') {
    throw new Error('createMySqlAuthStore requires dbClient.inTransaction');
  }
  if (typeof random !== 'function') {
    throw new Error('createMySqlAuthStore requires random function when random is provided');
  }
  if (typeof sleepFn !== 'function') {
    throw new Error('createMySqlAuthStore requires sleepFn function when sleepFn is provided');
  }

  const retryConfig = {
    maxRetries: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.maxRetries
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.maxRetries
        )
      )
    ),
    baseDelayMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.baseDelayMs
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.baseDelayMs
        )
      )
    ),
    maxDelayMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.maxDelayMs
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.maxDelayMs
        )
      )
    ),
    jitterMs: Math.max(
      0,
      Math.floor(
        Number(
          deadlockRetryConfig?.jitterMs
            ?? DEFAULT_DEADLOCK_RETRY_CONFIG.jitterMs
        )
      )
    )
  };
  if (retryConfig.maxDelayMs < retryConfig.baseDelayMs) {
    retryConfig.maxDelayMs = retryConfig.baseDelayMs;
  }

  const deadlockMetricsByOperation = new Map();
  const getDeadlockMetricsByOperation = (operation) => {
    const normalizedOperation = String(operation || 'unknown');
    if (!deadlockMetricsByOperation.has(normalizedOperation)) {
      deadlockMetricsByOperation.set(normalizedOperation, {
        deadlockCount: 0,
        retrySuccessCount: 0,
        finalFailureCount: 0
      });
    }
    return deadlockMetricsByOperation.get(normalizedOperation);
  };

  const toDeadlockRates = (metrics) => {
    const resolutionCount =
      Number(metrics?.retrySuccessCount || 0) + Number(metrics?.finalFailureCount || 0);
    if (resolutionCount <= 0) {
      return {
        retrySuccessRate: 0,
        finalFailureRate: 0
      };
    }
    return {
      retrySuccessRate: Number((Number(metrics.retrySuccessCount) / resolutionCount).toFixed(6)),
      finalFailureRate: Number((Number(metrics.finalFailureCount) / resolutionCount).toFixed(6))
    };
  };

  const emitDeadlockMetric = ({
    operation,
    event,
    attemptsUsed,
    retriesUsed,
    retryDelayMs = null,
    error = null
  }) => {
    const metrics = getDeadlockMetricsByOperation(operation);
    if (event === 'deadlock-detected') {
      metrics.deadlockCount += 1;
    } else if (event === 'retry-succeeded') {
      metrics.retrySuccessCount += 1;
    } else if (event === 'final-failure') {
      metrics.finalFailureCount += 1;
    }
    const rates = toDeadlockRates(metrics);
    const payload = {
      operation: String(operation || 'unknown'),
      event: String(event || 'unknown'),
      deadlock_count: Number(metrics.deadlockCount),
      retry_success_count: Number(metrics.retrySuccessCount),
      final_failure_count: Number(metrics.finalFailureCount),
      retry_success_rate: Number(rates.retrySuccessRate),
      final_failure_rate: Number(rates.finalFailureRate),
      attempts_used: Number(attemptsUsed || 0),
      retries_used: Number(retriesUsed || 0),
      max_retries: Number(retryConfig.maxRetries),
      retry_delay_ms: retryDelayMs === null ? null : Number(retryDelayMs),
      error_code: String(error?.code || ''),
      error_errno: Number(error?.errno || 0),
      error_sql_state: String(error?.sqlState || '')
    };
    if (typeof onDeadlockMetric === 'function') {
      try {
        onDeadlockMetric(payload);
      } catch (_error) {}
    }
    return payload;
  };

  const computeRetryDelayMs = (retryNumber) => {
    const exponent = Math.max(0, Number(retryNumber || 1) - 1);
    const baseDelay = retryConfig.baseDelayMs * (2 ** exponent);
    const boundedDelay = Math.min(retryConfig.maxDelayMs, baseDelay);
    const randomValue = Number(random());
    const normalizedRandom = Number.isFinite(randomValue)
      ? Math.min(1, Math.max(0, randomValue))
      : 0;
    const jitter = retryConfig.jitterMs > 0
      ? Math.floor(normalizedRandom * (retryConfig.jitterMs + 1))
      : 0;
    return Math.max(0, Math.floor(boundedDelay + jitter));
  };

  const executeWithDeadlockRetry = async ({
    operation,
    execute,
    onExhausted = 'return-fallback',
    fallbackResult = DEFAULT_DEADLOCK_FALLBACK_RESULT
  }) => {
    let retriesUsed = 0;
    while (true) {
      try {
        const result = await execute();
        if (retriesUsed > 0) {
          const recoveredMetric = emitDeadlockMetric({
            operation,
            event: 'retry-succeeded',
            attemptsUsed: retriesUsed + 1,
            retriesUsed
          });
          log('info', 'MySQL deadlock recovered after retry', {
            component: 'auth.store.mysql',
            ...recoveredMetric
          });
        }
        return result;
      } catch (error) {
        if (!isDeadlockError(error)) {
          throw error;
        }
        const canRetry = retriesUsed < retryConfig.maxRetries;
        const retryDelayMs = canRetry ? computeRetryDelayMs(retriesUsed + 1) : null;
        const deadlockMetric = emitDeadlockMetric({
          operation,
          event: 'deadlock-detected',
          attemptsUsed: retriesUsed + 1,
          retriesUsed,
          retryDelayMs,
          error
        });
        if (canRetry) {
          log('warn', 'MySQL deadlock detected, retrying auth store operation', {
            component: 'auth.store.mysql',
            ...deadlockMetric
          });
          retriesUsed += 1;
          if (retryDelayMs > 0) {
            await sleepFn(retryDelayMs);
          }
          continue;
        }
        const finalFailureMetric = emitDeadlockMetric({
          operation,
          event: 'final-failure',
          attemptsUsed: retriesUsed + 1,
          retriesUsed,
          retryDelayMs: null,
          error
        });
        log('error', 'MySQL deadlock retries exhausted in auth store', {
          component: 'auth.store.mysql',
          alert: true,
          ...finalFailureMetric
        });
        if (onExhausted === 'throw') {
          throw error;
        }
        if (typeof fallbackResult === 'function') {
          return fallbackResult(error);
        }
        if (
          fallbackResult
          && typeof fallbackResult === 'object'
          && !Array.isArray(fallbackResult)
        ) {
          return { ...fallbackResult };
        }
        return DEFAULT_DEADLOCK_FALLBACK_RESULT;
      }
    }
  };
  let orgStatusGuardAvailable = true;
  let tenantMembershipHistoryTableAvailable = true;

  const runTenantMembershipQuery = async ({
    txClient = dbClient,
    sqlWithOrgGuard,
    sqlWithoutOrgGuard,
    params = []
  }) => {
    const queryClient = txClient || dbClient;
    if (!orgStatusGuardAvailable) {
      return queryClient.query(sqlWithoutOrgGuard, params);
    }
    try {
      return await queryClient.query(sqlWithOrgGuard, params);
    } catch (error) {
      if (!isMissingOrgsTableError(error)) {
        throw error;
      }
      orgStatusGuardAvailable = false;
      return queryClient.query(sqlWithoutOrgGuard, params);
    }
  };

  const insertTenantMembershipHistoryTx = async ({
    txClient,
    row,
    archivedReason = null,
    archivedByUserId = null
  }) => {
    if (!tenantMembershipHistoryTableAvailable) {
      throw createTenantMembershipHistoryUnavailableError();
    }
    const normalizedRowStatus = normalizeTenantMembershipStatusForRead(row?.status);
    if (!VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedRowStatus)) {
      throw new Error('insertTenantMembershipHistoryTx encountered unsupported status');
    }
    try {
      await txClient.query(
        `
          INSERT INTO auth_user_tenant_membership_history (
            membership_id,
            user_id,
            tenant_id,
            tenant_name,
            status,
            can_view_member_admin,
            can_operate_member_admin,
            can_view_billing,
            can_operate_billing,
            joined_at,
            left_at,
            archived_reason,
            archived_by_user_id
          )
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `,
        [
          String(row?.membership_id || '').trim(),
          String(row?.user_id || '').trim(),
          String(row?.tenant_id || '').trim(),
          row?.tenant_name === null || row?.tenant_name === undefined
            ? null
            : String(row.tenant_name || '').trim() || null,
          normalizedRowStatus,
          toBoolean(row?.can_view_member_admin) ? 1 : 0,
          toBoolean(row?.can_operate_member_admin) ? 1 : 0,
          toBoolean(row?.can_view_billing) ? 1 : 0,
          toBoolean(row?.can_operate_billing) ? 1 : 0,
          row?.joined_at || row?.created_at || null,
          row?.left_at || null,
          archivedReason === null || archivedReason === undefined
            ? null
            : String(archivedReason || '').trim() || null,
          archivedByUserId === null || archivedByUserId === undefined
            ? null
            : String(archivedByUserId || '').trim() || null
        ]
      );
    } catch (error) {
      if (isMissingTenantMembershipHistoryTableError(error)) {
        tenantMembershipHistoryTableAvailable = false;
        throw createTenantMembershipHistoryUnavailableError();
      }
      throw error;
    }
  };

  const ensureTenantDomainAccessForUserTx = async ({
    txClient,
    userId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { inserted: false };
    }
    const tenantCountRows = await runTenantMembershipQuery({
      txClient,
      sqlWithOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM auth_user_tenants ut
        LEFT JOIN orgs o ON o.id = ut.tenant_id
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
          AND o.status IN ('active', 'enabled')
      `,
      sqlWithoutOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM auth_user_tenants ut
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
      `,
      params: [normalizedUserId]
    });
    const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
    if (tenantCount <= 0) {
      return { inserted: false };
    }

    const result = await txClient.query(
      `
        INSERT INTO auth_user_domain_access (user_id, domain, status)
        VALUES (?, 'tenant', 'active')
        ON DUPLICATE KEY UPDATE
          status = CASE
            WHEN status IN ('active', 'enabled') THEN status
            ELSE 'active'
          END,
          updated_at = CASE
            WHEN status IN ('active', 'enabled') THEN updated_at
            ELSE CURRENT_TIMESTAMP(3)
          END
      `,
      [normalizedUserId]
    );
    return { inserted: Number(result?.affectedRows || 0) > 0 };
  };

  const removeTenantDomainAccessForUserTx = async ({
    txClient,
    userId
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { removed: false };
    }
    const result = await runTenantMembershipQuery({
      txClient,
      sqlWithOrgGuard: `
        DELETE FROM auth_user_domain_access
        WHERE user_id = ?
          AND domain = 'tenant'
          AND NOT EXISTS (
            SELECT 1
            FROM auth_user_tenants ut
            LEFT JOIN orgs o ON o.id = ut.tenant_id
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
              AND o.status IN ('active', 'enabled')
          )
      `,
      sqlWithoutOrgGuard: `
        DELETE FROM auth_user_domain_access
        WHERE user_id = ?
          AND domain = 'tenant'
          AND NOT EXISTS (
            SELECT 1
            FROM auth_user_tenants ut
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
          )
      `,
      params: [normalizedUserId, normalizedUserId]
    });
    return { removed: Number(result?.affectedRows || 0) > 0 };
  };

  const normalizeTenantMembershipRoleIds = (roleIds = []) =>
    [...new Set(
      (Array.isArray(roleIds) ? roleIds : [])
        .map((roleId) => normalizePlatformRoleCatalogRoleId(roleId))
        .filter((roleId) => roleId.length > 0)
    )].sort((left, right) => left.localeCompare(right));

  const revokeTenantSessionsForUserTx = async ({
    txClient,
    userId,
    tenantId,
    reason = 'tenant-membership-permission-changed'
  }) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedUserId || !normalizedTenantId) {
      return;
    }
    await txClient.query(
      `
        UPDATE auth_sessions
        SET status = 'revoked',
            revoked_reason = ?,
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE user_id = ?
          AND entry_domain = 'tenant'
          AND active_tenant_id = ?
          AND status = 'active'
      `,
      [reason, normalizedUserId, normalizedTenantId]
    );
    await txClient.query(
      `
        UPDATE refresh_tokens
        SET status = 'revoked',
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE status = 'active'
          AND session_id IN (
            SELECT session_id
            FROM auth_sessions
            WHERE user_id = ?
              AND entry_domain = 'tenant'
              AND active_tenant_id = ?
          )
      `,
      [normalizedUserId, normalizedTenantId]
    );
  };

  const listTenantMembershipRoleBindingsTx = async ({
    txClient,
    membershipId
  }) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    if (!normalizedMembershipId) {
      return [];
    }
    const roleRows = await txClient.query(
      `
        SELECT role_id
        FROM auth_tenant_membership_roles
        WHERE membership_id = ?
        ORDER BY role_id ASC
        FOR UPDATE
      `,
      [normalizedMembershipId]
    );
    const normalizedRoleIds = [];
    const seenRoleIds = new Set();
    for (const row of Array.isArray(roleRows) ? roleRows : []) {
      const normalizedRoleId = normalizeStrictTenantMembershipRoleIdFromBindingRow(
        row?.role_id,
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

  const loadActiveTenantRoleGrantCodesByRoleIdsTx = async ({
    txClient,
    tenantId,
    roleIds = []
  }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    const normalizedRoleIds = normalizeTenantMembershipRoleIds(roleIds);
    const grantsByRoleId = new Map();
    for (const roleId of normalizedRoleIds) {
      grantsByRoleId.set(roleId, []);
    }
    const seenGrantPermissionCodeKeysByRoleId = new Map(
      normalizedRoleIds.map((roleId) => [roleId, new Set()])
    );
    if (!normalizedTenantId || normalizedRoleIds.length === 0) {
      return grantsByRoleId;
    }
    const rolePlaceholders = buildSqlInPlaceholders(normalizedRoleIds.length);
    const roleRows = await txClient.query(
      `
        SELECT role_id, status, scope, tenant_id
        FROM platform_role_catalog
        WHERE role_id IN (${rolePlaceholders})
        ORDER BY role_id ASC
        FOR UPDATE
      `,
      normalizedRoleIds
    );
    const activeRoleIds = new Set();
    for (const row of Array.isArray(roleRows) ? roleRows : []) {
      const roleId = normalizeStrictRoleIdFromTenantGrantRow(
        row?.role_id,
        'tenant-role-permission-grants-invalid-role-id'
      );
      if (!roleId || !grantsByRoleId.has(roleId)) {
        continue;
      }
      const roleScope = normalizePlatformRoleCatalogScope(row?.scope);
      const roleTenantId = normalizePlatformRoleCatalogTenantId(row?.tenant_id);
      const roleStatus = normalizePlatformRoleCatalogStatus(row?.status || 'disabled');
      if (
        roleScope === 'tenant'
        && roleTenantId === normalizedTenantId
        && isActiveLikeStatus(roleStatus)
      ) {
        activeRoleIds.add(roleId);
      }
    }
    if (activeRoleIds.size === 0) {
      return grantsByRoleId;
    }
    const grantRoleIds = [...activeRoleIds];
    const grantPlaceholders = buildSqlInPlaceholders(grantRoleIds.length);
    const grantRows = await txClient.query(
      `
        SELECT role_id, permission_code
        FROM tenant_role_permission_grants
        WHERE role_id IN (${grantPlaceholders})
        ORDER BY role_id ASC, permission_code ASC
        FOR UPDATE
      `,
      grantRoleIds
    );
    for (const row of Array.isArray(grantRows) ? grantRows : []) {
      const roleId = normalizeStrictRoleIdFromTenantGrantRow(
        row?.role_id,
        'tenant-role-permission-grants-invalid-role-id'
      );
      if (!activeRoleIds.has(roleId)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-unexpected-role-id'
        );
      }
      if (!grantsByRoleId.has(roleId)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-invalid-role-id'
        );
      }
      const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
        row?.permission_code,
        'tenant-role-permission-grants-invalid-permission-code'
      );
      const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
      if (seenPermissionCodeKeys.has(permissionCodeKey)) {
        throw createTenantRolePermissionGrantDataError(
          'tenant-role-permission-grants-duplicate-permission-code'
        );
      }
      seenPermissionCodeKeys.add(permissionCodeKey);
      grantsByRoleId.get(roleId).push(permissionCodeKey);
    }
    for (const roleId of grantsByRoleId.keys()) {
      if (!activeRoleIds.has(roleId)) {
        grantsByRoleId.set(roleId, []);
        continue;
      }
      grantsByRoleId.set(roleId, [...grantsByRoleId.get(roleId)]);
    }
    return grantsByRoleId;
  };

  const resolveTenantPermissionSnapshotForMembershipTx = async ({
    txClient,
    membership = null,
    tenantId,
    roleIds = []
  }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    const membershipStatus = normalizeTenantMembershipStatusForRead(
      membership?.status
    );
    if (!isActiveLikeStatus(membershipStatus)) {
      return toTenantPermissionSnapshotFromGrantCodes([]);
    }
    const normalizedRoleIds = normalizeTenantMembershipRoleIds(roleIds);
    if (normalizedRoleIds.length === 0) {
      return toTenantPermissionSnapshotFromGrantCodes([]);
    }
    const grantsByRoleId = await loadActiveTenantRoleGrantCodesByRoleIdsTx({
      txClient,
      tenantId: normalizedTenantId,
      roleIds: normalizedRoleIds
    });
    const mergedGrantCodes = [];
    for (const roleId of normalizedRoleIds) {
      mergedGrantCodes.push(...(grantsByRoleId.get(roleId) || []));
    }
    return toTenantPermissionSnapshotFromGrantCodes(mergedGrantCodes);
  };

  const syncTenantMembershipPermissionSnapshotInTx = async ({
    txClient,
    membershipId,
    tenantId,
    roleIds = null,
    revokeReason = 'tenant-membership-permission-changed'
  }) => {
    const normalizedMembershipId = String(membershipId || '').trim();
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedMembershipId || !normalizedTenantId) {
      return {
        synced: false,
        reason: 'invalid-membership-reference',
        changed: false,
        permission: null
      };
    }

    const membershipRows = await txClient.query(
      `
        SELECT membership_id,
               user_id,
               tenant_id,
               status,
               can_view_member_admin,
               can_operate_member_admin,
               can_view_billing,
               can_operate_billing
        FROM auth_user_tenants
        WHERE membership_id = ? AND tenant_id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [normalizedMembershipId, normalizedTenantId]
    );
    const membership = membershipRows?.[0] || null;
    if (!membership) {
      return {
        synced: false,
        reason: 'membership-not-found',
        changed: false,
        permission: null
      };
    }

    const previousSnapshot = toPlatformPermissionSnapshotFromRow(
      membership,
      '组织权限（角色并集）'
    );
    const resolvedRoleIds = Array.isArray(roleIds)
      ? normalizeTenantMembershipRoleIds(roleIds)
      : await listTenantMembershipRoleBindingsTx({
        txClient,
        membershipId: normalizedMembershipId
      });
    const nextSnapshot = await resolveTenantPermissionSnapshotForMembershipTx({
      txClient,
      membership,
      tenantId: normalizedTenantId,
      roleIds: resolvedRoleIds
    });
    const changed = !isSameTenantPermissionSnapshot(previousSnapshot, nextSnapshot);
    if (changed) {
      await txClient.query(
        `
          UPDATE auth_user_tenants
          SET can_view_member_admin = ?,
              can_operate_member_admin = ?,
              can_view_billing = ?,
              can_operate_billing = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE membership_id = ? AND tenant_id = ?
        `,
        [
          nextSnapshot.canViewMemberAdmin ? 1 : 0,
          nextSnapshot.canOperateMemberAdmin ? 1 : 0,
          nextSnapshot.canViewBilling ? 1 : 0,
          nextSnapshot.canOperateBilling ? 1 : 0,
          normalizedMembershipId,
          normalizedTenantId
        ]
      );
      await revokeTenantSessionsForUserTx({
        txClient,
        userId: membership.user_id,
        tenantId: normalizedTenantId,
        reason: revokeReason
      });
    }

    return {
      synced: true,
      reason: 'ok',
      changed,
      permission: {
        canViewMemberAdmin: nextSnapshot.canViewMemberAdmin,
        canOperateMemberAdmin: nextSnapshot.canOperateMemberAdmin,
        canViewBilling: nextSnapshot.canViewBilling,
        canOperateBilling: nextSnapshot.canOperateBilling
      },
      membershipId: normalizedMembershipId,
      tenantId: normalizedTenantId,
      userId: String(membership.user_id || '').trim(),
      roleIds: resolvedRoleIds
    };
  };

  const bumpSessionVersionAndConvergeSessionsTx = async ({
    txClient,
    userId,
    passwordHash = null,
    reason = 'critical-state-changed',
    revokeRefreshTokens = true,
    revokeAuthSessions = true
  }) => {
    const normalizedUserId = String(userId);
    const shouldUpdatePassword = passwordHash !== null && passwordHash !== undefined;
    const updateResult = shouldUpdatePassword
      ? await txClient.query(
        `
          UPDATE users
          SET password_hash = ?,
              session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [passwordHash, normalizedUserId]
      )
      : await txClient.query(
        `
          UPDATE users
          SET session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [normalizedUserId]
      );

    if (!updateResult || Number(updateResult.affectedRows || 0) !== 1) {
      return null;
    }

    if (revokeAuthSessions) {
      await txClient.query(
        `
          UPDATE auth_sessions
          SET status = 'revoked',
              revoked_reason = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [reason || 'critical-state-changed', normalizedUserId]
      );
    }

    if (revokeRefreshTokens) {
      await txClient.query(
        `
          UPDATE refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [normalizedUserId]
      );
    }

    const rows = await txClient.query(
      `
        SELECT id, phone, password_hash, status, session_version
        FROM users
        WHERE id = ?
        LIMIT 1
      `,
      [normalizedUserId]
    );
    return toUserRecord(rows[0]);
  };

  const readPlatformRoleFactsSummaryByUserId = async ({ txClient = dbClient, userId }) => {
    const summaryRows = await txClient.query(
      `
        SELECT COUNT(*) AS role_count,
               MAX(updated_at) AS latest_role_updated_at,
               MAX(DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s.%f')) AS latest_role_updated_at_key,
               COALESCE(
                 SUM(
                   CRC32(
                     CONCAT_WS(
                       '#',
                       role_id,
                       status,
                       can_view_member_admin,
                       can_operate_member_admin,
                       can_view_billing,
                       can_operate_billing,
                       DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s.%f')
                     )
                   )
                 ),
                 0
               ) AS role_facts_checksum
        FROM auth_user_platform_roles
        WHERE user_id = ?
      `,
      [userId]
    );
    const summaryRow = summaryRows?.[0] || null;
    const rawLatestRoleUpdatedAt = summaryRow?.latest_role_updated_at;
    let latestRoleUpdatedAtKey = '';
    if (
      typeof summaryRow?.latest_role_updated_at_key === 'string'
      && summaryRow.latest_role_updated_at_key.trim().length > 0
    ) {
      latestRoleUpdatedAtKey = summaryRow.latest_role_updated_at_key.trim();
    } else if (rawLatestRoleUpdatedAt instanceof Date) {
      latestRoleUpdatedAtKey = rawLatestRoleUpdatedAt.toISOString();
    } else if (rawLatestRoleUpdatedAt !== null && rawLatestRoleUpdatedAt !== undefined) {
      latestRoleUpdatedAtKey = String(rawLatestRoleUpdatedAt).trim();
    }
    const rawRoleFactsChecksum = summaryRow?.role_facts_checksum;
    let roleFactsChecksum = null;
    if (rawRoleFactsChecksum !== null && rawRoleFactsChecksum !== undefined) {
      const normalizedChecksum = String(rawRoleFactsChecksum).trim();
      if (normalizedChecksum.length > 0) {
        roleFactsChecksum = normalizedChecksum;
      }
    }
    return {
      roleFactCount: Number(summaryRow?.role_count || 0),
      latestRoleUpdatedAtMs: toEpochMilliseconds(
        summaryRow?.latest_role_updated_at
      ),
      latestRoleUpdatedAtKey,
      roleFactsChecksum
    };
  };

  const didPlatformRoleFactsSummaryChange = async ({
    txClient = dbClient,
    userId,
    expectedRoleFactCount,
    expectedLatestRoleUpdatedAtKey,
    expectedRoleFactsChecksum = null
  }) => {
    const latestSummary = await readPlatformRoleFactsSummaryByUserId({
      txClient,
      userId
    });
    const normalizedExpectedChecksum =
      expectedRoleFactsChecksum === null || expectedRoleFactsChecksum === undefined
        ? null
        : String(expectedRoleFactsChecksum).trim();
    return (
      latestSummary.roleFactCount !== Number(expectedRoleFactCount || 0)
      || latestSummary.latestRoleUpdatedAtKey
      !== String(expectedLatestRoleUpdatedAtKey || '')
      || (
        normalizedExpectedChecksum !== null
        && latestSummary.roleFactsChecksum !== normalizedExpectedChecksum
      )
    );
  };

  const syncPlatformPermissionSnapshotByUserIdOnce = async ({
    userId,
    forceWhenNoRoleFacts = false,
    txClient = dbClient
  }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const snapshotRows = await txClient.query(
      `
        SELECT can_view_member_admin,
               can_operate_member_admin,
               can_view_billing,
               can_operate_billing,
               updated_at
        FROM auth_user_domain_access
        WHERE user_id = ? AND domain = 'platform' AND status IN ('active', 'enabled')
        LIMIT 1
      `,
      [normalizedUserId]
    );
    const snapshotRow = snapshotRows?.[0] || null;
    const snapshotPermission = toPlatformPermissionSnapshotFromRow(snapshotRow);
    const snapshotUpdatedAtMs = toEpochMilliseconds(snapshotRow?.updated_at);

    let roleFactsSummary = null;
    try {
      roleFactsSummary = await readPlatformRoleFactsSummaryByUserId({
        txClient,
        userId: normalizedUserId
      });
    } catch (error) {
      if (isTableMissingError(error)) {
        return {
          synced: false,
          reason: 'role-facts-table-missing',
          permission: null
        };
      }
      throw error;
    }

    const roleFactCount = Number(roleFactsSummary?.roleFactCount || 0);
    const latestRoleUpdatedAtMs = Number(
      roleFactsSummary?.latestRoleUpdatedAtMs || 0
    );
    const latestRoleUpdatedAtKey = String(
      roleFactsSummary?.latestRoleUpdatedAtKey || ''
    );
    const roleFactsChecksum =
      roleFactsSummary?.roleFactsChecksum === null
      || roleFactsSummary?.roleFactsChecksum === undefined
        ? null
        : String(roleFactsSummary.roleFactsChecksum).trim();
    if (roleFactCount <= 0) {
      if (!forceWhenNoRoleFacts) {
        return {
          synced: false,
          reason: 'no-role-facts',
          permission: null
        };
      }

      const emptyPermission = toPlatformPermissionSnapshot();
      if (!snapshotRow || isEmptyPlatformPermissionSnapshot(snapshotPermission)) {
        return {
          synced: false,
          reason: 'already-empty',
          permission: emptyPermission
        };
      }

      const zeroUpdateResult = await txClient.query(
        `
          UPDATE auth_user_domain_access
          SET can_view_member_admin = 0,
              can_operate_member_admin = 0,
              can_view_billing = 0,
              can_operate_billing = 0,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND domain = 'platform' AND status IN ('active', 'enabled')
            AND (
              can_view_member_admin <> 0
              OR can_operate_member_admin <> 0
              OR can_view_billing <> 0
              OR can_operate_billing <> 0
            )
            AND (
              SELECT COUNT(*)
              FROM auth_user_platform_roles
              WHERE user_id = ?
            ) = 0
        `,
        [normalizedUserId, normalizedUserId]
      );

      const zeroed = Number(zeroUpdateResult?.affectedRows || 0) > 0;
      if (!zeroed) {
        const roleFactsChanged = await didPlatformRoleFactsSummaryChange({
          txClient,
          userId: normalizedUserId,
          expectedRoleFactCount: 0,
          expectedLatestRoleUpdatedAtKey: '',
          expectedRoleFactsChecksum: roleFactsChecksum
        });
        if (roleFactsChanged) {
          return {
            synced: false,
            reason: 'concurrent-role-facts-update',
            permission: null
          };
        }
      }

      return {
        synced: zeroed,
        reason: 'ok',
        permission: emptyPermission
      };
    }

    if (
      snapshotRow
      && latestRoleUpdatedAtMs > 0
      && snapshotUpdatedAtMs > latestRoleUpdatedAtMs
    ) {
      return {
        synced: false,
        reason: 'up-to-date',
        permission: snapshotPermission
      };
    }

    const roleRows = await txClient.query(
      `
        SELECT role_id,
               status,
               can_view_member_admin,
               can_operate_member_admin,
               can_view_billing,
               can_operate_billing
        FROM auth_user_platform_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );

    const aggregate = aggregatePlatformPermissionFromRoleRows(roleRows);
    if (!aggregate.hasRoleFacts && !forceWhenNoRoleFacts) {
      return {
        synced: false,
        reason: 'no-role-facts',
        permission: null
      };
    }

    const permission = aggregate.permission;
    const canViewMemberAdmin = Number(permission.canViewMemberAdmin);
    const canOperateMemberAdmin = Number(permission.canOperateMemberAdmin);
    const canViewBilling = Number(permission.canViewBilling);
    const canOperateBilling = Number(permission.canOperateBilling);
    const updateResult = await txClient.query(
      `
        UPDATE auth_user_domain_access
        SET can_view_member_admin = ?,
            can_operate_member_admin = ?,
            can_view_billing = ?,
            can_operate_billing = ?,
            updated_at = CURRENT_TIMESTAMP(3)
        WHERE user_id = ? AND domain = 'platform' AND status IN ('active', 'enabled')
          AND (
            can_view_member_admin <> ?
            OR can_operate_member_admin <> ?
            OR can_view_billing <> ?
            OR can_operate_billing <> ?
          )
          AND (
            SELECT COUNT(*)
            FROM auth_user_platform_roles
            WHERE user_id = ?
          ) = ?
          AND COALESCE(
            (
              SELECT MAX(DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s.%f'))
              FROM auth_user_platform_roles
              WHERE user_id = ?
            ),
            ''
          ) = ?
          AND (
            ? IS NULL
            OR (
              SELECT COALESCE(
                SUM(
                  CRC32(
                    CONCAT_WS(
                      '#',
                      role_id,
                      status,
                      can_view_member_admin,
                      can_operate_member_admin,
                      can_view_billing,
                      can_operate_billing,
                      DATE_FORMAT(updated_at, '%Y-%m-%d %H:%i:%s.%f')
                    )
                  )
                ),
                0
              )
              FROM auth_user_platform_roles
              WHERE user_id = ?
            ) = ?
          )
      `,
      [
        canViewMemberAdmin,
        canOperateMemberAdmin,
        canViewBilling,
        canOperateBilling,
        normalizedUserId,
        canViewMemberAdmin,
        canOperateMemberAdmin,
        canViewBilling,
        canOperateBilling,
        normalizedUserId,
        roleFactCount,
        normalizedUserId,
        latestRoleUpdatedAtKey,
        roleFactsChecksum,
        normalizedUserId,
        roleFactsChecksum
      ]
    );

    const synced = Number(updateResult?.affectedRows || 0) > 0;
    if (!synced) {
      const roleFactsChanged = await didPlatformRoleFactsSummaryChange({
        txClient,
        userId: normalizedUserId,
        expectedRoleFactCount: roleFactCount,
        expectedLatestRoleUpdatedAtKey: latestRoleUpdatedAtKey,
        expectedRoleFactsChecksum: roleFactsChecksum
      });
      if (roleFactsChanged) {
        return {
          synced: false,
          reason: 'concurrent-role-facts-update',
          permission: null
        };
      }
    }

    return {
      synced,
      reason: 'ok',
      permission
    };
  };

  const syncPlatformPermissionSnapshotByUserId = async ({
    userId,
    forceWhenNoRoleFacts = false,
    txClient = dbClient
  }) =>
    executeWithDeadlockRetry({
      operation: 'syncPlatformPermissionSnapshotByUserId',
      execute: () =>
        syncPlatformPermissionSnapshotByUserIdOnce({
          userId,
          forceWhenNoRoleFacts,
          txClient
        })
    });

  const replacePlatformRolesAndSyncSnapshotInTx = async ({
    txClient,
    userId,
    roles = []
  }) => {
    const transactionalClient = txClient || dbClient;
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const normalizedRoles = dedupePlatformRoleFacts(roles);

    const userRows = await transactionalClient.query(
      `
        SELECT id
        FROM users
        WHERE id = ?
        LIMIT 1
        FOR UPDATE
      `,
      [normalizedUserId]
    );
    if (!userRows?.[0]) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const previousRoleRows = await transactionalClient.query(
      `
        SELECT status,
               can_view_member_admin,
               can_operate_member_admin,
               can_view_billing,
               can_operate_billing
        FROM auth_user_platform_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );
    const previousPermission = aggregatePlatformPermissionFromRoleRows(previousRoleRows).permission;

    await transactionalClient.query(
      `
        DELETE FROM auth_user_platform_roles
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );

    for (const role of normalizedRoles) {
      await transactionalClient.query(
        `
          INSERT INTO auth_user_platform_roles (
            user_id,
            role_id,
            status,
            can_view_member_admin,
            can_operate_member_admin,
            can_view_billing,
            can_operate_billing
          )
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `,
        [
          normalizedUserId,
          role.roleId,
          role.status,
          Number(role.canViewMemberAdmin),
          Number(role.canOperateMemberAdmin),
          Number(role.canViewBilling),
          Number(role.canOperateBilling)
        ]
      );
    }

    const permission = aggregatePlatformPermissionFromRoleRows(normalizedRoles).permission;
    const canViewMemberAdmin = Number(permission.canViewMemberAdmin);
    const canOperateMemberAdmin = Number(permission.canOperateMemberAdmin);
    const canViewBilling = Number(permission.canViewBilling);
    const canOperateBilling = Number(permission.canOperateBilling);

    if (normalizedRoles.length > 0) {
      await transactionalClient.query(
        `
          INSERT INTO auth_user_domain_access (
            user_id,
            domain,
            status,
            can_view_member_admin,
            can_operate_member_admin,
            can_view_billing,
            can_operate_billing
          )
          VALUES (?, 'platform', 'active', ?, ?, ?, ?)
          ON DUPLICATE KEY UPDATE
            can_view_member_admin = VALUES(can_view_member_admin),
            can_operate_member_admin = VALUES(can_operate_member_admin),
            can_view_billing = VALUES(can_view_billing),
            can_operate_billing = VALUES(can_operate_billing),
            updated_at = CURRENT_TIMESTAMP(3)
        `,
        [
          normalizedUserId,
          canViewMemberAdmin,
          canOperateMemberAdmin,
          canViewBilling,
          canOperateBilling
        ]
      );
    } else {
      await transactionalClient.query(
        `
          UPDATE auth_user_domain_access
          SET can_view_member_admin = ?,
              can_operate_member_admin = ?,
              can_view_billing = ?,
              can_operate_billing = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND domain = 'platform' AND status IN ('active', 'enabled')
            AND (
              can_view_member_admin <> ?
              OR can_operate_member_admin <> ?
              OR can_view_billing <> ?
              OR can_operate_billing <> ?
            )
        `,
        [
          canViewMemberAdmin,
          canOperateMemberAdmin,
          canViewBilling,
          canOperateBilling,
          normalizedUserId,
          canViewMemberAdmin,
          canOperateMemberAdmin,
          canViewBilling,
          canOperateBilling
        ]
      );
    }

    if (!isSamePlatformPermissionSnapshot(previousPermission, permission)) {
      await bumpSessionVersionAndConvergeSessionsTx({
        txClient: transactionalClient,
        userId: normalizedUserId,
        reason: 'platform-role-facts-changed',
        revokeRefreshTokens: true,
        revokeAuthSessions: true
      });
    }

    return {
      synced: true,
      reason: 'ok',
      permission
    };
  };

  const replacePlatformRolesAndSyncSnapshotOnce = async ({ userId, roles = [] }) =>
    dbClient.inTransaction(async (tx) =>
      replacePlatformRolesAndSyncSnapshotInTx({
        txClient: tx,
        userId,
        roles
      }));

  const replacePlatformRolesAndSyncSnapshot = async ({ userId, roles = [] }) =>
    executeWithDeadlockRetry({
      operation: 'replacePlatformRolesAndSyncSnapshot',
      execute: () =>
        replacePlatformRolesAndSyncSnapshotOnce({
          userId,
          roles
        })
    });

  return {
    findUserByPhone: async (phone) => {
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM users
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
          FROM users
          WHERE id = ?
          LIMIT 1
        `,
        [userId]
      );
      return toUserRecord(rows[0]);
    },

    countPlatformRoleCatalogEntries: async () => {
      const rows = await dbClient.query(
        `
          SELECT COUNT(*) AS role_count
          FROM platform_role_catalog
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
          FROM platform_role_catalog
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
          FROM platform_role_catalog
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
          FROM platform_role_catalog
          WHERE role_id IN (${placeholders})
          ORDER BY created_at ASC, role_id ASC
        `,
        normalizedRoleIds
      );
      return (Array.isArray(rows) ? rows : [])
        .map((row) => toPlatformRoleCatalogRecord(row))
        .filter(Boolean);
    },

    listPlatformRolePermissionGrants: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT permission_code
          FROM platform_role_permission_grants
          WHERE role_id = ?
          ORDER BY permission_code ASC
        `,
        [normalizedRoleId]
      );
      return [...new Set(
        (Array.isArray(rows) ? rows : [])
          .map((row) => normalizePlatformPermissionCode(row?.permission_code))
          .filter((permissionCode) => permissionCode.length > 0)
      )];
    },

    listPlatformRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
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
          SELECT role_id, permission_code
          FROM platform_role_permission_grants
          WHERE role_id IN (${placeholders})
          ORDER BY role_id ASC, permission_code ASC
        `,
        normalizedRoleIds
      );
      const grantsByRoleId = new Map();
      for (const roleId of normalizedRoleIds) {
        grantsByRoleId.set(roleId, []);
      }
      for (const row of Array.isArray(rows) ? rows : []) {
        const roleId = normalizePlatformRoleCatalogRoleId(row?.role_id);
        const permissionCode = normalizePlatformPermissionCode(row?.permission_code);
        if (!roleId || !permissionCode || !grantsByRoleId.has(roleId)) {
          continue;
        }
        grantsByRoleId.get(roleId).push(permissionCode);
      }
      return [...grantsByRoleId.entries()].map(([roleId, permissionCodes]) => ({
        roleId,
        permissionCodes: [...new Set(permissionCodes)]
      }));
    },

    replacePlatformRolePermissionGrants: async ({
      roleId,
      permissionCodes = [],
      operatorUserId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('replacePlatformRolePermissionGrants requires roleId');
      }
      const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes);
      return executeWithDeadlockRetry({
        operation: 'replacePlatformRolePermissionGrants',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_role_catalog
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            await tx.query(
              `
                DELETE FROM platform_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO platform_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const grantRows = await tx.query(
              `
                SELECT permission_code
                FROM platform_role_permission_grants
                WHERE role_id = ?
                ORDER BY permission_code ASC
              `,
              [normalizedRoleId]
            );
            return [...new Set(
              (Array.isArray(grantRows) ? grantRows : [])
                .map((row) => normalizePlatformPermissionCode(row?.permission_code))
                .filter((permissionCode) => permissionCode.length > 0)
            )];
          })
      });
    },

    replacePlatformRolePermissionGrantsAndSyncSnapshots: async ({
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      maxAffectedUsers = DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('replacePlatformRolePermissionGrantsAndSyncSnapshots requires roleId');
      }
      const normalizedPermissionCodes = normalizePlatformPermissionCodes(permissionCodes);
      const normalizedMaxAffectedUsers = Math.max(
        1,
        Math.floor(Number(maxAffectedUsers || DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS))
      );
      return executeWithDeadlockRetry({
        operation: 'replacePlatformRolePermissionGrantsAndSyncSnapshots',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_role_catalog
                WHERE role_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            const affectedUserRows = await tx.query(
              `
                SELECT user_id
                FROM auth_user_platform_roles
                WHERE role_id = ?
                ORDER BY user_id ASC
                FOR UPDATE
              `,
              [normalizedRoleId]
            );
            const affectedUserIds = [
              ...new Set(
                (Array.isArray(affectedUserRows) ? affectedUserRows : [])
                  .map((row) => String(row?.user_id || '').trim())
                  .filter((userId) => userId.length > 0)
              )
            ];
            if (affectedUserIds.length > normalizedMaxAffectedUsers) {
              const limitError = new Error('platform role permission affected users exceed limit');
              limitError.code = 'ERR_PLATFORM_ROLE_PERMISSION_AFFECTED_USERS_OVER_LIMIT';
              limitError.maxAffectedUsers = normalizedMaxAffectedUsers;
              limitError.affectedUsers = affectedUserIds.length;
              throw limitError;
            }

            await tx.query(
              `
                DELETE FROM platform_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO platform_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const grantCodesByRoleId = new Map();
            grantCodesByRoleId.set(normalizedRoleId, [...normalizedPermissionCodes]);

            for (const affectedUserId of affectedUserIds) {
              const roleRowsForUser = await tx.query(
                `
                  SELECT role_id, status
                  FROM auth_user_platform_roles
                  WHERE user_id = ?
                  ORDER BY role_id ASC
                  FOR UPDATE
                `,
                [affectedUserId]
              );

              const normalizedRoleIdsForUser = [
                ...new Set(
                  (Array.isArray(roleRowsForUser) ? roleRowsForUser : [])
                    .map((row) => normalizePlatformRoleCatalogRoleId(row?.role_id))
                    .filter((candidateRoleId) => candidateRoleId.length > 0)
                )
              ];
              const missingGrantRoleIds = normalizedRoleIdsForUser.filter(
                (candidateRoleId) => !grantCodesByRoleId.has(candidateRoleId)
              );
              if (missingGrantRoleIds.length > 0) {
                const placeholders = buildSqlInPlaceholders(missingGrantRoleIds.length);
                const grantRows = await tx.query(
                  `
                    SELECT role_id, permission_code
                    FROM platform_role_permission_grants
                    WHERE role_id IN (${placeholders})
                    ORDER BY role_id ASC, permission_code ASC
                  `,
                  missingGrantRoleIds
                );
                for (const roleIdKey of missingGrantRoleIds) {
                  grantCodesByRoleId.set(roleIdKey, []);
                }
                for (const row of Array.isArray(grantRows) ? grantRows : []) {
                  const roleIdKey = normalizePlatformRoleCatalogRoleId(row?.role_id);
                  const permissionCode = normalizePlatformPermissionCode(row?.permission_code);
                  if (!roleIdKey || !permissionCode || !grantCodesByRoleId.has(roleIdKey)) {
                    continue;
                  }
                  grantCodesByRoleId.get(roleIdKey).push(permissionCode);
                }
                for (const roleIdKey of missingGrantRoleIds) {
                  const dedupedCodes = [
                    ...new Set(normalizePlatformPermissionCodes(grantCodesByRoleId.get(roleIdKey)))
                  ];
                  grantCodesByRoleId.set(roleIdKey, dedupedCodes);
                }
              }

              const nextRoles = (Array.isArray(roleRowsForUser) ? roleRowsForUser : [])
                .map((row) => {
                  const normalizedRoleIdForUser = normalizePlatformRoleCatalogRoleId(row?.role_id);
                  if (!normalizedRoleIdForUser) {
                    return null;
                  }
                  const permissionSnapshot = toPlatformPermissionSnapshotFromGrantCodes(
                    grantCodesByRoleId.get(normalizedRoleIdForUser) || []
                  );
                  return {
                    roleId: normalizedRoleIdForUser,
                    status: normalizePlatformRoleStatus(row?.status),
                    canViewMemberAdmin: permissionSnapshot.canViewMemberAdmin,
                    canOperateMemberAdmin: permissionSnapshot.canOperateMemberAdmin,
                    canViewBilling: permissionSnapshot.canViewBilling,
                    canOperateBilling: permissionSnapshot.canOperateBilling
                  };
                })
                .filter(Boolean);

              const syncResult = await replacePlatformRolesAndSyncSnapshotInTx({
                txClient: tx,
                userId: affectedUserId,
                roles: nextRoles
              });
              const syncReason = String(syncResult?.reason || 'unknown')
                .trim()
                .toLowerCase();
              if (syncReason !== 'ok') {
                const syncError = new Error(
                  `platform role permission sync failed: ${syncReason || 'unknown'}`
                );
                syncError.code = 'ERR_PLATFORM_ROLE_PERMISSION_SYNC_FAILED';
                syncError.syncReason = syncReason || 'unknown';
                throw syncError;
              }
            }

            return {
              roleId: normalizedRoleId,
              permissionCodes: [...normalizedPermissionCodes],
              affectedUserIds: [...affectedUserIds],
              affectedUserCount: affectedUserIds.length
            };
          })
      });
    },

    listTenantRolePermissionGrants: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT permission_code
          FROM tenant_role_permission_grants
          WHERE role_id = ?
          ORDER BY permission_code ASC
        `,
        [normalizedRoleId]
      );
      const normalizedPermissionCodeKeys = [];
      const seenPermissionCodeKeys = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
          row?.permission_code,
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
      return normalizedPermissionCodeKeys;
    },

    listTenantRolePermissionGrantsByRoleIds: async ({ roleIds = [] } = {}) => {
      const normalizedRoleIds = normalizeTenantMembershipRoleIds(roleIds);
      if (normalizedRoleIds.length === 0) {
        return [];
      }
      const placeholders = buildSqlInPlaceholders(normalizedRoleIds.length);
      const rows = await dbClient.query(
        `
          SELECT role_id, permission_code
          FROM tenant_role_permission_grants
          WHERE role_id IN (${placeholders})
          ORDER BY role_id ASC, permission_code ASC
        `,
        normalizedRoleIds
      );
      const grantsByRoleId = new Map();
      for (const roleId of normalizedRoleIds) {
        grantsByRoleId.set(roleId, []);
      }
      const seenGrantPermissionCodeKeysByRoleId = new Map(
        normalizedRoleIds.map((roleId) => [roleId, new Set()])
      );
      for (const row of Array.isArray(rows) ? rows : []) {
        const roleId = normalizeStrictRoleIdFromTenantGrantRow(
          row?.role_id,
          'tenant-role-permission-grants-invalid-role-id'
        );
        if (!roleId || !grantsByRoleId.has(roleId)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-invalid-role-id'
          );
        }
        const permissionCodeKey = normalizeStrictTenantPermissionCodeFromGrantRow(
          row?.permission_code,
          'tenant-role-permission-grants-invalid-permission-code'
        );
        const seenPermissionCodeKeys = seenGrantPermissionCodeKeysByRoleId.get(roleId);
        if (seenPermissionCodeKeys.has(permissionCodeKey)) {
          throw createTenantRolePermissionGrantDataError(
            'tenant-role-permission-grants-duplicate-permission-code'
          );
        }
        seenPermissionCodeKeys.add(permissionCodeKey);
        grantsByRoleId.get(roleId).push(permissionCodeKey);
      }
      return [...grantsByRoleId.entries()].map(([roleId, permissionCodes]) => ({
        roleId,
        permissionCodes: [...permissionCodes]
      }));
    },

    replaceTenantRolePermissionGrantsAndSyncSnapshots: async ({
      tenantId,
      roleId,
      permissionCodes = [],
      operatorUserId = null,
      maxAffectedMemberships = DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
    }) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedTenantId || !normalizedRoleId) {
        throw new Error('replaceTenantRolePermissionGrantsAndSyncSnapshots requires tenantId and roleId');
      }
      const normalizedPermissionCodes = normalizeTenantPermissionCodes(permissionCodes)
        .sort((left, right) => left.localeCompare(right));
      const normalizedMaxAffectedMemberships = Math.max(
        1,
        Math.floor(
          Number(
            maxAffectedMemberships || DEFAULT_MAX_ATOMIC_ROLE_PERMISSION_AFFECTED_USERS
          )
        )
      );
      return executeWithDeadlockRetry({
        operation: 'replaceTenantRolePermissionGrantsAndSyncSnapshots',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const roleRows = await tx.query(
              `
                SELECT role_id
                FROM platform_role_catalog
                WHERE role_id = ?
                  AND scope = 'tenant'
                  AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedRoleId, normalizedTenantId]
            );
            if (!roleRows?.[0]) {
              return null;
            }

            const membershipRows = await tx.query(
              `
                SELECT ut.membership_id, ut.user_id
                FROM auth_tenant_membership_roles mr
                JOIN auth_user_tenants ut ON ut.membership_id = mr.membership_id
                WHERE mr.role_id = ?
                  AND ut.tenant_id = ?
                  AND ut.status IN ('active', 'enabled')
                ORDER BY ut.membership_id ASC
                FOR UPDATE
              `,
              [normalizedRoleId, normalizedTenantId]
            );
            const affectedMembershipIds = [];
            const affectedUserIds = new Set();
            for (const row of Array.isArray(membershipRows) ? membershipRows : []) {
              const membershipId =
                normalizeStrictTenantRolePermissionGrantIdentity(
                  row?.membership_id,
                  'tenant-role-permission-grants-invalid-membership-id'
                );
              if (affectedMembershipIds.includes(membershipId)) {
                continue;
              }
              affectedMembershipIds.push(membershipId);
              const userId = normalizeStrictTenantRolePermissionGrantIdentity(
                row?.user_id,
                'tenant-role-permission-grants-invalid-affected-user-id'
              );
              affectedUserIds.add(userId);
            }
            if (affectedMembershipIds.length > normalizedMaxAffectedMemberships) {
              const limitError = new Error(
                'tenant role permission affected memberships exceed limit'
              );
              limitError.code = 'ERR_TENANT_ROLE_PERMISSION_AFFECTED_MEMBERSHIPS_OVER_LIMIT';
              limitError.maxAffectedMemberships = normalizedMaxAffectedMemberships;
              limitError.affectedMemberships = affectedMembershipIds.length;
              throw limitError;
            }

            await tx.query(
              `
                DELETE FROM tenant_role_permission_grants
                WHERE role_id = ?
              `,
              [normalizedRoleId]
            );

            for (const permissionCode of normalizedPermissionCodes) {
              await tx.query(
                `
                  INSERT INTO tenant_role_permission_grants (
                    role_id,
                    permission_code,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedRoleId,
                  permissionCode,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            for (const membershipId of affectedMembershipIds) {
              const syncResult = await syncTenantMembershipPermissionSnapshotInTx({
                txClient: tx,
                membershipId,
                tenantId: normalizedTenantId,
                revokeReason: 'tenant-role-permission-grants-changed'
              });
              const syncReason = String(syncResult?.reason || 'unknown')
                .trim()
                .toLowerCase();
              if (syncReason !== 'ok') {
                const syncError = new Error(
                  `tenant role permission sync failed: ${syncReason || 'unknown'}`
                );
                syncError.code = 'ERR_TENANT_ROLE_PERMISSION_SYNC_FAILED';
                syncError.syncReason = syncReason || 'unknown';
                throw syncError;
              }
            }

            return {
              roleId: normalizedRoleId,
              permissionCodes: [...normalizedPermissionCodes],
              affectedUserIds: [...affectedUserIds],
              affectedUserCount: affectedUserIds.size
            };
          })
      });
    },

    listUserIdsByPlatformRoleId: async ({ roleId }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT user_id
          FROM auth_user_platform_roles
          WHERE role_id = ?
          ORDER BY user_id ASC
        `,
        [normalizedRoleId]
      );
      return (Array.isArray(rows) ? rows : [])
        .map((row) => String(row?.user_id || '').trim())
        .filter((userId) => userId.length > 0);
    },

    listPlatformRoleFactsByUserId: async ({ userId }) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT role_id,
                 status,
                 can_view_member_admin,
                 can_operate_member_admin,
                 can_view_billing,
                 can_operate_billing
          FROM auth_user_platform_roles
          WHERE user_id = ?
          ORDER BY role_id ASC
        `,
        [normalizedUserId]
      );
      return (Array.isArray(rows) ? rows : []).map((row) => ({
        roleId: String(row?.role_id || '').trim(),
        role_id: String(row?.role_id || '').trim(),
        status: String(row?.status || 'active').trim().toLowerCase() || 'active',
        permission: {
          canViewMemberAdmin: toBoolean(row?.can_view_member_admin),
          canOperateMemberAdmin: toBoolean(row?.can_operate_member_admin),
          canViewBilling: toBoolean(row?.can_view_billing),
          canOperateBilling: toBoolean(row?.can_operate_billing)
        }
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
      operatorUserId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      const normalizedCode = String(code || '').trim();
      const normalizedName = String(name || '').trim();
      const normalizedStatus = normalizePlatformRoleCatalogStatus(status);
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      if (
        !normalizedRoleId
        || !normalizedCode
        || !normalizedName
        || !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(normalizedStatus)
        || !VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)
      ) {
        throw new Error('createPlatformRoleCatalogEntry received invalid input');
      }

      return executeWithDeadlockRetry({
        operation: 'createPlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: async () => {
          await dbClient.query(
            `
              INSERT INTO platform_role_catalog (
                role_id,
                tenant_id,
                code,
                code_normalized,
                name,
                status,
                scope,
                is_system,
                created_by_user_id,
                updated_by_user_id
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
              normalizedRoleId,
              normalizedTenantId,
              normalizedCode,
              normalizedCode.toLowerCase(),
              normalizedName,
              normalizedStatus,
              normalizedScope,
              Number(Boolean(isSystem)),
              operatorUserId ? String(operatorUserId) : null,
              operatorUserId ? String(operatorUserId) : null
            ]
          );
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
              FROM platform_role_catalog
              WHERE role_id = ?
              LIMIT 1
            `,
            [normalizedRoleId]
          );
          return toPlatformRoleCatalogRecord(rows?.[0] || null);
        }
      });
    },

    updatePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      code = undefined,
      name = undefined,
      status = undefined,
      operatorUserId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('updatePlatformRoleCatalogEntry requires roleId');
      }
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('updatePlatformRoleCatalogEntry received unsupported scope');
      }
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      const whereClause = normalizedScope === 'tenant'
        ? 'role_id = ? AND scope = ? AND tenant_id = ?'
        : "role_id = ? AND scope = ? AND tenant_id = ''";
      const lookupArgs = normalizedScope === 'tenant'
        ? [normalizedRoleId, normalizedScope, normalizedTenantId]
        : [normalizedRoleId, normalizedScope];

      return executeWithDeadlockRetry({
        operation: 'updatePlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
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
                FROM platform_role_catalog
                WHERE ${whereClause}
                LIMIT 1
                FOR UPDATE
              `,
              lookupArgs
            );
            const existing = toPlatformRoleCatalogRecord(rows?.[0] || null);
            if (!existing) {
              return null;
            }

            const nextCode = code === undefined
              ? existing.code
              : String(code || '').trim();
            const nextName = name === undefined
              ? existing.name
              : String(name || '').trim();
            const nextStatus = status === undefined
              ? existing.status
              : normalizePlatformRoleCatalogStatus(status);
            if (
              !nextCode
              || !nextName
              || !VALID_PLATFORM_ROLE_CATALOG_STATUS.has(nextStatus)
            ) {
              throw new Error('updatePlatformRoleCatalogEntry received invalid update payload');
            }

            await tx.query(
              `
                UPDATE platform_role_catalog
                SET code = ?,
                    code_normalized = ?,
                    name = ?,
                    status = ?,
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE role_id = ?
              `,
              [
                nextCode,
                nextCode.toLowerCase(),
                nextName,
                nextStatus,
                operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
                existing.roleId
              ]
            );

            const updatedRows = await tx.query(
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
                FROM platform_role_catalog
                WHERE role_id = ?
                LIMIT 1
              `,
              [existing.roleId]
            );
            return toPlatformRoleCatalogRecord(updatedRows?.[0] || null);
          })
      });
    },

    deletePlatformRoleCatalogEntry: async ({
      roleId,
      scope = 'platform',
      tenantId = null,
      operatorUserId = null
    }) => {
      const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
      if (!normalizedRoleId) {
        throw new Error('deletePlatformRoleCatalogEntry requires roleId');
      }
      const normalizedScope = normalizePlatformRoleCatalogScope(scope);
      if (!VALID_PLATFORM_ROLE_CATALOG_SCOPE.has(normalizedScope)) {
        throw new Error('deletePlatformRoleCatalogEntry received unsupported scope');
      }
      const normalizedTenantId = normalizePlatformRoleCatalogTenantIdForScope({
        scope: normalizedScope,
        tenantId
      });
      const whereClause = normalizedScope === 'tenant'
        ? 'role_id = ? AND scope = ? AND tenant_id = ?'
        : "role_id = ? AND scope = ? AND tenant_id = ''";
      const lookupArgs = normalizedScope === 'tenant'
        ? [normalizedRoleId, normalizedScope, normalizedTenantId]
        : [normalizedRoleId, normalizedScope];

      return executeWithDeadlockRetry({
        operation: 'deletePlatformRoleCatalogEntry',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
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
                FROM platform_role_catalog
                WHERE ${whereClause}
                LIMIT 1
                FOR UPDATE
              `,
              lookupArgs
            );
            const existing = toPlatformRoleCatalogRecord(rows?.[0] || null);
            if (!existing) {
              return null;
            }

            await tx.query(
              `
                UPDATE platform_role_catalog
                SET status = 'disabled',
                    updated_by_user_id = ?,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE role_id = ?
              `,
              [
                operatorUserId ? String(operatorUserId) : existing.updatedByUserId,
                existing.roleId
              ]
            );

            const updatedRows = await tx.query(
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
                FROM platform_role_catalog
                WHERE role_id = ?
                LIMIT 1
              `,
              [existing.roleId]
            );
            return toPlatformRoleCatalogRecord(updatedRows?.[0] || null);
          })
      });
    },

    createUserByPhone: async ({ phone, passwordHash, status = 'active' }) => {
      const normalizedPhone = String(phone || '').trim();
      const normalizedPasswordHash = String(passwordHash || '').trim();
      if (!normalizedPhone || !normalizedPasswordHash) {
        throw new Error('createUserByPhone requires phone and passwordHash');
      }
      const normalizedStatus = String(status || 'active').trim().toLowerCase() || 'active';
      const userId = randomUUID();
      try {
        await dbClient.query(
          `
            INSERT INTO users (id, phone, password_hash, status, session_version)
            VALUES (?, ?, ?, ?, 1)
          `,
          [userId, normalizedPhone, normalizedPasswordHash, normalizedStatus]
        );
      } catch (error) {
        if (isDuplicateEntryError(error)) {
          return null;
        }
        throw error;
      }
      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM users
          WHERE id = ?
          LIMIT 1
        `,
        [userId]
      );
      return toUserRecord(rows[0]);
    },

    createOrganizationWithOwner: async ({
      orgId = randomUUID(),
      orgName,
      ownerUserId,
      operatorUserId
    }) =>
      executeWithDeadlockRetry({
        operation: 'createOrganizationWithOwner',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedOrgId = String(orgId || '').trim() || randomUUID();
            const normalizedOrgName = normalizeOrgName(orgName);
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

            const insertOrgResult = await tx.query(
              `
                INSERT INTO orgs (id, name, owner_user_id, status, created_by_user_id)
                VALUES (?, ?, ?, 'active', ?)
              `,
              [
                normalizedOrgId,
                normalizedOrgName,
                normalizedOwnerUserId,
                normalizedOperatorUserId
              ]
            );
            if (Number(insertOrgResult?.affectedRows || 0) !== 1) {
              throw new Error('org-create-write-not-applied');
            }

            const insertMembershipResult = await tx.query(
              `
                INSERT INTO memberships (org_id, user_id, membership_role, status)
                VALUES (?, ?, 'owner', 'active')
              `,
              [normalizedOrgId, normalizedOwnerUserId]
            );
            if (Number(insertMembershipResult?.affectedRows || 0) !== 1) {
              throw new Error('org-membership-write-not-applied');
            }

            return {
              org_id: normalizedOrgId,
              owner_user_id: normalizedOwnerUserId
            };
          })
      }),

    findOrganizationById: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT id, name, owner_user_id, status, created_by_user_id
          FROM orgs
          WHERE BINARY id = ?
          LIMIT 1
        `,
        [normalizedOrgId]
      );
      const org = rows?.[0] || null;
      if (!org) {
        return null;
      }
      return {
        org_id: String(org.id || '').trim(),
        org_name: String(org.name || '').trim(),
        owner_user_id: String(org.owner_user_id || '').trim(),
        status: normalizeOrgStatus(org.status),
        created_by_user_id: org.created_by_user_id
          ? String(org.created_by_user_id).trim()
          : null
      };
    },

    acquireOwnerTransferLock: async ({
      orgId,
      timeoutSeconds = 0
    }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      const lockName = toOwnerTransferLockName(normalizedOrgId);
      if (!lockName) {
        return false;
      }
      const rows = await dbClient.query(
        `
          SELECT GET_LOCK(?, ?) AS lock_acquired
        `,
        [
          lockName,
          normalizeOwnerTransferLockTimeoutSeconds(timeoutSeconds)
        ]
      );
      return Number(rows?.[0]?.lock_acquired || 0) === 1;
    },

    releaseOwnerTransferLock: async ({ orgId }) => {
      const normalizedOrgId = String(orgId || '').trim();
      if (!normalizedOrgId) {
        return false;
      }
      const lockName = toOwnerTransferLockName(normalizedOrgId);
      if (!lockName) {
        return false;
      }
      const rows = await dbClient.query(
        `
          SELECT RELEASE_LOCK(?) AS lock_released
        `,
        [lockName]
      );
      return Number(rows?.[0]?.lock_released || 0) === 1;
    },

    updateOrganizationStatus: async ({
      orgId,
      nextStatus,
      operatorUserId
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateOrganizationStatus',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedOrgId = String(orgId || '').trim();
            const normalizedNextStatus = normalizeOrgStatus(nextStatus);
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedOrgId
              || !normalizedOperatorUserId
              || !VALID_ORG_STATUS.has(normalizedNextStatus)
            ) {
              throw new Error(
                'updateOrganizationStatus requires orgId, nextStatus, and operatorUserId'
              );
            }

            const orgRows = await tx.query(
              `
                SELECT id, status, owner_user_id
                FROM orgs
                WHERE BINARY id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedOrgId]
            );
            const org = orgRows?.[0] || null;
            if (!org) {
              return null;
            }

            const previousStatus = normalizeOrgStatus(org.status);
            if (previousStatus !== normalizedNextStatus) {
              const updateResult = await tx.query(
                `
                  UPDATE orgs
                  SET status = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE BINARY id = ? AND status <> ?
                `,
                [normalizedNextStatus, normalizedOrgId, normalizedNextStatus]
              );
              if (Number(updateResult?.affectedRows || 0) !== 1) {
                throw new Error('org-status-write-not-applied');
              }

              if (normalizedNextStatus === 'disabled') {
                const membershipRows = await tx.query(
                  `
                    SELECT DISTINCT user_id
                    FROM memberships
                    WHERE org_id = ? AND status IN ('active', 'enabled')
                  `,
                  [normalizedOrgId]
                );
                const affectedUserIds = new Set(
                  (Array.isArray(membershipRows) ? membershipRows : [])
                    .map((row) => String(row?.user_id || '').trim())
                    .filter((userId) => userId.length > 0)
                );
                const ownerUserId = String(org.owner_user_id || '').trim();
                if (ownerUserId.length > 0) {
                  affectedUserIds.add(ownerUserId);
                }
                for (const affectedUserId of affectedUserIds) {
                  await tx.query(
                    `
                      UPDATE auth_sessions
                      SET status = 'revoked',
                          revoked_reason = ?,
                          updated_at = CURRENT_TIMESTAMP(3)
                      WHERE user_id = ?
                        AND entry_domain = 'tenant'
                        AND status = 'active'
                    `,
                    ['org-status-changed', affectedUserId]
                  );
                  await tx.query(
                    `
                      UPDATE refresh_tokens
                      SET status = 'revoked',
                          updated_at = CURRENT_TIMESTAMP(3)
                      WHERE status = 'active'
                        AND session_id IN (
                          SELECT session_id
                          FROM auth_sessions
                          WHERE user_id = ?
                            AND entry_domain = 'tenant'
                        )
                    `,
                    [affectedUserId]
                  );
                }
              }
            }

            return {
              org_id: normalizedOrgId,
              previous_status: previousStatus,
              current_status: normalizedNextStatus
            };
          })
      }),

    updatePlatformUserStatus: async ({
      userId,
      nextStatus,
      operatorUserId
    }) =>
      executeWithDeadlockRetry({
        operation: 'updatePlatformUserStatus',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const normalizedUserId = String(userId || '').trim();
            const normalizedNextStatus = normalizeOrgStatus(nextStatus);
            const normalizedOperatorUserId = String(operatorUserId || '').trim();
            if (
              !normalizedUserId
              || !normalizedOperatorUserId
              || !VALID_PLATFORM_USER_STATUS.has(normalizedNextStatus)
            ) {
              throw new Error(
                'updatePlatformUserStatus requires userId, nextStatus, and operatorUserId'
              );
            }

            const userRows = await tx.query(
              `
                SELECT u.id AS user_id,
                       da.status AS platform_status
                FROM users u
                LEFT JOIN auth_user_domain_access da
                  ON da.user_id = u.id AND da.domain = 'platform'
                WHERE u.id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            const user = userRows?.[0] || null;
            if (
              !user
              || user.platform_status === null
              || user.platform_status === undefined
            ) {
              return null;
            }

            const previousStatus = normalizeOrgStatus(user.platform_status);
            if (!VALID_PLATFORM_USER_STATUS.has(previousStatus)) {
              throw new Error('platform-user-status-read-invalid');
            }
            if (previousStatus !== normalizedNextStatus) {
              const updateResult = await tx.query(
                `
                  UPDATE auth_user_domain_access
                  SET status = ?,
                      updated_at = CURRENT_TIMESTAMP(3)
                  WHERE user_id = ?
                    AND domain = 'platform'
                    AND status <> ?
                `,
                [normalizedNextStatus, normalizedUserId, normalizedNextStatus]
              );
              if (Number(updateResult?.affectedRows || 0) !== 1) {
                throw new Error('platform-user-status-write-not-applied');
              }

              if (normalizedNextStatus === 'disabled') {
                await tx.query(
                  `
                    UPDATE auth_sessions
                    SET status = 'revoked',
                        revoked_reason = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ?
                      AND entry_domain = 'platform'
                      AND status = 'active'
                  `,
                  ['platform-user-status-changed', normalizedUserId]
                );
                await tx.query(
                  `
                    UPDATE refresh_tokens
                    SET status = 'revoked',
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE status = 'active'
                      AND session_id IN (
                        SELECT session_id
                        FROM auth_sessions
                        WHERE user_id = ?
                          AND entry_domain = 'platform'
                      )
                  `,
                  [normalizedUserId]
                );
              }
            }

            return {
              user_id: normalizedUserId,
              previous_status: previousStatus,
              current_status: normalizedNextStatus
            };
          })
      }),

    deleteUserById: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { deleted: false };
      }
      return executeWithDeadlockRetry({
        operation: 'deleteUserById',
        onExhausted: 'return-fallback',
        fallbackResult: { deleted: false },
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            await tx.query(
              `
                DELETE FROM refresh_tokens
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM auth_sessions
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM auth_user_platform_roles
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM auth_user_domain_access
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            await tx.query(
              `
                DELETE FROM auth_user_tenants
                WHERE user_id = ?
              `,
              [normalizedUserId]
            );
            const result = await tx.query(
              `
                DELETE FROM users
                WHERE id = ?
              `,
              [normalizedUserId]
            );
            return { deleted: Number(result?.affectedRows || 0) > 0 };
          })
      });
    },

    createTenantMembershipForUser: async ({ userId, tenantId, tenantName = null }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('createTenantMembershipForUser requires userId and tenantId');
      }
      const normalizedTenantName = tenantName === null || tenantName === undefined
        ? null
        : String(tenantName).trim() || null;
      return executeWithDeadlockRetry({
        operation: 'createTenantMembershipForUser',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const userRows = await tx.query(
              `
                SELECT id
                FROM users
                WHERE id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId]
            );
            if (!Array.isArray(userRows) || userRows.length === 0) {
              return { created: false };
            }

            const existingRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       tenant_name,
                       status,
                       can_view_member_admin,
                       can_operate_member_admin,
                       can_view_billing,
                       can_operate_billing,
                       joined_at,
                       left_at
                FROM auth_user_tenants
                WHERE user_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedUserId, normalizedTenantId]
            );
            const existing = existingRows?.[0] || null;
            if (!existing) {
              const membershipId = randomUUID();
              let result;
              try {
                result = await tx.query(
                  `
                    INSERT INTO auth_user_tenants (
                      membership_id,
                      user_id,
                      tenant_id,
                      tenant_name,
                      status,
                      joined_at,
                      left_at
                    )
                    VALUES (?, ?, ?, ?, 'active', CURRENT_TIMESTAMP(3), NULL)
                  `,
                  [
                    membershipId,
                    normalizedUserId,
                    normalizedTenantId,
                    normalizedTenantName
                  ]
                );
              } catch (error) {
                if (isDuplicateEntryError(error)) {
                  return { created: false };
                }
                throw error;
              }
              return { created: Number(result?.affectedRows || 0) > 0 };
            }

            const existingStatus = normalizeTenantMembershipStatusForRead(existing.status);
            if (!VALID_TENANT_MEMBERSHIP_STATUS.has(existingStatus)) {
              throw new Error(
                'createTenantMembershipForUser encountered unsupported existing status'
              );
            }
            if (existingStatus !== 'left') {
              return { created: false };
            }

            const previousMembershipId = String(existing.membership_id || '').trim();
            await insertTenantMembershipHistoryTx({
              txClient: tx,
              row: {
                ...existing,
                membership_id: previousMembershipId,
                user_id: normalizedUserId,
                tenant_id: normalizedTenantId
              },
              archivedReason: 'rejoin',
              archivedByUserId: null
            });

            await tx.query(
              `
                DELETE FROM auth_tenant_membership_roles
                WHERE membership_id = ?
              `,
              [previousMembershipId]
            );

            const nextMembershipId = randomUUID();
            const updateResult = await tx.query(
              `
                UPDATE auth_user_tenants
                SET membership_id = ?,
                    tenant_name = ?,
                    status = 'active',
                    can_view_member_admin = 0,
                    can_operate_member_admin = 0,
                    can_view_billing = 0,
                    can_operate_billing = 0,
                    joined_at = CURRENT_TIMESTAMP(3),
                    left_at = NULL,
                    updated_at = CURRENT_TIMESTAMP(3)
                WHERE user_id = ? AND tenant_id = ?
              `,
              [
                nextMembershipId,
                normalizedTenantName,
                normalizedUserId,
                normalizedTenantId
              ]
            );
            return { created: Number(updateResult?.affectedRows || 0) > 0 };
          })
      });
    },

    removeTenantMembershipForUser: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        throw new Error('removeTenantMembershipForUser requires userId and tenantId');
      }
      const result = await dbClient.query(
        `
          DELETE FROM auth_user_tenants
          WHERE user_id = ? AND tenant_id = ?
        `,
        [normalizedUserId, normalizedTenantId]
      );
      return { removed: Number(result?.affectedRows || 0) > 0 };
    },

    removeTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return { removed: false };
      }
      const result = await runTenantMembershipQuery({
        sqlWithOrgGuard: `
          DELETE FROM auth_user_domain_access
          WHERE user_id = ?
            AND domain = 'tenant'
            AND NOT EXISTS (
                SELECT 1
              FROM auth_user_tenants ut
              LEFT JOIN orgs o ON o.id = ut.tenant_id
              WHERE ut.user_id = ?
                AND ut.status IN ('active', 'enabled')
                AND o.status IN ('active', 'enabled')
            )
        `,
        sqlWithoutOrgGuard: `
          DELETE FROM auth_user_domain_access
          WHERE user_id = ?
            AND domain = 'tenant'
            AND NOT EXISTS (
              SELECT 1
              FROM auth_user_tenants ut
              WHERE ut.user_id = ?
                AND ut.status IN ('active', 'enabled')
            )
        `,
        params: [normalizedUserId, normalizedUserId]
      });
      return { removed: Number(result?.affectedRows || 0) > 0 };
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
      const normalizedUserId = String(userId);
      try {
        const rows = await dbClient.query(
          `
            SELECT domain, status
            FROM auth_user_domain_access
            WHERE user_id = ?
          `,
          [normalizedUserId]
        );

        const domainRows = Array.isArray(rows) ? rows : [];
        const activeDomains = new Set();
        let hasAnyTenantDomainRecord = false;
        for (const row of domainRows) {
          const domain = String(row?.domain || '').trim().toLowerCase();
          if (!domain) {
            continue;
          }
          if (domain === 'tenant') {
            hasAnyTenantDomainRecord = true;
          }
          const status = row?.status;
          if (isActiveLikeStatus(status)) {
            activeDomains.add(domain);
          }
        }

        let tenantFromMembership = false;
        if (!activeDomains.has('tenant') && !hasAnyTenantDomainRecord) {
          const tenantRows = await runTenantMembershipQuery({
            sqlWithOrgGuard: `
              SELECT COUNT(*) AS tenant_count
              FROM auth_user_tenants ut
              LEFT JOIN orgs o ON o.id = ut.tenant_id
              WHERE ut.user_id = ?
                AND ut.status IN ('active', 'enabled')
                AND o.status IN ('active', 'enabled')
            `,
            sqlWithoutOrgGuard: `
              SELECT COUNT(*) AS tenant_count
              FROM auth_user_tenants ut
              WHERE ut.user_id = ?
                AND ut.status IN ('active', 'enabled')
            `,
            params: [normalizedUserId]
          });
          const tenantCount = Number(tenantRows?.[0]?.tenant_count || 0);
          tenantFromMembership = tenantCount > 0;
        }

        return {
          platform: activeDomains.has('platform'),
          tenant: activeDomains.has('tenant') || tenantFromMembership
        };
      } catch (error) {
        throw error;
      }
    },

    ensureDefaultDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const result = await dbClient.query(
        `
          INSERT IGNORE INTO auth_user_domain_access (user_id, domain, status)
          VALUES (?, 'platform', 'active')
        `,
        [normalizedUserId]
      );

      return { inserted: Number(result?.affectedRows || 0) > 0 };
    },

    ensureTenantDomainAccessForUser: async (userId) => {
      const normalizedUserId = String(userId);
      const tenantCountRows = await runTenantMembershipQuery({
        sqlWithOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM auth_user_tenants ut
          LEFT JOIN orgs o ON o.id = ut.tenant_id
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
        `,
        sqlWithoutOrgGuard: `
          SELECT COUNT(*) AS tenant_count
          FROM auth_user_tenants ut
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
        `,
        params: [normalizedUserId]
      });
      const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
      if (tenantCount <= 0) {
        return { inserted: false };
      }

      const result = await dbClient.query(
        `
          INSERT INTO auth_user_domain_access (user_id, domain, status)
          VALUES (?, 'tenant', 'active')
          ON DUPLICATE KEY UPDATE
            status = CASE
              WHEN status IN ('active', 'enabled') THEN status
              ELSE 'active'
            END,
            updated_at = CASE
              WHEN status IN ('active', 'enabled') THEN updated_at
              ELSE CURRENT_TIMESTAMP(3)
            END
        `,
        [normalizedUserId]
      );
      return { inserted: Number(result?.affectedRows || 0) > 0 };
    },

    findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId);
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedTenantId) {
        return null;
      }

      try {
        const rows = await runTenantMembershipQuery({
          sqlWithOrgGuard: `
            SELECT tenant_id,
                   tenant_name,
                   can_view_member_admin,
                   can_operate_member_admin,
                   can_view_billing,
                   can_operate_billing
            FROM auth_user_tenants ut
            LEFT JOIN orgs o ON o.id = ut.tenant_id
            WHERE ut.user_id = ?
              AND ut.tenant_id = ?
              AND ut.status IN ('active', 'enabled')
              AND o.status IN ('active', 'enabled')
            LIMIT 1
          `,
          sqlWithoutOrgGuard: `
            SELECT tenant_id,
                   tenant_name,
                   can_view_member_admin,
                   can_operate_member_admin,
                   can_view_billing,
                   can_operate_billing
            FROM auth_user_tenants ut
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
          canViewMemberAdmin: toBoolean(row.can_view_member_admin),
          canOperateMemberAdmin: toBoolean(row.can_operate_member_admin),
          canViewBilling: toBoolean(row.can_view_billing),
          canOperateBilling: toBoolean(row.can_operate_billing)
        };
      } catch (error) {
        throw error;
      }
    },

    listTenantOptionsByUserId: async (userId) => {
      const normalizedUserId = String(userId);
      try {
        const rows = await runTenantMembershipQuery({
          sqlWithOrgGuard: `
            SELECT tenant_id, tenant_name
            FROM auth_user_tenants ut
            LEFT JOIN orgs o ON o.id = ut.tenant_id
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
              AND o.status IN ('active', 'enabled')
            ORDER BY tenant_id ASC
          `,
          sqlWithoutOrgGuard: `
            SELECT tenant_id, tenant_name
            FROM auth_user_tenants ut
            WHERE ut.user_id = ?
              AND ut.status IN ('active', 'enabled')
            ORDER BY tenant_id ASC
          `,
          params: [normalizedUserId]
        });

        return (Array.isArray(rows) ? rows : [])
          .map((row) => ({
            tenantId: String(row.tenant_id || '').trim(),
            tenantName: row.tenant_name ? String(row.tenant_name) : null
          }))
          .filter((row) => row.tenantId.length > 0);
      } catch (error) {
        throw error;
      }
    },

    findTenantMembershipByUserAndTenantId: async ({ userId, tenantId }) => {
      const normalizedUserId = String(userId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedUserId || !normalizedTenantId) {
        return null;
      }
      const rows = await dbClient.query(
        `
          SELECT ut.membership_id,
                 ut.user_id,
                 ut.tenant_id,
                 ut.tenant_name,
                 ut.status,
                 ut.joined_at,
                 ut.left_at,
                 u.phone
          FROM auth_user_tenants ut
          JOIN users u ON u.id = ut.user_id
          WHERE ut.user_id = ? AND ut.tenant_id = ?
          LIMIT 1
        `,
        [normalizedUserId, normalizedTenantId]
      );
      const row = rows?.[0];
      if (!row) {
        return null;
      }
      return {
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        phone: String(row.phone || ''),
        status: normalizeTenantMembershipStatusForRead(row.status),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
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
      const rows = await dbClient.query(
        `
          SELECT membership_id,
                 user_id,
                 tenant_id,
                 tenant_name,
                 status,
                 joined_at,
                 left_at
          FROM auth_user_tenants
          WHERE membership_id = ? AND tenant_id = ?
          LIMIT 1
        `,
        [normalizedMembershipId, normalizedTenantId]
      );
      const row = rows?.[0] || null;
      if (!row) {
        return null;
      }
      return {
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        status: normalizeTenantMembershipStatusForRead(row.status),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
      };
    },

    listTenantMembershipRoleBindings: async ({
      membershipId,
      tenantId
    } = {}) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      const normalizedTenantId = String(tenantId || '').trim();
      if (!normalizedMembershipId || !normalizedTenantId) {
        return [];
      }
      const rows = await dbClient.query(
        `
          SELECT mr.role_id
          FROM auth_tenant_membership_roles mr
          JOIN auth_user_tenants ut ON ut.membership_id = mr.membership_id
          WHERE mr.membership_id = ?
            AND ut.tenant_id = ?
          ORDER BY mr.role_id ASC
        `,
        [normalizedMembershipId, normalizedTenantId]
      );
      const normalizedRoleIds = [];
      const seenRoleIds = new Set();
      for (const row of Array.isArray(rows) ? rows : []) {
        const normalizedRoleId = normalizeStrictTenantMembershipRoleIdFromBindingRow(
          row?.role_id,
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
    },

    replaceTenantMembershipRoleBindingsAndSyncSnapshot: async ({
      tenantId,
      membershipId,
      roleIds = [],
      operatorUserId = null
    } = {}) => {
      const normalizedTenantId = String(tenantId || '').trim();
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedTenantId || !normalizedMembershipId) {
        throw new Error(
          'replaceTenantMembershipRoleBindingsAndSyncSnapshot requires tenantId and membershipId'
        );
      }
      const normalizedRoleIds = normalizeTenantMembershipRoleIds(roleIds);
      return executeWithDeadlockRetry({
        operation: 'replaceTenantMembershipRoleBindingsAndSyncSnapshot',
        onExhausted: 'throw',
        execute: () =>
          dbClient.inTransaction(async (tx) => {
            const membershipRows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       status
                FROM auth_user_tenants
                WHERE membership_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const membershipRow = membershipRows?.[0] || null;
            if (!membershipRow) {
              return null;
            }
            const normalizedMembershipStatus = normalizeTenantMembershipStatusForRead(
              membershipRow.status
            );
            if (!isActiveLikeStatus(normalizedMembershipStatus)) {
              const membershipStatusError = new Error(
                'tenant membership role bindings membership not active'
              );
              membershipStatusError.code =
                'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_MEMBERSHIP_NOT_ACTIVE';
              throw membershipStatusError;
            }
            const normalizedAffectedUserId =
              normalizeStrictTenantMembershipRoleBindingIdentity(
                membershipRow?.user_id,
                'tenant-membership-role-bindings-invalid-affected-user-id'
              );
            if (normalizedRoleIds.length > 0) {
              const rolePlaceholders = buildSqlInPlaceholders(
                normalizedRoleIds.length
              );
              const roleRows = await tx.query(
                `
                  SELECT role_id, status, scope, tenant_id
                  FROM platform_role_catalog
                  WHERE role_id IN (${rolePlaceholders})
                  FOR UPDATE
                `,
                normalizedRoleIds
              );
              const roleRowsByRoleId = new Map();
              for (const row of Array.isArray(roleRows) ? roleRows : []) {
                const resolvedRoleId = normalizePlatformRoleCatalogRoleId(
                  row?.role_id
                );
                if (!resolvedRoleId || roleRowsByRoleId.has(resolvedRoleId)) {
                  continue;
                }
                roleRowsByRoleId.set(resolvedRoleId, row);
              }
              for (const roleId of normalizedRoleIds) {
                const roleRow = roleRowsByRoleId.get(roleId) || null;
                const roleScope = normalizePlatformRoleCatalogScope(roleRow?.scope);
                const roleTenantId = normalizePlatformRoleCatalogTenantId(
                  roleRow?.tenant_id
                );
                let roleStatus = 'disabled';
                try {
                  roleStatus = normalizePlatformRoleCatalogStatus(
                    roleRow?.status || 'disabled'
                  );
                } catch (_error) {}
                if (
                  !roleRow
                  || roleScope !== 'tenant'
                  || roleTenantId !== normalizedTenantId
                  || !isActiveLikeStatus(roleStatus)
                ) {
                  const roleValidationError = new Error(
                    'tenant membership role bindings role invalid'
                  );
                  roleValidationError.code =
                    'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_ROLE_INVALID';
                  roleValidationError.roleId = roleId;
                  throw roleValidationError;
                }
              }
            }

            await tx.query(
              `
                DELETE FROM auth_tenant_membership_roles
                WHERE membership_id = ?
              `,
              [normalizedMembershipId]
            );

            for (const roleId of normalizedRoleIds) {
              await tx.query(
                `
                  INSERT INTO auth_tenant_membership_roles (
                    membership_id,
                    role_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedMembershipId,
                  roleId,
                  operatorUserId ? String(operatorUserId) : null,
                  operatorUserId ? String(operatorUserId) : null
                ]
              );
            }

            const syncResult = await syncTenantMembershipPermissionSnapshotInTx({
              txClient: tx,
              membershipId: normalizedMembershipId,
              tenantId: normalizedTenantId,
              roleIds: normalizedRoleIds,
              revokeReason: 'tenant-membership-role-bindings-changed'
            });
            const syncReason = String(syncResult?.reason || 'unknown')
              .trim()
              .toLowerCase();
            if (syncReason !== 'ok') {
              const syncError = new Error(
                `tenant membership role bindings sync failed: ${syncReason || 'unknown'}`
              );
              syncError.code = 'ERR_TENANT_MEMBERSHIP_ROLE_BINDINGS_SYNC_FAILED';
              syncError.syncReason = syncReason || 'unknown';
              throw syncError;
            }

            return {
              membershipId: normalizedMembershipId,
              roleIds: [...normalizedRoleIds],
              affectedUserIds: [normalizedAffectedUserId],
              affectedUserCount: 1
            };
          })
      });
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
      const offset = (resolvedPage - 1) * resolvedPageSize;

      const rows = await dbClient.query(
        `
          SELECT ut.membership_id,
                 ut.user_id,
                 ut.tenant_id,
                 ut.tenant_name,
                 ut.status,
                 ut.joined_at,
                 ut.left_at,
                 u.phone
          FROM auth_user_tenants ut
          JOIN users u ON u.id = ut.user_id
          WHERE ut.tenant_id = ?
          ORDER BY ut.joined_at DESC, ut.membership_id DESC
          LIMIT ? OFFSET ?
        `,
        [normalizedTenantId, resolvedPageSize, offset]
      );
      return (Array.isArray(rows) ? rows : []).map((row) => ({
        membership_id: String(row.membership_id || '').trim(),
        user_id: String(row.user_id || '').trim(),
        tenant_id: String(row.tenant_id || '').trim(),
        tenant_name: row.tenant_name ? String(row.tenant_name) : null,
        phone: String(row.phone || ''),
        status: normalizeTenantMembershipStatusForRead(row.status),
        joined_at: row.joined_at ? new Date(row.joined_at).toISOString() : null,
        left_at: row.left_at ? new Date(row.left_at).toISOString() : null
      }));
    },

    updateTenantMembershipStatus: async ({
      membershipId,
      tenantId,
      nextStatus,
      operatorUserId,
      reason = null
    }) =>
      executeWithDeadlockRetry({
        operation: 'updateTenantMembershipStatus',
        onExhausted: 'throw',
        execute: async () => {
          const normalizedMembershipId = String(membershipId || '').trim();
          const normalizedTenantId = String(tenantId || '').trim();
          const normalizedNextStatus = normalizeTenantMembershipStatusForRead(nextStatus);
          const normalizedOperatorUserId = String(operatorUserId || '').trim();
          const normalizedReason = reason === null || reason === undefined
            ? null
            : String(reason).trim() || null;
          if (
            !normalizedMembershipId
            || !normalizedTenantId
            || !normalizedOperatorUserId
            || !VALID_TENANT_MEMBERSHIP_STATUS.has(normalizedNextStatus)
          ) {
            throw new Error(
              'updateTenantMembershipStatus requires membershipId, tenantId, nextStatus and operatorUserId'
            );
          }
          return dbClient.inTransaction(async (tx) => {
            const rows = await tx.query(
              `
                SELECT membership_id,
                       user_id,
                       tenant_id,
                       tenant_name,
                       status,
                       can_view_member_admin,
                       can_operate_member_admin,
                       can_view_billing,
                       can_operate_billing,
                       joined_at,
                       left_at
                FROM auth_user_tenants
                WHERE membership_id = ? AND tenant_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedMembershipId, normalizedTenantId]
            );
            const row = rows?.[0] || null;
            if (!row) {
              return null;
            }
            const previousStatus = normalizeTenantMembershipStatusForRead(row.status);
            if (!VALID_TENANT_MEMBERSHIP_STATUS.has(previousStatus)) {
              throw new Error(
                'updateTenantMembershipStatus encountered unsupported existing status'
              );
            }
            let finalMembershipId = String(row.membership_id || '').trim() || normalizedMembershipId;
            if (previousStatus !== normalizedNextStatus) {
              if (previousStatus === 'left' && normalizedNextStatus === 'active') {
                await insertTenantMembershipHistoryTx({
                  txClient: tx,
                  row,
                  archivedReason: normalizedReason || 'reactivate',
                  archivedByUserId: normalizedOperatorUserId
                });
                await tx.query(
                  `
                    DELETE FROM auth_tenant_membership_roles
                    WHERE membership_id = ?
                  `,
                  [normalizedMembershipId]
                );
                finalMembershipId = randomUUID();
                await tx.query(
                  `
                    UPDATE auth_user_tenants
                    SET membership_id = ?,
                        status = 'active',
                        can_view_member_admin = 0,
                        can_operate_member_admin = 0,
                        can_view_billing = 0,
                        can_operate_billing = 0,
                        left_at = NULL,
                        joined_at = CURRENT_TIMESTAMP(3),
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE membership_id = ? AND tenant_id = ?
                  `,
                  [finalMembershipId, normalizedMembershipId, normalizedTenantId]
                );
              } else {
                if (normalizedNextStatus === 'left') {
                  await insertTenantMembershipHistoryTx({
                    txClient: tx,
                    row,
                    archivedReason: normalizedReason || 'left',
                    archivedByUserId: normalizedOperatorUserId
                  });
                  await tx.query(
                    `
                      DELETE FROM auth_tenant_membership_roles
                      WHERE membership_id = ?
                    `,
                    [finalMembershipId]
                  );
                }
                await tx.query(
                  `
                    UPDATE auth_user_tenants
                    SET status = ?,
                        can_view_member_admin = CASE WHEN ? = 'left' THEN 0 ELSE can_view_member_admin END,
                        can_operate_member_admin = CASE WHEN ? = 'left' THEN 0 ELSE can_operate_member_admin END,
                        can_view_billing = CASE WHEN ? = 'left' THEN 0 ELSE can_view_billing END,
                        can_operate_billing = CASE WHEN ? = 'left' THEN 0 ELSE can_operate_billing END,
                        left_at = CASE
                          WHEN ? = 'left' THEN CURRENT_TIMESTAMP(3)
                          WHEN ? = 'active' THEN NULL
                          ELSE left_at
                        END,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE membership_id = ? AND tenant_id = ?
                  `,
                  [
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    normalizedNextStatus,
                    finalMembershipId,
                    normalizedTenantId
                  ]
                );
              }

              if (normalizedNextStatus === 'active') {
                await syncTenantMembershipPermissionSnapshotInTx({
                  txClient: tx,
                  membershipId: finalMembershipId,
                  tenantId: normalizedTenantId,
                  roleIds: previousStatus === 'left' ? [] : null,
                  revokeReason: 'tenant-membership-status-changed'
                });
                await ensureTenantDomainAccessForUserTx({
                  txClient: tx,
                  userId: row.user_id
                });
              } else {
                await tx.query(
                  `
                    UPDATE auth_sessions
                    SET status = 'revoked',
                        revoked_reason = ?,
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE user_id = ?
                      AND entry_domain = 'tenant'
                      AND active_tenant_id = ?
                      AND status = 'active'
                  `,
                  [
                    'tenant-membership-status-changed',
                    row.user_id,
                    normalizedTenantId
                  ]
                );
                await tx.query(
                  `
                    UPDATE refresh_tokens
                    SET status = 'revoked',
                        updated_at = CURRENT_TIMESTAMP(3)
                    WHERE status = 'active'
                      AND session_id IN (
                        SELECT session_id
                        FROM auth_sessions
                        WHERE user_id = ?
                          AND entry_domain = 'tenant'
                          AND active_tenant_id = ?
                      )
                  `,
                  [row.user_id, normalizedTenantId]
                );
                await removeTenantDomainAccessForUserTx({
                  txClient: tx,
                  userId: row.user_id
                });
              }
            }

            return {
              membership_id: finalMembershipId,
              user_id: String(row.user_id || '').trim(),
              tenant_id: String(row.tenant_id || '').trim(),
              previous_status: previousStatus,
              current_status: normalizedNextStatus
            };
          });
        }
      }),

    hasAnyTenantRelationshipByUserId: async (userId) => {
      const normalizedUserId = String(userId);
      const rows = await dbClient.query(
        `
          SELECT COUNT(*) AS tenant_count
          FROM auth_user_tenants
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

      try {
        const rows = await dbClient.query(
          `
            SELECT status,
                   can_view_member_admin,
                   can_operate_member_admin,
                   can_view_billing,
                   can_operate_billing
            FROM auth_user_domain_access
            WHERE user_id = ? AND domain = 'platform' AND status IN ('active', 'enabled')
            LIMIT 1
          `,
          [normalizedUserId]
        );
        const row = rows?.[0];
        if (!row) {
          return null;
        }

        const hasPermissionSnapshot =
          Object.prototype.hasOwnProperty.call(row, 'can_view_member_admin')
          || Object.prototype.hasOwnProperty.call(row, 'can_operate_member_admin')
          || Object.prototype.hasOwnProperty.call(row, 'can_view_billing')
          || Object.prototype.hasOwnProperty.call(row, 'can_operate_billing')
          || Object.prototype.hasOwnProperty.call(row, 'canViewMemberAdmin')
          || Object.prototype.hasOwnProperty.call(row, 'canOperateMemberAdmin')
          || Object.prototype.hasOwnProperty.call(row, 'canViewBilling')
          || Object.prototype.hasOwnProperty.call(row, 'canOperateBilling');
        if (!hasPermissionSnapshot) {
          return null;
        }

        return {
          scopeLabel: '平台权限（服务端快照）',
          canViewMemberAdmin: toBoolean(
            row.can_view_member_admin ?? row.canViewMemberAdmin
          ),
          canOperateMemberAdmin: toBoolean(
            row.can_operate_member_admin ?? row.canOperateMemberAdmin
          ),
          canViewBilling: toBoolean(row.can_view_billing ?? row.canViewBilling),
          canOperateBilling: toBoolean(
            row.can_operate_billing ?? row.canOperateBilling
          )
        };
      } catch (error) {
        throw error;
      }
    },

    syncPlatformPermissionSnapshotByUserId: async ({
      userId,
      forceWhenNoRoleFacts = false
    }) =>
      syncPlatformPermissionSnapshotByUserId({
        userId,
        forceWhenNoRoleFacts
      }),

    replacePlatformRolesAndSyncSnapshot: async ({ userId, roles = [] }) =>
      replacePlatformRolesAndSyncSnapshot({
        userId,
        roles
      }),

    getPlatformDeadlockMetrics: () =>
      Object.fromEntries(
        [...deadlockMetricsByOperation.entries()].map(([operation, metrics]) => {
          const rates = toDeadlockRates(metrics);
          return [
            operation,
            {
              deadlockCount: Number(metrics.deadlockCount),
              retrySuccessCount: Number(metrics.retrySuccessCount),
              finalFailureCount: Number(metrics.finalFailureCount),
              retrySuccessRate: Number(rates.retrySuccessRate),
              finalFailureRate: Number(rates.finalFailureRate)
            }
          ];
        })
      ),

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
          UPDATE refresh_tokens
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
          UPDATE refresh_tokens
          SET status = 'revoked',
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE user_id = ? AND status = 'active'
        `,
        [String(userId)]
      );
    },

    createRefreshToken: async ({ tokenHash, sessionId, userId, expiresAt }) => {
      await dbClient.query(
        `
          INSERT INTO refresh_tokens (token_hash, session_id, user_id, status, expires_at)
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
          FROM refresh_tokens
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
          UPDATE refresh_tokens
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
          UPDATE refresh_tokens
          SET rotated_to_token_hash = ?,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE token_hash = ?
        `,
        [nextTokenHash, previousTokenHash]
      );

      await dbClient.query(
        `
          UPDATE refresh_tokens
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
            FROM refresh_tokens
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
            UPDATE refresh_tokens
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
            INSERT INTO refresh_tokens (token_hash, session_id, user_id, status, expires_at, rotated_from_token_hash)
            VALUES (?, ?, ?, 'active', FROM_UNIXTIME(? / 1000.0), ?)
          `,
          [nextTokenHash, normalizedSessionId, normalizedUserId, Number(expiresAt), previousTokenHash]
        );

        await tx.query(
          `
            UPDATE refresh_tokens
            SET rotated_to_token_hash = ?,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE token_hash = ?
          `,
          [nextTokenHash, previousTokenHash]
        );

        return { ok: true };
      }),

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

module.exports = { createMySqlAuthStore };
