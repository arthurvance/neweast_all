const { setTimeout: sleep } = require('node:timers/promises');
const { log } = require('../../common/logger');

const DEFAULT_DEADLOCK_RETRY_CONFIG = Object.freeze({
  maxRetries: 2,
  baseDelayMs: 20,
  maxDelayMs: 200,
  jitterMs: 20
});

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
  const normalizedStatus = String(status || 'active').trim().toLowerCase();
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
    dedupedByRoleId.set(normalizedRole.roleId, normalizedRole);
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
    execute
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
        return {
          synced: false,
          reason: 'db-deadlock',
          permission: null
        };
      }
    }
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

  const replacePlatformRolesAndSyncSnapshotOnce = async ({ userId, roles = [] }) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return {
        synced: false,
        reason: 'invalid-user-id',
        permission: null
      };
    }

    const normalizedRoles = dedupePlatformRoleFacts(roles);

    return dbClient.inTransaction(async (tx) => {
      await tx.query(
        `
          DELETE FROM auth_user_platform_roles
          WHERE user_id = ?
        `,
        [normalizedUserId]
      );

      for (const role of normalizedRoles) {
        await tx.query(
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
      let snapshotResult = { affectedRows: 0 };

      if (normalizedRoles.length > 0) {
        snapshotResult = await tx.query(
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
        snapshotResult = await tx.query(
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

      return {
        synced: Number(snapshotResult?.affectedRows || 0) > 0,
        reason: 'ok',
        permission
      };
    });
  };

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
          const tenantRows = await dbClient.query(
            `
              SELECT COUNT(*) AS tenant_count
              FROM auth_user_tenants
              WHERE user_id = ? AND status IN ('active', 'enabled')
            `,
            [normalizedUserId]
          );
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
      const countRows = await dbClient.query(
        `
          SELECT COUNT(*) AS domain_count
          FROM auth_user_domain_access
          WHERE user_id = ?
        `,
        [normalizedUserId]
      );
      const domainCount = Number(countRows?.[0]?.domain_count || 0);
      if (domainCount > 0) {
        return { inserted: false };
      }

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

      const tenantDomainRows = await dbClient.query(
        `
          SELECT status
          FROM auth_user_domain_access
          WHERE user_id = ? AND domain = 'tenant'
          LIMIT 1
        `,
        [normalizedUserId]
      );
      if (Array.isArray(tenantDomainRows) && tenantDomainRows.length > 0) {
        return { inserted: false };
      }

      const tenantCountRows = await dbClient.query(
        `
          SELECT COUNT(*) AS tenant_count
          FROM auth_user_tenants
          WHERE user_id = ? AND status IN ('active', 'enabled')
        `,
        [normalizedUserId]
      );
      const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
      if (tenantCount <= 0) {
        return { inserted: false };
      }

      const result = await dbClient.query(
        `
          INSERT IGNORE INTO auth_user_domain_access (user_id, domain, status)
          VALUES (?, 'tenant', 'active')
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
        const rows = await dbClient.query(
          `
            SELECT tenant_id,
                   tenant_name,
                   can_view_member_admin,
                   can_operate_member_admin,
                   can_view_billing,
                   can_operate_billing
            FROM auth_user_tenants
            WHERE user_id = ? AND tenant_id = ? AND status IN ('active', 'enabled')
            LIMIT 1
          `,
          [normalizedUserId, normalizedTenantId]
        );
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
        const rows = await dbClient.query(
          `
            SELECT tenant_id, tenant_name
            FROM auth_user_tenants
            WHERE user_id = ? AND status IN ('active', 'enabled')
            ORDER BY tenant_id ASC
          `,
          [normalizedUserId]
        );

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

    updateUserPasswordAndBumpSessionVersion: async ({ userId, passwordHash }) => {
      await dbClient.query(
        `
          UPDATE users
          SET password_hash = ?,
              session_version = session_version + 1,
              updated_at = CURRENT_TIMESTAMP(3)
          WHERE id = ?
        `,
        [passwordHash, String(userId)]
      );

      const rows = await dbClient.query(
        `
          SELECT id, phone, password_hash, status, session_version
          FROM users
          WHERE id = ?
          LIMIT 1
        `,
        [String(userId)]
      );
      return toUserRecord(rows[0]);
    },

    updateUserPasswordAndRevokeSessions: async ({ userId, passwordHash, reason }) =>
      dbClient.inTransaction(async (tx) => {
        const updated = await tx.query(
          `
            UPDATE users
            SET password_hash = ?,
                session_version = session_version + 1,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE id = ?
          `,
          [passwordHash, String(userId)]
        );

        if (!updated || Number(updated.affectedRows || 0) !== 1) {
          return null;
        }

        await tx.query(
          `
            UPDATE auth_sessions
            SET status = 'revoked',
                revoked_reason = ?,
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE user_id = ? AND status = 'active'
          `,
          [reason || 'password-changed', String(userId)]
        );

        await tx.query(
          `
            UPDATE refresh_tokens
            SET status = 'revoked',
                updated_at = CURRENT_TIMESTAMP(3)
            WHERE user_id = ? AND status = 'active'
          `,
          [String(userId)]
        );

        const rows = await tx.query(
          `
            SELECT id, phone, password_hash, status, session_version
            FROM users
            WHERE id = ?
            LIMIT 1
          `,
          [String(userId)]
        );

        return toUserRecord(rows[0]);
      })
  };
};

module.exports = { createMySqlAuthStore };
