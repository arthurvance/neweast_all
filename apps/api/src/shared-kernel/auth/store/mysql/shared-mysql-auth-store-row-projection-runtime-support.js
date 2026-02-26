'use strict';

const createSharedMysqlAuthStoreRowProjectionRuntimeSupport = ({
  normalizeUserStatus,
  normalizePlatformRoleCatalogTenantId,
  normalizePlatformRoleCatalogStatus,
  normalizePlatformRoleCatalogScope,
  normalizePlatformIntegrationId,
  normalizePlatformIntegrationCode,
  normalizePlatformIntegrationDirection,
  normalizePlatformIntegrationLifecycleStatus,
  isValidPlatformIntegrationId,
  MAX_PLATFORM_INTEGRATION_CODE_LENGTH,
  VALID_PLATFORM_INTEGRATION_DIRECTION,
  VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
  normalizePlatformIntegrationOptionalText,
  MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH,
  MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_NAME_LENGTH,
  MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH,
  MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH,
  MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH,
  MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH,
  MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH,
  normalizePlatformIntegrationCodeKey,
  normalizePlatformIntegrationContractType,
  normalizePlatformIntegrationContractVersion,
  normalizePlatformIntegrationContractSchemaChecksum,
  normalizePlatformIntegrationContractStatus,
  VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
  MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH,
  PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN,
  VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
  MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH,
  normalizePlatformIntegrationContractEvaluationResult,
  VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT,
  MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH,
  normalizePlatformIntegrationRecoveryId,
  normalizePlatformIntegrationRecoveryStatus,
  MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH,
  VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
  MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
  normalizePlatformIntegrationFreezeId,
  normalizePlatformIntegrationFreezeStatus,
  normalizeStoreIsoTimestamp,
  MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH,
  VALID_PLATFORM_INTEGRATION_FREEZE_STATUS,
  MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH,
  MAX_OPERATOR_USER_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH,
  MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH,
  createPlatformIntegrationFreezeActiveConflictError
} = {}) => {
  const toBoolean = (value) =>
    value === true
    || value === 1
    || value === '1'
    || String(value || '').toLowerCase() === 'true';

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

  const toPlatformIntegrationCatalogRecord = (row) => {
    if (!row) {
      return null;
    }
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      row.integration_id
    );
    const normalizedCode = normalizePlatformIntegrationCode(row.code);
    const normalizedDirection = normalizePlatformIntegrationDirection(row.direction);
    const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
      row.lifecycle_status
    );
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !normalizedCode
      || normalizedCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
      || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)
      || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
    ) {
      return null;
    }
    const normalizedProtocol = String(row.protocol || '').trim();
    const normalizedAuthMode = String(row.auth_mode || '').trim();
    const normalizedName = String(row.name || '').trim();
    const normalizedTimeoutMs = Number(row.timeout_ms);
    const normalizedEndpoint = normalizePlatformIntegrationOptionalText(row.endpoint);
    const normalizedBaseUrl = normalizePlatformIntegrationOptionalText(row.base_url);
    const normalizedVersionStrategy = normalizePlatformIntegrationOptionalText(
      row.version_strategy
    );
    const normalizedRunbookUrl = normalizePlatformIntegrationOptionalText(row.runbook_url);
    const normalizedLifecycleReason = normalizePlatformIntegrationOptionalText(
      row.lifecycle_reason
    );
    if (
      !normalizedProtocol
      || normalizedProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
      || !normalizedAuthMode
      || normalizedAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
      || !normalizedName
      || normalizedName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
      || (
        normalizedEndpoint !== null
        && normalizedEndpoint.length > MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH
      )
      || (
        normalizedBaseUrl !== null
        && normalizedBaseUrl.length > MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH
      )
      || (
        normalizedVersionStrategy !== null
        && normalizedVersionStrategy.length > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
      )
      || (
        normalizedRunbookUrl !== null
        && normalizedRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
      )
      || (
        normalizedLifecycleReason !== null
        && normalizedLifecycleReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
      )
      || !Number.isInteger(normalizedTimeoutMs)
      || normalizedTimeoutMs < 1
    ) {
      return null;
    }
    return {
      integrationId: normalizedIntegrationId,
      code: normalizedCode,
      codeNormalized: normalizePlatformIntegrationCodeKey(normalizedCode),
      name: normalizedName,
      direction: normalizedDirection,
      protocol: normalizedProtocol,
      authMode: normalizedAuthMode,
      endpoint: normalizedEndpoint,
      baseUrl: normalizedBaseUrl,
      timeoutMs: normalizedTimeoutMs,
      retryPolicy: safeParseJsonValue(row.retry_policy),
      idempotencyPolicy: safeParseJsonValue(row.idempotency_policy),
      versionStrategy: normalizedVersionStrategy,
      runbookUrl: normalizedRunbookUrl,
      lifecycleStatus: normalizedLifecycleStatus,
      lifecycleReason: normalizedLifecycleReason,
      createdByUserId: normalizePlatformIntegrationOptionalText(row.created_by_user_id),
      updatedByUserId: normalizePlatformIntegrationOptionalText(row.updated_by_user_id),
      createdAt: row.created_at instanceof Date
        ? row.created_at.toISOString()
        : String(row.created_at || ''),
      updatedAt: row.updated_at instanceof Date
        ? row.updated_at.toISOString()
        : String(row.updated_at || '')
    };
  };

  const toPlatformIntegrationContractVersionRecord = (row) => {
    if (!row) {
      return null;
    }
    const integrationId = normalizePlatformIntegrationId(row.integration_id);
    const contractType = normalizePlatformIntegrationContractType(row.contract_type);
    const contractVersion = normalizePlatformIntegrationContractVersion(
      row.contract_version
    );
    const schemaRef = normalizePlatformIntegrationOptionalText(row.schema_ref);
    const schemaChecksum = normalizePlatformIntegrationContractSchemaChecksum(
      row.schema_checksum
    );
    const status = normalizePlatformIntegrationContractStatus(row.status);
    const compatibilityNotes = normalizePlatformIntegrationOptionalText(
      row.compatibility_notes
    );
    const createdByUserId = normalizePlatformIntegrationOptionalText(
      row.created_by_user_id
    );
    const updatedByUserId = normalizePlatformIntegrationOptionalText(
      row.updated_by_user_id
    );
    const createdAt = row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at || '');
    const updatedAt = row.updated_at instanceof Date
      ? row.updated_at.toISOString()
      : String(row.updated_at || '');
    if (
      !isValidPlatformIntegrationId(integrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(contractType)
      || !contractVersion
      || contractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !schemaRef
      || schemaRef.length > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH
      || !schemaChecksum
      || schemaChecksum.length > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH
      || !PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN.test(schemaChecksum)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(status)
      || (
        compatibilityNotes !== null
        && compatibilityNotes.length > MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH
      )
      || !createdAt
      || !updatedAt
    ) {
      return null;
    }
    return {
      contractId: Number(row.contract_id),
      integrationId,
      contractType,
      contractVersion,
      schemaRef,
      schemaChecksum,
      status,
      isBackwardCompatible: toBoolean(row.is_backward_compatible),
      compatibilityNotes,
      createdByUserId,
      updatedByUserId,
      createdAt,
      updatedAt
    };
  };

  const toPlatformIntegrationContractCompatibilityCheckRecord = (row) => {
    if (!row) {
      return null;
    }
    const integrationId = normalizePlatformIntegrationId(row.integration_id);
    const contractType = normalizePlatformIntegrationContractType(row.contract_type);
    const baselineVersion = normalizePlatformIntegrationContractVersion(
      row.baseline_version
    );
    const candidateVersion = normalizePlatformIntegrationContractVersion(
      row.candidate_version
    );
    const evaluationResult = normalizePlatformIntegrationContractEvaluationResult(
      row.evaluation_result
    );
    const requestId = String(row.request_id || '').trim();
    const checkedByUserId = normalizePlatformIntegrationOptionalText(
      row.checked_by_user_id
    );
    const checkedAt = row.checked_at instanceof Date
      ? row.checked_at.toISOString()
      : String(row.checked_at || '');
    const breakingChangeCount = Number(row.breaking_change_count);
    const diffSummary = safeParseJsonValue(row.diff_summary);
    if (
      !isValidPlatformIntegrationId(integrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(contractType)
      || !baselineVersion
      || baselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !candidateVersion
      || candidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(evaluationResult)
      || !Number.isInteger(breakingChangeCount)
      || breakingChangeCount < 0
      || !requestId
      || requestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
      || !checkedAt
      || (
        row.diff_summary !== null
        && row.diff_summary !== undefined
        && diffSummary === null
        && String(row.diff_summary || '').trim() !== ''
      )
    ) {
      return null;
    }
    const normalizedDiffSummary = diffSummary === null
      ? null
      : JSON.stringify(diffSummary);
    if (
      normalizedDiffSummary !== null
      && normalizedDiffSummary.length > MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH
    ) {
      return null;
    }
    return {
      checkId: Number(row.check_id),
      integrationId,
      contractType,
      baselineVersion,
      candidateVersion,
      evaluationResult,
      breakingChangeCount,
      diffSummary,
      requestId,
      checkedByUserId,
      checkedAt
    };
  };

  const toPlatformIntegrationRecoveryQueueRecord = (row) => {
    if (!row) {
      return null;
    }
    const recoveryId = normalizePlatformIntegrationRecoveryId(row.recovery_id);
    const integrationId = normalizePlatformIntegrationId(row.integration_id);
    const contractType = normalizePlatformIntegrationContractType(row.contract_type);
    const contractVersion = normalizePlatformIntegrationContractVersion(
      row.contract_version
    );
    const requestId = String(row.request_id || '').trim();
    const traceparent = normalizePlatformIntegrationOptionalText(row.traceparent);
    const idempotencyKey = normalizePlatformIntegrationOptionalText(
      row.idempotency_key
    );
    const attemptCount = Number(row.attempt_count);
    const maxAttempts = Number(row.max_attempts);
    const nextRetryAt = row.next_retry_at instanceof Date
      ? row.next_retry_at.toISOString()
      : (
        row.next_retry_at === null || row.next_retry_at === undefined
          ? null
          : String(row.next_retry_at || '')
      );
    const lastAttemptAt = row.last_attempt_at instanceof Date
      ? row.last_attempt_at.toISOString()
      : (
        row.last_attempt_at === null || row.last_attempt_at === undefined
          ? null
          : String(row.last_attempt_at || '')
      );
    const status = normalizePlatformIntegrationRecoveryStatus(row.status);
    const failureCode = normalizePlatformIntegrationOptionalText(row.failure_code);
    const failureDetail = normalizePlatformIntegrationOptionalText(row.failure_detail);
    const lastHttpStatus = row.last_http_status === null || row.last_http_status === undefined
      ? null
      : Number(row.last_http_status);
    const retryable = toBoolean(row.retryable);
    const payloadSnapshot = safeParseJsonValue(row.payload_snapshot);
    const responseSnapshot = safeParseJsonValue(row.response_snapshot);
    const createdByUserId = normalizePlatformIntegrationOptionalText(
      row.created_by_user_id
    );
    const updatedByUserId = normalizePlatformIntegrationOptionalText(
      row.updated_by_user_id
    );
    const createdAt = row.created_at instanceof Date
      ? row.created_at.toISOString()
      : String(row.created_at || '');
    const updatedAt = row.updated_at instanceof Date
      ? row.updated_at.toISOString()
      : String(row.updated_at || '');
    if (
      !recoveryId
      || recoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
      || !isValidPlatformIntegrationId(integrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(contractType)
      || !contractVersion
      || contractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !requestId
      || requestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
      || (
        traceparent !== null
        && traceparent.length > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
      )
      || (
        idempotencyKey !== null
        && idempotencyKey.length > MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH
      )
      || !Number.isInteger(attemptCount)
      || attemptCount < 0
      || !Number.isInteger(maxAttempts)
      || maxAttempts < 1
      || maxAttempts > 5
      || !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(status)
      || (
        failureCode !== null
        && failureCode.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH
      )
      || (
        failureDetail !== null
        && failureDetail.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH
      )
      || (
        lastHttpStatus !== null
        && (
          !Number.isInteger(lastHttpStatus)
          || lastHttpStatus < 100
          || lastHttpStatus > 599
        )
      )
      || payloadSnapshot === null
      || !createdAt
      || !updatedAt
    ) {
      return null;
    }
    if (
      nextRetryAt !== null
      && Number.isNaN(new Date(nextRetryAt).getTime())
    ) {
      return null;
    }
    if (
      lastAttemptAt !== null
      && Number.isNaN(new Date(lastAttemptAt).getTime())
    ) {
      return null;
    }
    return {
      recoveryId,
      integrationId,
      contractType,
      contractVersion,
      requestId,
      traceparent,
      idempotencyKey,
      attemptCount,
      maxAttempts,
      nextRetryAt,
      lastAttemptAt,
      status,
      failureCode,
      failureDetail,
      lastHttpStatus,
      retryable,
      payloadSnapshot,
      responseSnapshot,
      createdByUserId,
      updatedByUserId,
      createdAt,
      updatedAt
    };
  };

  const toPlatformIntegrationFreezeRecord = (row) => {
    if (!row) {
      return null;
    }
    const freezeId = normalizePlatformIntegrationFreezeId(row.freeze_id);
    const status = normalizePlatformIntegrationFreezeStatus(row.status);
    const freezeReason = normalizePlatformIntegrationOptionalText(row.freeze_reason);
    const rollbackReason = normalizePlatformIntegrationOptionalText(row.rollback_reason);
    const frozenAt = normalizeStoreIsoTimestamp(row.frozen_at);
    const releasedAt = normalizeStoreIsoTimestamp(row.released_at);
    const frozenByUserId = normalizePlatformIntegrationOptionalText(
      row.frozen_by_user_id
    );
    const releasedByUserId = normalizePlatformIntegrationOptionalText(
      row.released_by_user_id
    );
    const requestId = String(row.request_id || '').trim();
    const traceparent = normalizePlatformIntegrationOptionalText(row.traceparent);
    const createdAt = normalizeStoreIsoTimestamp(row.created_at);
    const updatedAt = normalizeStoreIsoTimestamp(row.updated_at);
    if (
      !freezeId
      || freezeId.length > MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH
      || !VALID_PLATFORM_INTEGRATION_FREEZE_STATUS.has(status)
      || !freezeReason
      || freezeReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
      || (
        rollbackReason !== null
        && rollbackReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
      )
      || !frozenAt
      || (
        releasedAt !== null
        && !releasedAt
      )
      || (
        status === 'active'
        && releasedAt !== null
      )
      || (
        status === 'released'
        && releasedAt === null
      )
      || (
        frozenByUserId !== null
        && frozenByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
      )
      || (
        releasedByUserId !== null
        && releasedByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
      )
      || !requestId
      || requestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
      || (
        traceparent !== null
        && traceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
      )
      || !createdAt
      || !updatedAt
    ) {
      return null;
    }
    return {
      freezeId,
      status,
      freezeReason,
      rollbackReason,
      frozenAt,
      releasedAt,
      frozenByUserId,
      releasedByUserId,
      requestId,
      traceparent,
      createdAt,
      updatedAt
    };
  };

  const findActivePlatformIntegrationFreezeRecordForWriteGate = async (queryClient) => {
    const rows = await queryClient.query(
      `
        SELECT freeze_id,
               status,
               freeze_reason,
               rollback_reason,
               frozen_at,
               released_at,
               frozen_by_user_id,
               released_by_user_id,
               request_id,
               traceparent,
               created_at,
               updated_at
        FROM platform_integration_freeze_control
        WHERE status = 'active'
        ORDER BY frozen_at DESC, freeze_id DESC
        LIMIT 1
        FOR UPDATE
      `
    );
    if (!Array.isArray(rows)) {
      throw new Error('platform integration freeze gate query malformed');
    }
    if (rows.length === 0) {
      return null;
    }
    const activeFreeze = toPlatformIntegrationFreezeRecord(rows[0]);
    if (!activeFreeze) {
      throw new Error('platform integration freeze gate row malformed');
    }
    return activeFreeze;
  };

  const assertPlatformIntegrationWriteAllowedByFreezeGate = async (queryClient) => {
    const activeFreeze = await findActivePlatformIntegrationFreezeRecordForWriteGate(queryClient);
    if (!activeFreeze) {
      return;
    }
    throw createPlatformIntegrationFreezeActiveConflictError({
      freezeId: activeFreeze.freezeId,
      frozenAt: activeFreeze.frozenAt,
      freezeReason: activeFreeze.freezeReason
    });
  };

  return {
    toSessionRecord,
    toRefreshRecord,
    toUserRecord,
    toPlatformRoleCatalogRecord,
    toPlatformIntegrationCatalogRecord,
    toPlatformIntegrationContractVersionRecord,
    toPlatformIntegrationContractCompatibilityCheckRecord,
    toPlatformIntegrationRecoveryQueueRecord,
    toPlatformIntegrationFreezeRecord,
    findActivePlatformIntegrationFreezeRecordForWriteGate,
    assertPlatformIntegrationWriteAllowedByFreezeGate
  };
};

module.exports = {
  createSharedMysqlAuthStoreRowProjectionRuntimeSupport
};
