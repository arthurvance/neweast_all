'use strict';

const createPlatformMemoryAuthStoreRuntimeBootstrap = (dependencies = {}) => {
  let {
    nextPlatformIntegrationContractVersionId = 1
  } = dependencies;

  const {
    CONTROL_CHAR_PATTERN,
    KNOWN_PLATFORM_PERMISSION_CODES,
    KNOWN_PLATFORM_PERMISSION_CODE_SET,
    MAX_OPERATOR_USER_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH,
    MAX_PLATFORM_INTEGRATION_BASE_URL_LENGTH,
    MAX_PLATFORM_INTEGRATION_CODE_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH,
    MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH,
    MAX_PLATFORM_INTEGRATION_ENDPOINT_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH,
    MAX_PLATFORM_INTEGRATION_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH,
    MAX_PLATFORM_INTEGRATION_NAME_LENGTH,
    MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH,
    MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH,
    MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH,
    MAX_PLATFORM_INTEGRATION_TIMEOUT_MS,
    MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH,
    MAX_PLATFORM_ROLE_CODE_LENGTH,
    MAX_PLATFORM_ROLE_NAME_LENGTH,
    PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS,
    VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT,
    VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS,
    VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE,
    VALID_PLATFORM_INTEGRATION_DIRECTION,
    VALID_PLATFORM_INTEGRATION_FREEZE_STATUS,
    VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS,
    VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS,
    VALID_PLATFORM_ROLE_CATALOG_SCOPE,
    VALID_PLATFORM_ROLE_CATALOG_STATUS,
    VALID_PLATFORM_ROLE_FACT_STATUS,
    domainsByUserId,
    isActiveLikeStatus,
    platformIntegrationCatalogById,
    platformIntegrationCatalogCodeIndex,
    platformIntegrationContractVersionsByKey,
    platformIntegrationFreezeById,
    platformIntegrationRecoveryDedupIndex,
    platformIntegrationRecoveryQueueByRecoveryId,
    platformPermissionsByUserId,
    platformProfilesByUserId,
    platformRoleCatalogById,
    platformRoleCatalogCodeIndex,
    platformRolePermissionGrantsByRoleId,
    platformRolesByUserId,
    toPlatformPermissionSnapshotFromCodes,
    usersById
  } = dependencies;

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
  const normalizePlatformIntegrationId = (integrationId) =>
    String(integrationId || '').trim().toLowerCase();
  const isValidPlatformIntegrationId = (integrationId) =>
    Boolean(integrationId) && integrationId.length <= MAX_PLATFORM_INTEGRATION_ID_LENGTH;
  const normalizePlatformIntegrationCode = (code) =>
    String(code || '').trim();
  const toPlatformIntegrationCodeKey = (code) =>
    normalizePlatformIntegrationCode(code).toLowerCase();
  const normalizePlatformIntegrationDirection = (direction) =>
    String(direction || '').trim().toLowerCase();
  const normalizePlatformIntegrationLifecycleStatus = (status) =>
    String(status || '').trim().toLowerCase();
  const normalizePlatformIntegrationContractType = (contractType) =>
    String(contractType || '').trim().toLowerCase();
  const normalizePlatformIntegrationContractVersion = (contractVersion) =>
    String(contractVersion || '').trim();
  const normalizePlatformIntegrationContractStatus = (status) =>
    String(status || '').trim().toLowerCase();
  const normalizePlatformIntegrationContractEvaluationResult = (evaluationResult) =>
    String(evaluationResult || '').trim().toLowerCase();
  const normalizePlatformIntegrationContractSchemaChecksum = (schemaChecksum) =>
    String(schemaChecksum || '').trim().toLowerCase();
  const normalizePlatformIntegrationRecoveryId = (recoveryId) =>
    String(recoveryId || '').trim().toLowerCase();
  const normalizePlatformIntegrationRecoveryStatus = (status) =>
    String(status || '').trim().toLowerCase();
  const normalizePlatformIntegrationFreezeId = (freezeId) =>
    String(freezeId || '').trim().toLowerCase();
  const normalizePlatformIntegrationFreezeStatus = (status) =>
    String(status || '').trim().toLowerCase();
  const normalizePlatformIntegrationRecoveryIdempotencyKey = (idempotencyKey) =>
    idempotencyKey === null || idempotencyKey === undefined
      ? ''
      : String(idempotencyKey || '').trim();
  const PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN = /^[a-f0-9]{64}$/;
  const toPlatformIntegrationContractVersionKey = ({
    integrationId,
    contractType,
    contractVersion
  } = {}) =>
    [
      normalizePlatformIntegrationId(integrationId),
      normalizePlatformIntegrationContractType(contractType),
      normalizePlatformIntegrationContractVersion(contractVersion)
    ].join('::');
  const toPlatformIntegrationContractScopeKey = ({
    integrationId,
    contractType
  } = {}) =>
    [
      normalizePlatformIntegrationId(integrationId),
      normalizePlatformIntegrationContractType(contractType)
    ].join('::');
  const toPlatformIntegrationRecoveryDedupKey = ({
    integrationId,
    contractType,
    contractVersion,
    requestId,
    idempotencyKey
  } = {}) =>
    [
      normalizePlatformIntegrationId(integrationId),
      normalizePlatformIntegrationContractType(contractType),
      normalizePlatformIntegrationContractVersion(contractVersion),
      String(requestId || '').trim(),
      normalizePlatformIntegrationRecoveryIdempotencyKey(idempotencyKey)
    ].join('::');
  const normalizePlatformIntegrationOptionalText = (value) => {
    if (value === null || value === undefined) {
      return null;
    }
    const normalized = String(value).trim();
    return normalized.length > 0 ? normalized : null;
  };
  const normalizePlatformIntegrationTimeoutMs = (timeoutMs) => {
    if (timeoutMs === null || timeoutMs === undefined) {
      return PLATFORM_INTEGRATION_DEFAULT_TIMEOUT_MS;
    }
    const parsed = Number(timeoutMs);
    return Number.isInteger(parsed) ? parsed : NaN;
  };
  const normalizePlatformIntegrationJsonForStorage = ({
    value,
    allowUndefined = false
  } = {}) => {
    if (value === undefined) {
      return allowUndefined ? undefined : null;
    }
    if (value === null) {
      return null;
    }
    if (typeof value === 'string') {
      const normalized = value.trim();
      if (!normalized) {
        return null;
      }
      try {
        return JSON.parse(normalized);
      } catch (_error) {
        return undefined;
      }
    }
    if (typeof value === 'object') {
      return structuredClone(value);
    }
    return undefined;
  };
  const createDuplicatePlatformIntegrationCatalogEntryError = ({
    target = 'code'
  } = {}) => {
    const normalizedTarget = String(target || '').trim().toLowerCase();
    const resolvedTarget = normalizedTarget === 'integration_id'
      ? 'integration_id'
      : 'code';
    const error = new Error(
      resolvedTarget === 'integration_id'
        ? 'duplicate platform integration catalog integration_id'
        : 'duplicate platform integration catalog code'
    );
    error.code = 'ER_DUP_ENTRY';
    error.errno = 1062;
    error.conflictTarget = resolvedTarget;
    error.platformIntegrationCatalogConflictTarget = resolvedTarget;
    return error;
  };
  const createDuplicatePlatformIntegrationContractVersionError = () => {
    const error = new Error('duplicate platform integration contract version');
    error.code = 'ER_DUP_ENTRY';
    error.errno = 1062;
    error.conflictTarget = 'contract_version';
    error.platformIntegrationContractConflictTarget = 'contract_version';
    return error;
  };
  const createPlatformIntegrationContractActivationBlockedError = ({
    integrationId = null,
    contractType = null,
    contractVersion = null,
    reason = 'activation-blocked'
  } = {}) => {
    const error = new Error('platform integration contract activation blocked');
    error.code = 'ERR_PLATFORM_INTEGRATION_CONTRACT_ACTIVATION_BLOCKED';
    error.integrationId = normalizePlatformIntegrationId(integrationId) || null;
    error.contractType =
      normalizePlatformIntegrationContractType(contractType) || null;
    error.contractVersion =
      normalizePlatformIntegrationContractVersion(contractVersion) || null;
    error.reason = String(reason || 'activation-blocked').trim().toLowerCase();
    return error;
  };
  const isPlatformIntegrationLifecycleTransitionAllowed = ({
    previousStatus,
    nextStatus
  } = {}) => {
    const normalizedPreviousStatus = normalizePlatformIntegrationLifecycleStatus(
      previousStatus
    );
    const normalizedNextStatus = normalizePlatformIntegrationLifecycleStatus(
      nextStatus
    );
    if (
      !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedPreviousStatus)
      || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedNextStatus)
    ) {
      return false;
    }
    if (normalizedPreviousStatus === normalizedNextStatus) {
      return false;
    }
    if (normalizedPreviousStatus === 'draft') {
      return normalizedNextStatus === 'active' || normalizedNextStatus === 'retired';
    }
    if (normalizedPreviousStatus === 'active') {
      return normalizedNextStatus === 'paused' || normalizedNextStatus === 'retired';
    }
    if (normalizedPreviousStatus === 'paused') {
      return normalizedNextStatus === 'active' || normalizedNextStatus === 'retired';
    }
    return false;
  };
  const createPlatformIntegrationLifecycleConflictError = ({
    integrationId = null,
    previousStatus = null,
    requestedStatus = null
  } = {}) => {
    const error = new Error('platform integration lifecycle transition conflict');
    error.code = 'ERR_PLATFORM_INTEGRATION_LIFECYCLE_CONFLICT';
    error.integrationId = normalizePlatformIntegrationId(integrationId) || null;
    error.previousStatus =
      normalizePlatformIntegrationLifecycleStatus(previousStatus) || null;
    error.requestedStatus =
      normalizePlatformIntegrationLifecycleStatus(requestedStatus) || null;
    return error;
  };
  const createPlatformIntegrationRecoveryReplayConflictError = ({
    integrationId = null,
    recoveryId = null,
    previousStatus = null,
    requestedStatus = 'replayed'
  } = {}) => {
    const error = new Error('platform integration recovery replay conflict');
    error.code = 'ERR_PLATFORM_INTEGRATION_RECOVERY_REPLAY_CONFLICT';
    error.integrationId = normalizePlatformIntegrationId(integrationId) || null;
    error.recoveryId = normalizePlatformIntegrationRecoveryId(recoveryId) || null;
    error.previousStatus =
      normalizePlatformIntegrationRecoveryStatus(previousStatus) || null;
    error.requestedStatus =
      normalizePlatformIntegrationRecoveryStatus(requestedStatus) || 'replayed';
    return error;
  };
  const createPlatformIntegrationFreezeActiveConflictError = ({
    freezeId = null,
    frozenAt = null,
    freezeReason = null
  } = {}) => {
    const error = new Error('platform integration freeze already active');
    error.code = 'ERR_PLATFORM_INTEGRATION_FREEZE_ACTIVE_CONFLICT';
    error.freezeId = normalizePlatformIntegrationFreezeId(freezeId) || null;
    error.frozenAt = String(frozenAt || '').trim() || null;
    error.freezeReason = normalizePlatformIntegrationOptionalText(freezeReason) || null;
    return error;
  };
  const createPlatformIntegrationFreezeReleaseConflictError = () => {
    const error = new Error('platform integration freeze release conflict');
    error.code = 'ERR_PLATFORM_INTEGRATION_FREEZE_RELEASE_CONFLICT';
    return error;
  };
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
  const toPlatformIntegrationCatalogRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedCode = normalizePlatformIntegrationCode(entry.code);
    const normalizedDirection = normalizePlatformIntegrationDirection(
      entry.direction
    );
    const normalizedLifecycleStatus = normalizePlatformIntegrationLifecycleStatus(
      entry.lifecycleStatus || entry.lifecycle_status || 'draft'
    );
    const normalizedProtocol = String(entry.protocol || '').trim();
    const normalizedAuthMode = String(entry.authMode || entry.auth_mode || '').trim();
    const normalizedName = String(entry.name || '').trim();
    const normalizedTimeoutMs = normalizePlatformIntegrationTimeoutMs(
      entry.timeoutMs ?? entry.timeout_ms
    );
    const normalizedEndpoint = normalizePlatformIntegrationOptionalText(entry.endpoint);
    const normalizedBaseUrl = normalizePlatformIntegrationOptionalText(
      entry.baseUrl || entry.base_url
    );
    const normalizedVersionStrategy = normalizePlatformIntegrationOptionalText(
      entry.versionStrategy || entry.version_strategy
    );
    const normalizedRunbookUrl = normalizePlatformIntegrationOptionalText(
      entry.runbookUrl || entry.runbook_url
    );
    const normalizedLifecycleReason = normalizePlatformIntegrationOptionalText(
      entry.lifecycleReason || entry.lifecycle_reason
    );
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !normalizedCode
      || normalizedCode.length > MAX_PLATFORM_INTEGRATION_CODE_LENGTH
      || !normalizedName
      || normalizedName.length > MAX_PLATFORM_INTEGRATION_NAME_LENGTH
      || !VALID_PLATFORM_INTEGRATION_DIRECTION.has(normalizedDirection)
      || !normalizedProtocol
      || normalizedProtocol.length > MAX_PLATFORM_INTEGRATION_PROTOCOL_LENGTH
      || !normalizedAuthMode
      || normalizedAuthMode.length > MAX_PLATFORM_INTEGRATION_AUTH_MODE_LENGTH
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
        && normalizedVersionStrategy.length
          > MAX_PLATFORM_INTEGRATION_VERSION_STRATEGY_LENGTH
      )
      || (
        normalizedRunbookUrl !== null
        && normalizedRunbookUrl.length > MAX_PLATFORM_INTEGRATION_RUNBOOK_URL_LENGTH
      )
      || (
        normalizedLifecycleReason !== null
        && normalizedLifecycleReason.length > MAX_PLATFORM_INTEGRATION_LIFECYCLE_REASON_LENGTH
      )
      || !VALID_PLATFORM_INTEGRATION_LIFECYCLE_STATUS.has(normalizedLifecycleStatus)
      || !Number.isInteger(normalizedTimeoutMs)
      || normalizedTimeoutMs < 1
      || normalizedTimeoutMs > MAX_PLATFORM_INTEGRATION_TIMEOUT_MS
    ) {
      throw new Error('invalid platform integration catalog entry');
    }
    const normalizedRetryPolicy = normalizePlatformIntegrationJsonForStorage({
      value: entry.retryPolicy ?? entry.retry_policy
    });
    const normalizedIdempotencyPolicy = normalizePlatformIntegrationJsonForStorage({
      value: entry.idempotencyPolicy ?? entry.idempotency_policy
    });
    if (
      normalizedRetryPolicy === undefined
      || normalizedIdempotencyPolicy === undefined
    ) {
      throw new Error('invalid platform integration policy payload');
    }
    return {
      integrationId: normalizedIntegrationId,
      code: normalizedCode,
      codeNormalized: toPlatformIntegrationCodeKey(normalizedCode),
      name: normalizedName,
      direction: normalizedDirection,
      protocol: normalizedProtocol,
      authMode: normalizedAuthMode,
      endpoint: normalizedEndpoint,
      baseUrl: normalizedBaseUrl,
      timeoutMs: normalizedTimeoutMs,
      retryPolicy: normalizedRetryPolicy,
      idempotencyPolicy: normalizedIdempotencyPolicy,
      versionStrategy: normalizedVersionStrategy,
      runbookUrl: normalizedRunbookUrl,
      lifecycleStatus: normalizedLifecycleStatus,
      lifecycleReason: normalizedLifecycleReason,
      createdByUserId: normalizePlatformIntegrationOptionalText(
        entry.createdByUserId || entry.created_by_user_id
      ),
      updatedByUserId: normalizePlatformIntegrationOptionalText(
        entry.updatedByUserId || entry.updated_by_user_id
      ),
      createdAt:
        entry.createdAt || entry.created_at || new Date().toISOString(),
      updatedAt:
        entry.updatedAt || entry.updated_at || new Date().toISOString()
    };
  };
  const clonePlatformIntegrationCatalogRecord = (entry = null) =>
    entry
      ? {
        integrationId: entry.integrationId,
        code: entry.code,
        codeNormalized: entry.codeNormalized,
        name: entry.name,
        direction: entry.direction,
        protocol: entry.protocol,
        authMode: entry.authMode,
        endpoint: entry.endpoint,
        baseUrl: entry.baseUrl,
        timeoutMs: entry.timeoutMs,
        retryPolicy: entry.retryPolicy ? structuredClone(entry.retryPolicy) : null,
        idempotencyPolicy: entry.idempotencyPolicy
          ? structuredClone(entry.idempotencyPolicy)
          : null,
        versionStrategy: entry.versionStrategy,
        runbookUrl: entry.runbookUrl,
        lifecycleStatus: entry.lifecycleStatus,
        lifecycleReason: entry.lifecycleReason,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationContractVersionRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedContractVersion = normalizePlatformIntegrationContractVersion(
      entry.contractVersion || entry.contract_version
    );
    const normalizedSchemaRef = normalizePlatformIntegrationOptionalText(
      entry.schemaRef || entry.schema_ref
    );
    const normalizedSchemaChecksum = normalizePlatformIntegrationContractSchemaChecksum(
      entry.schemaChecksum || entry.schema_checksum
    );
    const normalizedStatus = normalizePlatformIntegrationContractStatus(
      entry.status || 'candidate'
    );
    const normalizedCompatibilityNotes = normalizePlatformIntegrationOptionalText(
      entry.compatibilityNotes || entry.compatibility_notes
    );
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !normalizedSchemaRef
      || normalizedSchemaRef.length > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_REF_LENGTH
      || !normalizedSchemaChecksum
      || normalizedSchemaChecksum.length
        > MAX_PLATFORM_INTEGRATION_CONTRACT_SCHEMA_CHECKSUM_LENGTH
      || !PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN.test(normalizedSchemaChecksum)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_STATUS.has(normalizedStatus)
      || (
        normalizedCompatibilityNotes !== null
        && normalizedCompatibilityNotes.length
          > MAX_PLATFORM_INTEGRATION_CONTRACT_COMPATIBILITY_NOTES_LENGTH
      )
    ) {
      throw new Error('invalid platform integration contract version entry');
    }
    return {
      contractId: Number(entry.contractId || entry.contract_id || 0) || 0,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion,
      schemaRef: normalizedSchemaRef,
      schemaChecksum: normalizedSchemaChecksum,
      status: normalizedStatus,
      isBackwardCompatible: Boolean(
        entry.isBackwardCompatible ?? entry.is_backward_compatible
      ),
      compatibilityNotes: normalizedCompatibilityNotes,
      createdByUserId: normalizePlatformIntegrationOptionalText(
        entry.createdByUserId || entry.created_by_user_id
      ),
      updatedByUserId: normalizePlatformIntegrationOptionalText(
        entry.updatedByUserId || entry.updated_by_user_id
      ),
      createdAt: entry.createdAt || entry.created_at || new Date().toISOString(),
      updatedAt: entry.updatedAt || entry.updated_at || new Date().toISOString()
    };
  };
  const clonePlatformIntegrationContractVersionRecord = (entry = null) =>
    entry
      ? {
        contractId: Number(entry.contractId),
        integrationId: entry.integrationId,
        contractType: entry.contractType,
        contractVersion: entry.contractVersion,
        schemaRef: entry.schemaRef,
        schemaChecksum: entry.schemaChecksum,
        status: entry.status,
        isBackwardCompatible: Boolean(entry.isBackwardCompatible),
        compatibilityNotes: entry.compatibilityNotes,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationContractCompatibilityCheckRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedBaselineVersion = normalizePlatformIntegrationContractVersion(
      entry.baselineVersion || entry.baseline_version
    );
    const normalizedCandidateVersion = normalizePlatformIntegrationContractVersion(
      entry.candidateVersion || entry.candidate_version
    );
    const normalizedEvaluationResult = normalizePlatformIntegrationContractEvaluationResult(
      entry.evaluationResult || entry.evaluation_result
    );
    const normalizedBreakingChangeCount = Number(
      entry.breakingChangeCount ?? entry.breaking_change_count
    );
    const normalizedRequestId = String(entry.requestId || entry.request_id || '').trim();
    const normalizedCheckedAt = String(entry.checkedAt || entry.checked_at || '').trim()
      || new Date().toISOString();
    const normalizedDiffSummary = normalizePlatformIntegrationJsonForStorage({
      value: entry.diffSummary ?? entry.diff_summary
    });
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedBaselineVersion
      || normalizedBaselineVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !normalizedCandidateVersion
      || normalizedCandidateVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT.has(normalizedEvaluationResult)
      || !Number.isInteger(normalizedBreakingChangeCount)
      || normalizedBreakingChangeCount < 0
      || !normalizedRequestId
      || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
      || normalizedDiffSummary === undefined
      || (
        normalizedDiffSummary !== null
        && JSON.stringify(normalizedDiffSummary).length
          > MAX_PLATFORM_INTEGRATION_CONTRACT_DIFF_SUMMARY_LENGTH
      )
    ) {
      throw new Error('invalid platform integration contract compatibility check entry');
    }
    return {
      checkId: Number(entry.checkId || entry.check_id || 0) || 0,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      baselineVersion: normalizedBaselineVersion,
      candidateVersion: normalizedCandidateVersion,
      evaluationResult: normalizedEvaluationResult,
      breakingChangeCount: normalizedBreakingChangeCount,
      diffSummary: normalizedDiffSummary,
      requestId: normalizedRequestId,
      checkedByUserId: normalizePlatformIntegrationOptionalText(
        entry.checkedByUserId || entry.checked_by_user_id
      ),
      checkedAt: normalizedCheckedAt
    };
  };
  const clonePlatformIntegrationContractCompatibilityCheckRecord = (entry = null) =>
    entry
      ? {
        checkId: Number(entry.checkId),
        integrationId: entry.integrationId,
        contractType: entry.contractType,
        baselineVersion: entry.baselineVersion,
        candidateVersion: entry.candidateVersion,
        evaluationResult: entry.evaluationResult,
        breakingChangeCount: Number(entry.breakingChangeCount),
        diffSummary: entry.diffSummary ? structuredClone(entry.diffSummary) : null,
        requestId: entry.requestId,
        checkedByUserId: entry.checkedByUserId,
        checkedAt: entry.checkedAt
      }
      : null;
  const toPlatformIntegrationRecoveryQueueRecord = (entry = {}) => {
    const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(
      entry.recoveryId || entry.recovery_id
    );
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedContractVersion = normalizePlatformIntegrationContractVersion(
      entry.contractVersion || entry.contract_version
    );
    const normalizedRequestId = String(
      entry.requestId || entry.request_id || ''
    ).trim();
    const normalizedTraceparent = normalizePlatformIntegrationOptionalText(
      entry.traceparent
    );
    const normalizedIdempotencyKey = normalizePlatformIntegrationRecoveryIdempotencyKey(
      entry.idempotencyKey ?? entry.idempotency_key
    );
    const normalizedAttemptCount = Number(
      entry.attemptCount ?? entry.attempt_count ?? 0
    );
    const normalizedMaxAttempts = Number(
      entry.maxAttempts ?? entry.max_attempts ?? 5
    );
    const normalizedStatus = normalizePlatformIntegrationRecoveryStatus(
      entry.status || 'pending'
    );
    const normalizedFailureCode = normalizePlatformIntegrationOptionalText(
      entry.failureCode || entry.failure_code
    );
    const normalizedFailureDetail = normalizePlatformIntegrationOptionalText(
      entry.failureDetail || entry.failure_detail
    );
    const normalizedLastHttpStatus =
      (entry.lastHttpStatus === undefined || entry.lastHttpStatus === null)
      && (entry.last_http_status === undefined || entry.last_http_status === null)
        ? null
        : Number(entry.lastHttpStatus ?? entry.last_http_status);
    const normalizedRetryable = Boolean(entry.retryable ?? true);
    const normalizedPayloadSnapshot = normalizePlatformIntegrationJsonForStorage({
      value: entry.payloadSnapshot ?? entry.payload_snapshot
    });
    const normalizedResponseSnapshot = normalizePlatformIntegrationJsonForStorage({
      value: entry.responseSnapshot ?? entry.response_snapshot
    });
    const normalizedNextRetryAtRaw = entry.nextRetryAt ?? entry.next_retry_at;
    const normalizedLastAttemptAtRaw = entry.lastAttemptAt ?? entry.last_attempt_at;
    const normalizedNextRetryAt =
      normalizedNextRetryAtRaw === null || normalizedNextRetryAtRaw === undefined
        ? null
        : new Date(normalizedNextRetryAtRaw).toISOString();
    const normalizedLastAttemptAt =
      normalizedLastAttemptAtRaw === null || normalizedLastAttemptAtRaw === undefined
        ? null
        : new Date(normalizedLastAttemptAtRaw).toISOString();
    const normalizedCreatedAt = String(
      entry.createdAt || entry.created_at || new Date().toISOString()
    ).trim();
    const normalizedUpdatedAt = String(
      entry.updatedAt || entry.updated_at || new Date().toISOString()
    ).trim();
    if (
      !normalizedRecoveryId
      || normalizedRecoveryId.length > MAX_PLATFORM_INTEGRATION_RECOVERY_ID_LENGTH
      || !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
      || !normalizedRequestId
      || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_CONTRACT_REQUEST_ID_LENGTH
      || (
        normalizedTraceparent !== null
        && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_RECOVERY_TRACEPARENT_LENGTH
      )
      || normalizedIdempotencyKey.length > MAX_PLATFORM_INTEGRATION_RECOVERY_IDEMPOTENCY_KEY_LENGTH
      || !Number.isInteger(normalizedAttemptCount)
      || normalizedAttemptCount < 0
      || !Number.isInteger(normalizedMaxAttempts)
      || normalizedMaxAttempts < 1
      || normalizedMaxAttempts > 5
      || !VALID_PLATFORM_INTEGRATION_RECOVERY_STATUS.has(normalizedStatus)
      || (
        normalizedFailureCode !== null
        && normalizedFailureCode.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_CODE_LENGTH
      )
      || (
        normalizedFailureDetail !== null
        && normalizedFailureDetail.length > MAX_PLATFORM_INTEGRATION_RECOVERY_FAILURE_DETAIL_LENGTH
      )
      || (
        normalizedLastHttpStatus !== null
        && (
          !Number.isInteger(normalizedLastHttpStatus)
          || normalizedLastHttpStatus < 100
          || normalizedLastHttpStatus > 599
        )
      )
      || normalizedPayloadSnapshot === undefined
      || normalizedPayloadSnapshot === null
      || normalizedResponseSnapshot === undefined
      || !normalizedCreatedAt
      || !normalizedUpdatedAt
      || (
        normalizedNextRetryAt !== null
        && Number.isNaN(new Date(normalizedNextRetryAt).getTime())
      )
      || (
        normalizedLastAttemptAt !== null
        && Number.isNaN(new Date(normalizedLastAttemptAt).getTime())
      )
    ) {
      throw new Error('invalid platform integration recovery queue entry');
    }
    return {
      recoveryId: normalizedRecoveryId,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion,
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      idempotencyKey: normalizedIdempotencyKey || null,
      attemptCount: normalizedAttemptCount,
      maxAttempts: normalizedMaxAttempts,
      nextRetryAt: normalizedNextRetryAt,
      lastAttemptAt: normalizedLastAttemptAt,
      status: normalizedStatus,
      failureCode: normalizedFailureCode,
      failureDetail: normalizedFailureDetail,
      lastHttpStatus: normalizedLastHttpStatus,
      retryable: normalizedRetryable,
      payloadSnapshot: normalizedPayloadSnapshot,
      responseSnapshot: normalizedResponseSnapshot,
      createdByUserId: normalizePlatformIntegrationOptionalText(
        entry.createdByUserId || entry.created_by_user_id
      ),
      updatedByUserId: normalizePlatformIntegrationOptionalText(
        entry.updatedByUserId || entry.updated_by_user_id
      ),
      createdAt: normalizedCreatedAt,
      updatedAt: normalizedUpdatedAt
    };
  };
  const clonePlatformIntegrationRecoveryQueueRecord = (entry = null) =>
    entry
      ? {
        recoveryId: entry.recoveryId,
        integrationId: entry.integrationId,
        contractType: entry.contractType,
        contractVersion: entry.contractVersion,
        requestId: entry.requestId,
        traceparent: entry.traceparent,
        idempotencyKey: entry.idempotencyKey,
        attemptCount: Number(entry.attemptCount),
        maxAttempts: Number(entry.maxAttempts),
        nextRetryAt: entry.nextRetryAt,
        lastAttemptAt: entry.lastAttemptAt,
        status: entry.status,
        failureCode: entry.failureCode,
        failureDetail: entry.failureDetail,
        lastHttpStatus: entry.lastHttpStatus,
        retryable: Boolean(entry.retryable),
        payloadSnapshot: entry.payloadSnapshot
          ? structuredClone(entry.payloadSnapshot)
          : null,
        responseSnapshot: entry.responseSnapshot
          ? structuredClone(entry.responseSnapshot)
          : null,
        createdByUserId: entry.createdByUserId,
        updatedByUserId: entry.updatedByUserId,
        createdAt: entry.createdAt,
        updatedAt: entry.updatedAt
      }
      : null;
  const toPlatformIntegrationFreezeRecord = (entry = {}) => {
    const normalizedFreezeId = normalizePlatformIntegrationFreezeId(
      entry.freezeId || entry.freeze_id
    );
    const normalizedStatus = normalizePlatformIntegrationFreezeStatus(
      entry.status || 'active'
    );
    const normalizedFreezeReason = normalizePlatformIntegrationOptionalText(
      entry.freezeReason || entry.freeze_reason
    );
    const normalizedRollbackReason = normalizePlatformIntegrationOptionalText(
      entry.rollbackReason || entry.rollback_reason
    );
    const normalizedFrozenAt = String(
      entry.frozenAt || entry.frozen_at || new Date().toISOString()
    ).trim();
    const releasedAtRaw = entry.releasedAt ?? entry.released_at ?? null;
    const normalizedReleasedAt =
      releasedAtRaw === null || releasedAtRaw === undefined
        ? null
        : new Date(releasedAtRaw).toISOString();
    const normalizedRequestId = String(
      entry.requestId || entry.request_id || ''
    ).trim();
    const normalizedTraceparent = normalizePlatformIntegrationOptionalText(
      entry.traceparent
    );
    const normalizedCreatedAt = String(
      entry.createdAt || entry.created_at || new Date().toISOString()
    ).trim();
    const normalizedUpdatedAt = String(
      entry.updatedAt || entry.updated_at || new Date().toISOString()
    ).trim();
    const normalizedFrozenByUserId = normalizePlatformIntegrationOptionalText(
      entry.frozenByUserId || entry.frozen_by_user_id
    );
    const normalizedReleasedByUserId = normalizePlatformIntegrationOptionalText(
      entry.releasedByUserId || entry.released_by_user_id
    );
    if (
      !normalizedFreezeId
      || normalizedFreezeId.length > MAX_PLATFORM_INTEGRATION_FREEZE_ID_LENGTH
      || !VALID_PLATFORM_INTEGRATION_FREEZE_STATUS.has(normalizedStatus)
      || !normalizedFreezeReason
      || normalizedFreezeReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
      || (
        normalizedRollbackReason !== null
        && normalizedRollbackReason.length > MAX_PLATFORM_INTEGRATION_FREEZE_REASON_LENGTH
      )
      || !normalizedFrozenAt
      || Number.isNaN(new Date(normalizedFrozenAt).getTime())
      || (
        normalizedReleasedAt !== null
        && Number.isNaN(new Date(normalizedReleasedAt).getTime())
      )
      || (
        normalizedStatus === 'active'
        && normalizedReleasedAt !== null
      )
      || (
        normalizedStatus === 'released'
        && normalizedReleasedAt === null
      )
      || (
        normalizedFrozenByUserId !== null
        && normalizedFrozenByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
      )
      || (
        normalizedReleasedByUserId !== null
        && normalizedReleasedByUserId.length > MAX_OPERATOR_USER_ID_LENGTH
      )
      || !normalizedRequestId
      || normalizedRequestId.length > MAX_PLATFORM_INTEGRATION_FREEZE_REQUEST_ID_LENGTH
      || (
        normalizedTraceparent !== null
        && normalizedTraceparent.length > MAX_PLATFORM_INTEGRATION_FREEZE_TRACEPARENT_LENGTH
      )
      || !normalizedCreatedAt
      || Number.isNaN(new Date(normalizedCreatedAt).getTime())
      || !normalizedUpdatedAt
      || Number.isNaN(new Date(normalizedUpdatedAt).getTime())
    ) {
      throw new Error('invalid platform integration freeze entry');
    }
    return {
      freezeId: normalizedFreezeId,
      status: normalizedStatus,
      freezeReason: normalizedFreezeReason,
      rollbackReason: normalizedRollbackReason,
      frozenAt: normalizedFrozenAt,
      releasedAt: normalizedReleasedAt,
      frozenByUserId: normalizedFrozenByUserId,
      releasedByUserId: normalizedReleasedByUserId,
      requestId: normalizedRequestId,
      traceparent: normalizedTraceparent,
      createdAt: normalizedCreatedAt,
      updatedAt: normalizedUpdatedAt
    };
  };
  const clonePlatformIntegrationFreezeRecord = (entry = null) =>
    entry
      ? {
        freezeId: entry.freezeId,
        status: entry.status,
        freezeReason: entry.freezeReason,
        rollbackReason: entry.rollbackReason,
        frozenAt: entry.frozenAt,
        releasedAt: entry.releasedAt,
        frozenByUserId: entry.frozenByUserId,
        releasedByUserId: entry.releasedByUserId,
        requestId: entry.requestId,
        traceparent: entry.traceparent,
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
  const findPlatformIntegrationCatalogRecordStateByIntegrationId = (
    integrationId
  ) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(integrationId);
    if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
      return null;
    }
    if (platformIntegrationCatalogById.has(normalizedIntegrationId)) {
      return {
        integrationId: normalizedIntegrationId,
        record: platformIntegrationCatalogById.get(normalizedIntegrationId)
      };
    }
    return null;
  };
  const findPlatformIntegrationContractVersionRecordState = ({
    integrationId,
    contractType,
    contractVersion
  } = {}) => {
    const contractKey = toPlatformIntegrationContractVersionKey({
      integrationId,
      contractType,
      contractVersion
    });
    if (!platformIntegrationContractVersionsByKey.has(contractKey)) {
      return null;
    }
    return {
      key: contractKey,
      record: platformIntegrationContractVersionsByKey.get(contractKey)
    };
  };
  const findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId = (
    recoveryId
  ) => {
    const normalizedRecoveryId = normalizePlatformIntegrationRecoveryId(recoveryId);
    if (!normalizedRecoveryId) {
      return null;
    }
    if (!platformIntegrationRecoveryQueueByRecoveryId.has(normalizedRecoveryId)) {
      return null;
    }
    return {
      recoveryId: normalizedRecoveryId,
      record: platformIntegrationRecoveryQueueByRecoveryId.get(normalizedRecoveryId)
    };
  };
  const findPlatformIntegrationRecoveryQueueRecordStateByDedupKey = ({
    integrationId,
    contractType,
    contractVersion,
    requestId,
    idempotencyKey
  } = {}) => {
    const dedupKey = toPlatformIntegrationRecoveryDedupKey({
      integrationId,
      contractType,
      contractVersion,
      requestId,
      idempotencyKey
    });
    const recoveryId = platformIntegrationRecoveryDedupIndex.get(dedupKey);
    if (!recoveryId) {
      return null;
    }
    return findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(recoveryId);
  };
  const comparePlatformIntegrationFreezeRecords = (left, right) => {
    const leftFrozenAt = new Date(left?.frozenAt || 0).getTime();
    const rightFrozenAt = new Date(right?.frozenAt || 0).getTime();
    if (leftFrozenAt !== rightFrozenAt) {
      return rightFrozenAt - leftFrozenAt;
    }
    return String(right?.freezeId || '').localeCompare(String(left?.freezeId || ''));
  };
  const findActivePlatformIntegrationFreezeRecordState = () => {
    const activeEntries = [];
    for (const [freezeId, entry] of platformIntegrationFreezeById.entries()) {
      if (entry?.status !== 'active') {
        continue;
      }
      activeEntries.push({
        freezeId,
        record: entry
      });
    }
    if (activeEntries.length === 0) {
      return null;
    }
    activeEntries.sort((left, right) =>
      comparePlatformIntegrationFreezeRecords(left.record, right.record)
    );
    return activeEntries[0];
  };
  const findLatestPlatformIntegrationFreezeRecordState = () => {
    const entries = [];
    for (const [freezeId, record] of platformIntegrationFreezeById.entries()) {
      entries.push({
        freezeId,
        record
      });
    }
    if (entries.length === 0) {
      return null;
    }
    entries.sort((left, right) =>
      comparePlatformIntegrationFreezeRecords(left.record, right.record)
    );
    return entries[0];
  };
  const findActivePlatformIntegrationFreezeForWriteGate = () => {
    const activeState = findActivePlatformIntegrationFreezeRecordState();
    if (!activeState?.record) {
      return null;
    }
    const activeFreeze = toPlatformIntegrationFreezeRecord(activeState.record);
    if (!activeFreeze) {
      throw new Error('platform integration freeze gate state malformed');
    }
    return activeFreeze;
  };
  const assertPlatformIntegrationWriteAllowedByFreezeGate = () => {
    const activeFreeze = findActivePlatformIntegrationFreezeForWriteGate();
    if (!activeFreeze) {
      return;
    }
    throw createPlatformIntegrationFreezeActiveConflictError({
      freezeId: activeFreeze.freezeId,
      frozenAt: activeFreeze.frozenAt,
      freezeReason: activeFreeze.freezeReason
    });
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
      canViewUserManagement: Boolean(
        permission.canViewUserManagement ?? permission.can_view_user_management
      ),
      canOperateUserManagement: Boolean(
        permission.canOperateUserManagement ?? permission.can_operate_user_management
      ),
      canViewTenantManagement: Boolean(permission.canViewTenantManagement ?? permission.can_view_tenant_management),
      canOperateTenantManagement: Boolean(
        permission.canOperateTenantManagement ?? permission.can_operate_tenant_management
      ),
      canViewRoleManagement: Boolean(
        permission.canViewRoleManagement ?? permission.can_view_role_management
      ),
      canOperateRoleManagement: Boolean(
        permission.canOperateRoleManagement ?? permission.can_operate_role_management
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
      canViewUserManagement:
        Boolean(left.canViewUserManagement) || Boolean(right.canViewUserManagement),
      canOperateUserManagement:
        Boolean(left.canOperateUserManagement) || Boolean(right.canOperateUserManagement),
      canViewTenantManagement: Boolean(left.canViewTenantManagement) || Boolean(right.canViewTenantManagement),
      canOperateTenantManagement:
        Boolean(left.canOperateTenantManagement) || Boolean(right.canOperateTenantManagement),
      canViewRoleManagement:
        Boolean(left.canViewRoleManagement) || Boolean(right.canViewRoleManagement),
      canOperateRoleManagement:
        Boolean(left.canOperateRoleManagement) || Boolean(right.canOperateRoleManagement)
    };
  };

  const buildEmptyPlatformPermission = (scopeLabel = '平台权限（角色并集）') => ({
    scopeLabel,
    canViewUserManagement: false,
    canOperateUserManagement: false,
    canViewTenantManagement: false,
    canOperateTenantManagement: false,
    canViewRoleManagement: false,
    canOperateRoleManagement: false
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
    return {
      ...buildEmptyPlatformPermission(),
      ...toPlatformPermissionSnapshotFromCodes(
        normalizePlatformPermissionCodes(permissionCodes)
      )
    };
  };
  const createPlatformRolePermissionGrantDataError = (
    reason = 'platform-role-permission-grants-invalid'
  ) => {
    const error = new Error('platform role permission grants invalid');
    error.code = 'ERR_PLATFORM_ROLE_PERMISSION_GRANTS_INVALID';
    error.reason = String(reason || 'platform-role-permission-grants-invalid')
      .trim()
      .toLowerCase();
    return error;
  };

  const listPlatformRolePermissionGrantsForRoleId = (roleId) => {
    const normalizedRoleId = normalizePlatformRoleCatalogRoleId(roleId);
    if (!normalizedRoleId) {
      return [];
    }
    const normalizedPermissionCodeKeys = [];
    const seenPermissionCodeKeys = new Set();
    for (const permissionCode of platformRolePermissionGrantsByRoleId.get(normalizedRoleId) || []) {
      if (typeof permissionCode !== 'string') {
        throw createPlatformRolePermissionGrantDataError(
          'platform-role-permission-grants-invalid-permission-code'
        );
      }
      const normalizedPermissionCode = normalizePlatformPermissionCode(permissionCode);
      const permissionCodeKey = toPlatformPermissionCodeKey(normalizedPermissionCode);
      if (
        permissionCode !== normalizedPermissionCode
        || !normalizedPermissionCode
        || CONTROL_CHAR_PATTERN.test(normalizedPermissionCode)
        || !KNOWN_PLATFORM_PERMISSION_CODE_SET.has(permissionCodeKey)
      ) {
        throw createPlatformRolePermissionGrantDataError(
          'platform-role-permission-grants-invalid-permission-code'
        );
      }
      if (seenPermissionCodeKeys.has(permissionCodeKey)) {
        throw createPlatformRolePermissionGrantDataError(
          'platform-role-permission-grants-duplicate-permission-code'
        );
      }
      seenPermissionCodeKeys.add(permissionCodeKey);
      normalizedPermissionCodeKeys.push(permissionCodeKey);
    }
    return normalizedPermissionCodeKeys.sort((left, right) => left.localeCompare(right));
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

  const isSamePlatformPermission = (left, right) => {
    const normalizedLeft = left || buildEmptyPlatformPermission();
    const normalizedRight = right || buildEmptyPlatformPermission();
    return (
      Boolean(normalizedLeft.canViewUserManagement) === Boolean(normalizedRight.canViewUserManagement)
      && Boolean(normalizedLeft.canOperateUserManagement) === Boolean(normalizedRight.canOperateUserManagement)
      && Boolean(normalizedLeft.canViewTenantManagement) === Boolean(normalizedRight.canViewTenantManagement)
      && Boolean(normalizedLeft.canOperateTenantManagement) === Boolean(normalizedRight.canOperateTenantManagement)
      && Boolean(normalizedLeft.canViewRoleManagement) === Boolean(normalizedRight.canViewRoleManagement)
      && Boolean(normalizedLeft.canOperateRoleManagement)
        === Boolean(normalizedRight.canOperateRoleManagement)
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
      || permissionSource?.canViewUserManagement !== undefined
      || permissionSource?.can_view_user_management !== undefined
      || permissionSource?.canOperateUserManagement !== undefined
      || permissionSource?.can_operate_user_management !== undefined
      || permissionSource?.canViewTenantManagement !== undefined
      || permissionSource?.can_view_tenant_management !== undefined
      || permissionSource?.canOperateTenantManagement !== undefined
      || permissionSource?.can_operate_tenant_management !== undefined
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
  const upsertPlatformIntegrationCatalogRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    if (!isValidPlatformIntegrationId(normalizedIntegrationId)) {
      throw new Error('platform integration catalog entry requires integrationId');
    }
    const normalizedCode = normalizePlatformIntegrationCode(entry.code);
    if (!normalizedCode) {
      throw new Error('platform integration catalog entry requires code');
    }
    const codeKey = toPlatformIntegrationCodeKey(normalizedCode);
    const existingState = findPlatformIntegrationCatalogRecordStateByIntegrationId(
      normalizedIntegrationId
    );
    const existing = existingState?.record || null;
    const existingIntegrationIdForCode =
      platformIntegrationCatalogCodeIndex.get(codeKey);
    if (
      existingIntegrationIdForCode
      && normalizePlatformIntegrationId(existingIntegrationIdForCode)
        !== normalizedIntegrationId
    ) {
      throw createDuplicatePlatformIntegrationCatalogEntryError({
        target: 'code'
      });
    }
    if (existing && existing.codeNormalized !== codeKey) {
      platformIntegrationCatalogCodeIndex.delete(existing.codeNormalized);
    }
    const nowIso = new Date().toISOString();
    const merged = toPlatformIntegrationCatalogRecord({
      ...existing,
      ...entry,
      integrationId: normalizedIntegrationId,
      code: normalizedCode,
      createdAt: existing?.createdAt || entry.createdAt || nowIso,
      updatedAt: entry.updatedAt || nowIso
    });
    platformIntegrationCatalogById.set(normalizedIntegrationId, merged);
    platformIntegrationCatalogCodeIndex.set(codeKey, normalizedIntegrationId);
    return clonePlatformIntegrationCatalogRecord(merged);
  };
  const upsertPlatformIntegrationContractVersionRecord = (entry = {}) => {
    const normalizedIntegrationId = normalizePlatformIntegrationId(
      entry.integrationId || entry.integration_id
    );
    const normalizedContractType = normalizePlatformIntegrationContractType(
      entry.contractType || entry.contract_type
    );
    const normalizedContractVersion = normalizePlatformIntegrationContractVersion(
      entry.contractVersion || entry.contract_version
    );
    if (
      !isValidPlatformIntegrationId(normalizedIntegrationId)
      || !VALID_PLATFORM_INTEGRATION_CONTRACT_TYPE.has(normalizedContractType)
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_PLATFORM_INTEGRATION_CONTRACT_VERSION_LENGTH
    ) {
      throw new Error('platform integration contract version entry requires identity fields');
    }
    const contractKey = toPlatformIntegrationContractVersionKey({
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion
    });
    const existing = platformIntegrationContractVersionsByKey.get(contractKey) || null;
    const nowIso = new Date().toISOString();
    const merged = toPlatformIntegrationContractVersionRecord({
      ...existing,
      ...entry,
      contractId:
        Number(existing?.contractId || entry.contractId || entry.contract_id || 0)
        || nextPlatformIntegrationContractVersionId,
      integrationId: normalizedIntegrationId,
      contractType: normalizedContractType,
      contractVersion: normalizedContractVersion,
      createdAt: existing?.createdAt || entry.createdAt || entry.created_at || nowIso,
      updatedAt: entry.updatedAt || entry.updated_at || nowIso
    });
    if (!existing) {
      nextPlatformIntegrationContractVersionId += 1;
    }
    platformIntegrationContractVersionsByKey.set(contractKey, merged);
    return clonePlatformIntegrationContractVersionRecord(merged);
  };
  const upsertPlatformIntegrationRecoveryQueueRecord = ({
    entry = {},
    preserveTerminalStatus = false
  } = {}) => {
    const normalizedRecord = toPlatformIntegrationRecoveryQueueRecord(entry);
    const dedupState = findPlatformIntegrationRecoveryQueueRecordStateByDedupKey({
      integrationId: normalizedRecord.integrationId,
      contractType: normalizedRecord.contractType,
      contractVersion: normalizedRecord.contractVersion,
      requestId: normalizedRecord.requestId,
      idempotencyKey: normalizedRecord.idempotencyKey
    });
    const recoveryIdState = findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId(
      normalizedRecord.recoveryId
    );
    if (
      dedupState
      && recoveryIdState
      && dedupState.recoveryId !== recoveryIdState.recoveryId
    ) {
      throw new Error('duplicate platform integration recovery queue entry');
    }
    if (!dedupState && recoveryIdState) {
      throw new Error('duplicate platform integration recovery queue entry');
    }
    const existingState = dedupState || null;
    const existing = existingState?.record || null;
    const nowIso = new Date().toISOString();
    const persistedRecoveryId = existingState?.recoveryId || normalizedRecord.recoveryId;
    const merged = toPlatformIntegrationRecoveryQueueRecord({
      ...existing,
      ...normalizedRecord,
      recoveryId: persistedRecoveryId,
      status:
        preserveTerminalStatus
        && (
          existing?.status === 'succeeded'
          || existing?.status === 'replayed'
        )
          ? existing.status
          : normalizedRecord.status,
      createdAt: existing?.createdAt || normalizedRecord.createdAt || nowIso,
      updatedAt: nowIso
    });
    if (existing) {
      const previousDedupKey = toPlatformIntegrationRecoveryDedupKey({
        integrationId: existing.integrationId,
        contractType: existing.contractType,
        contractVersion: existing.contractVersion,
        requestId: existing.requestId,
        idempotencyKey: existing.idempotencyKey
      });
      platformIntegrationRecoveryDedupIndex.delete(previousDedupKey);
    }
    platformIntegrationRecoveryQueueByRecoveryId.set(persistedRecoveryId, merged);
    const dedupKey = toPlatformIntegrationRecoveryDedupKey({
      integrationId: merged.integrationId,
      contractType: merged.contractType,
      contractVersion: merged.contractVersion,
      requestId: merged.requestId,
      idempotencyKey: merged.idempotencyKey
    });
    platformIntegrationRecoveryDedupIndex.set(dedupKey, persistedRecoveryId);
    return clonePlatformIntegrationRecoveryQueueRecord(merged);
  };
  const upsertPlatformIntegrationFreezeRecord = (entry = {}) => {
    const normalizedRecord = toPlatformIntegrationFreezeRecord(entry);
    const existing = platformIntegrationFreezeById.get(normalizedRecord.freezeId) || null;
    const nowIso = new Date().toISOString();
    const merged = toPlatformIntegrationFreezeRecord({
      ...existing,
      ...normalizedRecord,
      freezeId: normalizedRecord.freezeId,
      createdAt: existing?.createdAt || normalizedRecord.createdAt || nowIso,
      updatedAt: normalizedRecord.updatedAt || nowIso
    });
    platformIntegrationFreezeById.set(merged.freezeId, merged);
    return clonePlatformIntegrationFreezeRecord(merged);
  };

  return {
    normalizePlatformRoleStatus,
    normalizePlatformRoleCatalogStatus,
    normalizePlatformRoleCatalogScope,
    normalizePlatformRoleCatalogTenantId,
    normalizePlatformRoleCatalogTenantIdForScope,
    normalizePlatformRoleCatalogRoleId,
    toPlatformRoleCatalogRoleIdKey,
    normalizePlatformRoleCatalogCode,
    toPlatformRoleCatalogCodeKey,
    toPlatformRoleCatalogCodeIndexKey,
    normalizePlatformIntegrationId,
    isValidPlatformIntegrationId,
    normalizePlatformIntegrationCode,
    toPlatformIntegrationCodeKey,
    normalizePlatformIntegrationDirection,
    normalizePlatformIntegrationLifecycleStatus,
    normalizePlatformIntegrationContractType,
    normalizePlatformIntegrationContractVersion,
    normalizePlatformIntegrationContractStatus,
    normalizePlatformIntegrationContractEvaluationResult,
    normalizePlatformIntegrationContractSchemaChecksum,
    normalizePlatformIntegrationRecoveryId,
    normalizePlatformIntegrationRecoveryStatus,
    normalizePlatformIntegrationFreezeId,
    normalizePlatformIntegrationFreezeStatus,
    normalizePlatformIntegrationRecoveryIdempotencyKey,
    PLATFORM_INTEGRATION_CONTRACT_CHECKSUM_PATTERN,
    toPlatformIntegrationContractVersionKey,
    toPlatformIntegrationContractScopeKey,
    toPlatformIntegrationRecoveryDedupKey,
    normalizePlatformIntegrationOptionalText,
    normalizePlatformIntegrationTimeoutMs,
    normalizePlatformIntegrationJsonForStorage,
    createDuplicatePlatformIntegrationCatalogEntryError,
    createDuplicatePlatformIntegrationContractVersionError,
    createPlatformIntegrationContractActivationBlockedError,
    isPlatformIntegrationLifecycleTransitionAllowed,
    createPlatformIntegrationLifecycleConflictError,
    createPlatformIntegrationRecoveryReplayConflictError,
    createPlatformIntegrationFreezeActiveConflictError,
    createPlatformIntegrationFreezeReleaseConflictError,
    normalizePlatformPermissionCode,
    toPlatformPermissionCodeKey,
    createDuplicatePlatformRoleCatalogEntryError,
    toPlatformRoleCatalogRecord,
    clonePlatformRoleCatalogRecord,
    toPlatformIntegrationCatalogRecord,
    clonePlatformIntegrationCatalogRecord,
    toPlatformIntegrationContractVersionRecord,
    clonePlatformIntegrationContractVersionRecord,
    toPlatformIntegrationContractCompatibilityCheckRecord,
    clonePlatformIntegrationContractCompatibilityCheckRecord,
    toPlatformIntegrationRecoveryQueueRecord,
    clonePlatformIntegrationRecoveryQueueRecord,
    toPlatformIntegrationFreezeRecord,
    clonePlatformIntegrationFreezeRecord,
    findPlatformRoleCatalogRecordStateByRoleId,
    findPlatformIntegrationCatalogRecordStateByIntegrationId,
    findPlatformIntegrationContractVersionRecordState,
    findPlatformIntegrationRecoveryQueueRecordStateByRecoveryId,
    findPlatformIntegrationRecoveryQueueRecordStateByDedupKey,
    comparePlatformIntegrationFreezeRecords,
    findActivePlatformIntegrationFreezeRecordState,
    findLatestPlatformIntegrationFreezeRecordState,
    findActivePlatformIntegrationFreezeForWriteGate,
    assertPlatformIntegrationWriteAllowedByFreezeGate,
    normalizePlatformPermission,
    mergePlatformPermission,
    buildEmptyPlatformPermission,
    normalizePlatformPermissionCodes,
    resolvePlatformPermissionFromGrantCodes,
    createPlatformRolePermissionGrantDataError,
    listPlatformRolePermissionGrantsForRoleId,
    replacePlatformRolePermissionGrantsForRoleId,
    isSamePlatformPermission,
    normalizePlatformRole,
    dedupePlatformRolesByRoleId,
    mergePlatformPermissionFromRoles,
    syncPlatformPermissionFromRoleFacts,
    upsertPlatformRoleCatalogRecord,
    upsertPlatformIntegrationCatalogRecord,
    upsertPlatformIntegrationContractVersionRecord,
    upsertPlatformIntegrationRecoveryQueueRecord,
    upsertPlatformIntegrationFreezeRecord,
  };
};

module.exports = {
  createPlatformMemoryAuthStoreRuntimeBootstrap
};
