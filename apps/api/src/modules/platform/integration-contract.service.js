const { log } = require('../../common/logger');
const { AuthProblemError } = require('../auth/auth.service');
const {
  resolveRoutePreauthorizedContext
} = require('../auth/route-preauthorization');
const {
  PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_CONTRACT_SCOPE,
  PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM,
  PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM,
  PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT_ENUM
} = require('./integration-contract.constants');

const CONTROL_CHAR_PATTERN = /[\u0000-\u001F\u007F]/;
const HEX_SHA256_PATTERN = /^[a-f0-9]{64}$/;
const MAX_AUDIT_TRAIL_ENTRIES = 200;
const MAX_INTEGRATION_ID_LENGTH = 64;
const MAX_OPERATOR_USER_ID_LENGTH = 64;
const MAX_CONTRACT_VERSION_LENGTH = 64;
const MAX_SCHEMA_REF_LENGTH = 512;
const MAX_SCHEMA_CHECKSUM_LENGTH = 64;
const MAX_COMPATIBILITY_NOTES_LENGTH = 4096;
const MAX_DIFF_SUMMARY_LENGTH = 65535;
const MAX_BREAKING_CHANGE_COUNT = 4294967295;
const MAX_REQUEST_ID_LENGTH = 128;
const MAX_LIST_SIZE = 200;

const VALID_CONTRACT_TYPES = new Set(PLATFORM_INTEGRATION_CONTRACT_TYPE_ENUM);
const VALID_CONTRACT_STATUSES = new Set(PLATFORM_INTEGRATION_CONTRACT_STATUS_ENUM);
const VALID_EVALUATION_RESULTS = new Set(
  PLATFORM_INTEGRATION_CONTRACT_EVALUATION_RESULT_ENUM
);
const VALID_INTEGRATION_LIFECYCLE_STATUSES = new Set([
  'draft',
  'active',
  'paused',
  'retired'
]);

const CREATE_ALLOWED_FIELDS = new Set([
  'contract_type',
  'contract_version',
  'schema_ref',
  'schema_checksum',
  'status',
  'is_backward_compatible',
  'compatibility_notes'
]);
const LIST_ALLOWED_QUERY_FIELDS = new Set(['contract_type', 'status']);
const COMPATIBILITY_ALLOWED_FIELDS = new Set([
  'contract_type',
  'baseline_version',
  'candidate_version',
  'diff_summary',
  'breaking_change_count'
]);
const ACTIVATE_ALLOWED_FIELDS = new Set(['contract_type', 'baseline_version']);

const isPlainObject = (candidate) =>
  candidate !== null
  && typeof candidate === 'object'
  && !Array.isArray(candidate);

const toCanonicalJsonValue = (value, seen = new WeakSet()) => {
  if (value === null || typeof value !== 'object') {
    return value;
  }
  if (seen.has(value)) {
    throw new TypeError('circular json value');
  }
  seen.add(value);
  try {
    if (Array.isArray(value)) {
      return value.map((item) => toCanonicalJsonValue(item, seen));
    }
    if (!isPlainObject(value)) {
      throw new TypeError('unsupported json value');
    }
    const normalized = {};
    for (const key of Object.keys(value).sort()) {
      normalized[key] = toCanonicalJsonValue(value[key], seen);
    }
    return normalized;
  } finally {
    seen.delete(value);
  }
};

const serializeCanonicalJson = (value) => {
  try {
    return JSON.stringify(toCanonicalJsonValue(value));
  } catch (_error) {
    return undefined;
  }
};

const normalizeStrictRequiredString = (candidate) => {
  if (typeof candidate !== 'string') {
    return '';
  }
  const normalized = candidate.trim();
  if (
    !normalized
    || normalized !== candidate
    || CONTROL_CHAR_PATTERN.test(normalized)
  ) {
    return '';
  }
  return normalized;
};

const normalizeStrictOptionalString = ({
  value,
  maxLength
} = {}) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (typeof value !== 'string') {
    return undefined;
  }
  const normalized = value.trim();
  if (
    !normalized
    || normalized !== value
    || CONTROL_CHAR_PATTERN.test(normalized)
    || normalized.length > maxLength
  ) {
    return undefined;
  }
  return normalized;
};

const normalizeIntegrationId = (integrationId) =>
  normalizeStrictRequiredString(integrationId).toLowerCase();

const normalizeContractType = (contractType) =>
  String(contractType || '').trim().toLowerCase();

const normalizeContractStatus = (status) =>
  String(status || '').trim().toLowerCase();

const normalizeContractVersion = (contractVersion) =>
  normalizeStrictRequiredString(contractVersion);

const normalizeSchemaChecksum = (schemaChecksum) =>
  String(schemaChecksum || '').trim().toLowerCase();

const normalizeStoreIsoTimestamp = (value) => {
  if (value instanceof Date) {
    return value.toISOString();
  }
  if (typeof value !== 'string') {
    return '';
  }
  const normalized = value.trim();
  if (!normalized) {
    return '';
  }
  if (normalized !== value || CONTROL_CHAR_PATTERN.test(normalized)) {
    return '';
  }
  const parsedDate = new Date(normalized);
  if (Number.isNaN(parsedDate.getTime())) {
    return '';
  }
  return parsedDate.toISOString();
};

const integrationContractProblem = ({
  status,
  title,
  detail,
  errorCode,
  extensions = {}
}) =>
  new AuthProblemError({
    status,
    title,
    detail,
    errorCode,
    extensions
  });

const integrationContractErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    integrationContractProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'integration_contract_invalid_payload'
    }),

  forbidden: () =>
    integrationContractProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  integrationNotFound: ({
    integrationId = null
  } = {}) =>
    integrationContractProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标集成目录不存在',
      errorCode: 'integration_contract_not_found',
      extensions: {
        retryable: false,
        integration_id: integrationId
      }
    }),

  contractNotFound: ({
    integrationId = null,
    contractType = null,
    contractVersion = null
  } = {}) =>
    integrationContractProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标契约版本不存在',
      errorCode: 'integration_contract_not_found',
      extensions: {
        retryable: false,
        integration_id: integrationId,
        contract_type: contractType,
        contract_version: contractVersion
      }
    }),

  contractConflict: () =>
    integrationContractProblem({
      status: 409,
      title: 'Conflict',
      detail: '契约版本冲突，请检查 contract_version',
      errorCode: 'integration_contract_conflict',
      extensions: {
        retryable: false
      }
    }),

  contractIncompatible: ({
    baselineVersion = null,
    candidateVersion = null,
    breakingChangeCount = null
  } = {}) =>
    integrationContractProblem({
      status: 409,
      title: 'Conflict',
      detail: '候选版本与基线版本不兼容，禁止激活',
      errorCode: 'integration_contract_incompatible',
      extensions: {
        retryable: false,
        baseline_version: baselineVersion,
        candidate_version: candidateVersion,
        breaking_change_count: breakingChangeCount
      }
    }),

  activationBlocked: ({
    reason = 'activation_blocked',
    baselineVersion = null,
    candidateVersion = null
  } = {}) =>
    integrationContractProblem({
      status: 409,
      title: 'Conflict',
      detail: '契约版本激活被阻断',
      errorCode: 'integration_contract_activation_blocked',
      extensions: {
        retryable: false,
        reason,
        baseline_version: baselineVersion,
        candidate_version: candidateVersion
      }
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    integrationContractProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '契约治理依赖暂不可用，请稍后重试',
      errorCode: 'INT-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
};

const normalizeActivationBlockedReason = (reason) => {
  const normalized = String(reason || '').trim().toLowerCase();
  if (!normalized) {
    return 'activation_blocked';
  }
  const canonical = normalized
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '');
  return canonical || 'activation_blocked';
};

const mapStoreError = (error) => {
  if (error instanceof AuthProblemError) {
    return error;
  }
  const normalizedErrorCode = String(error?.code || '').trim();
  if (
    normalizedErrorCode === 'ER_DUP_ENTRY'
    || Number(error?.errno || 0) === 1062
  ) {
    return integrationContractErrors.contractConflict();
  }
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_CONTRACT_ACTIVATION_BLOCKED') {
    return integrationContractErrors.activationBlocked({
      reason: normalizeActivationBlockedReason(error?.reason)
    });
  }
  return integrationContractErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'dependency-unavailable').trim().toLowerCase()
  });
};

const mapContractRecord = ({
  record,
  requestId
} = {}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const integrationId = normalizeIntegrationId(
    record.integrationId || record.integration_id
  );
  const contractType = normalizeContractType(
    record.contractType || record.contract_type
  );
  const contractVersion = normalizeContractVersion(
    record.contractVersion || record.contract_version
  );
  const schemaRef = normalizeStrictRequiredString(
    record.schemaRef === undefined ? record.schema_ref : record.schemaRef
  );
  const schemaChecksum = normalizeSchemaChecksum(
    record.schemaChecksum === undefined ? record.schema_checksum : record.schemaChecksum
  );
  const status = normalizeContractStatus(record.status);
  const compatibilityNotes = normalizeStrictOptionalString({
    value: record.compatibilityNotes === undefined
      ? record.compatibility_notes
      : record.compatibilityNotes,
    maxLength: MAX_COMPATIBILITY_NOTES_LENGTH
  });
  const createdByUserId = normalizeStrictOptionalString({
    value: record.createdByUserId === undefined
      ? record.created_by_user_id
      : record.createdByUserId,
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });
  const updatedByUserId = normalizeStrictOptionalString({
    value: record.updatedByUserId === undefined
      ? record.updated_by_user_id
      : record.updatedByUserId,
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });
  const createdAt = normalizeStoreIsoTimestamp(
    record.createdAt === undefined ? record.created_at : record.createdAt
  );
  const updatedAt = normalizeStoreIsoTimestamp(
    record.updatedAt === undefined ? record.updated_at : record.updatedAt
  );
  const isBackwardCompatible =
    record.isBackwardCompatible === undefined
      ? record.is_backward_compatible
      : record.isBackwardCompatible;
  if (
    !integrationId
    || integrationId.length > MAX_INTEGRATION_ID_LENGTH
    || !VALID_CONTRACT_TYPES.has(contractType)
    || !contractVersion
    || contractVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || !schemaRef
    || schemaRef.length > MAX_SCHEMA_REF_LENGTH
    || !schemaChecksum
    || schemaChecksum.length > MAX_SCHEMA_CHECKSUM_LENGTH
    || !HEX_SHA256_PATTERN.test(schemaChecksum)
    || !VALID_CONTRACT_STATUSES.has(status)
    || compatibilityNotes === undefined
    || createdByUserId === undefined
    || updatedByUserId === undefined
    || !createdAt
    || !updatedAt
    || typeof isBackwardCompatible !== 'boolean'
  ) {
    return null;
  }
  return {
    integration_id: integrationId,
    contract_type: contractType,
    contract_version: contractVersion,
    schema_ref: schemaRef,
    schema_checksum: schemaChecksum,
    status,
    is_backward_compatible: isBackwardCompatible,
    compatibility_notes: compatibilityNotes,
    created_by_user_id: createdByUserId,
    updated_by_user_id: updatedByUserId,
    created_at: createdAt,
    updated_at: updatedAt,
    request_id: String(requestId || '').trim() || 'request_id_unset'
  };
};

const mapCompatibilityCheckRecord = ({
  record
} = {}) => {
  if (!record || typeof record !== 'object') {
    return null;
  }
  const integrationId = normalizeIntegrationId(
    record.integrationId || record.integration_id
  );
  const contractType = normalizeContractType(
    record.contractType || record.contract_type
  );
  const baselineVersion = normalizeContractVersion(
    record.baselineVersion || record.baseline_version
  );
  const candidateVersion = normalizeContractVersion(
    record.candidateVersion || record.candidate_version
  );
  const evaluationResult = normalizeContractStatus(
    record.evaluationResult || record.evaluation_result
  );
  const breakingChangeCount = Number(
    record.breakingChangeCount ?? record.breaking_change_count
  );
  const checkedAt = normalizeStoreIsoTimestamp(
    record.checkedAt === undefined ? record.checked_at : record.checkedAt
  );
  const checkedByUserId = normalizeStrictOptionalString({
    value: record.checkedByUserId === undefined
      ? record.checked_by_user_id
      : record.checkedByUserId,
    maxLength: MAX_OPERATOR_USER_ID_LENGTH
  });
  const requestIdInRecord = normalizeStrictRequiredString(
    record.requestId === undefined ? record.request_id : record.requestId
  );
  const diffSummary =
    record.diffSummary === undefined ? record.diff_summary : record.diffSummary;
  if (
    !integrationId
    || integrationId.length > MAX_INTEGRATION_ID_LENGTH
    || !VALID_CONTRACT_TYPES.has(contractType)
    || !baselineVersion
    || baselineVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || !candidateVersion
    || candidateVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || !VALID_EVALUATION_RESULTS.has(evaluationResult)
    || !Number.isInteger(breakingChangeCount)
    || breakingChangeCount < 0
    || breakingChangeCount > MAX_BREAKING_CHANGE_COUNT
    || !requestIdInRecord
    || requestIdInRecord.length > MAX_REQUEST_ID_LENGTH
    || checkedByUserId === undefined
    || !checkedAt
    || (
      diffSummary !== null
      && !isPlainObject(diffSummary)
      && !Array.isArray(diffSummary)
    )
  ) {
    return null;
  }
  const serializedDiffSummary = serializeCanonicalJson(diffSummary);
  if (
    diffSummary !== null
    && (
      serializedDiffSummary === undefined
      || serializedDiffSummary.length > MAX_DIFF_SUMMARY_LENGTH
    )
  ) {
    return null;
  }
  return {
    integration_id: integrationId,
    contract_type: contractType,
    baseline_version: baselineVersion,
    candidate_version: candidateVersion,
    evaluation_result: evaluationResult,
    breaking_change_count: breakingChangeCount,
    diff_summary: diffSummary,
    request_id: requestIdInRecord,
    checked_by_user_id: checkedByUserId,
    checked_at: checkedAt
  };
};

const matchesExpectedContractLookup = ({
  record,
  integrationId,
  contractType = null,
  contractVersion = null,
  status = null
} = {}) => {
  if (!record || typeof record !== 'object') {
    return false;
  }
  const normalizedIntegrationId = normalizeIntegrationId(integrationId);
  const normalizedContractType = contractType === null || contractType === undefined
    ? null
    : normalizeContractType(contractType);
  const normalizedContractVersion = contractVersion === null || contractVersion === undefined
    ? null
    : normalizeContractVersion(contractVersion);
  const normalizedStatus = status === null || status === undefined
    ? null
    : normalizeContractStatus(status);
  if (!normalizedIntegrationId || record.integration_id !== normalizedIntegrationId) {
    return false;
  }
  if (normalizedContractType !== null && record.contract_type !== normalizedContractType) {
    return false;
  }
  if (normalizedContractVersion !== null && record.contract_version !== normalizedContractVersion) {
    return false;
  }
  if (normalizedStatus !== null && record.status !== normalizedStatus) {
    return false;
  }
  return true;
};

const matchesExpectedCompatibilityCheckLookup = ({
  record,
  integrationId,
  contractType = null,
  baselineVersion = null,
  candidateVersion = null,
  evaluationResult = null
} = {}) => {
  if (!record || typeof record !== 'object') {
    return false;
  }
  const normalizedIntegrationId = normalizeIntegrationId(integrationId);
  const normalizedContractType = contractType === null || contractType === undefined
    ? null
    : normalizeContractType(contractType);
  const normalizedBaselineVersion = baselineVersion === null || baselineVersion === undefined
    ? null
    : normalizeContractVersion(baselineVersion);
  const normalizedCandidateVersion = candidateVersion === null || candidateVersion === undefined
    ? null
    : normalizeContractVersion(candidateVersion);
  const normalizedEvaluationResult = evaluationResult === null || evaluationResult === undefined
    ? null
    : normalizeContractStatus(evaluationResult);
  if (!normalizedIntegrationId || record.integration_id !== normalizedIntegrationId) {
    return false;
  }
  if (normalizedContractType !== null && record.contract_type !== normalizedContractType) {
    return false;
  }
  if (normalizedBaselineVersion !== null && record.baseline_version !== normalizedBaselineVersion) {
    return false;
  }
  if (normalizedCandidateVersion !== null && record.candidate_version !== normalizedCandidateVersion) {
    return false;
  }
  if (normalizedEvaluationResult !== null && record.evaluation_result !== normalizedEvaluationResult) {
    return false;
  }
  return true;
};

const matchesExpectedCompatibilityResultPayload = ({
  record,
  requestId,
  breakingChangeCount,
  diffSummary
} = {}) => {
  if (!record || typeof record !== 'object') {
    return false;
  }
  const normalizedRequestId = normalizeStrictRequiredString(requestId);
  if (!normalizedRequestId || record.request_id !== normalizedRequestId) {
    return false;
  }
  if (
    !Number.isInteger(record.breaking_change_count)
    || record.breaking_change_count !== breakingChangeCount
  ) {
    return false;
  }
  const serializedExpectedDiffSummary = serializeCanonicalJson(diffSummary);
  const serializedActualDiffSummary = serializeCanonicalJson(record.diff_summary);
  if (
    serializedExpectedDiffSummary === undefined
    || serializedActualDiffSummary === undefined
    || serializedExpectedDiffSummary !== serializedActualDiffSummary
  ) {
    return false;
  }
  return true;
};

const matchesExpectedCreateContractPayload = ({
  record,
  schemaRef,
  schemaChecksum,
  isBackwardCompatible,
  compatibilityNotes
} = {}) => {
  if (!record || typeof record !== 'object') {
    return false;
  }
  if (record.schema_ref !== normalizeStrictRequiredString(schemaRef)) {
    return false;
  }
  if (record.schema_checksum !== normalizeSchemaChecksum(schemaChecksum)) {
    return false;
  }
  if (record.is_backward_compatible !== Boolean(isBackwardCompatible)) {
    return false;
  }
  const normalizedCompatibilityNotes = compatibilityNotes === null
    ? null
    : normalizeStrictRequiredString(compatibilityNotes);
  if (record.compatibility_notes !== normalizedCompatibilityNotes) {
    return false;
  }
  return true;
};

const parseListQuery = (query = {}) => {
  if (!isPlainObject(query)) {
    throw integrationContractErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(query).filter(
    (key) => !LIST_ALLOWED_QUERY_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw integrationContractErrors.invalidPayload();
  }
  const contractType = query.contract_type === undefined
    ? null
    : normalizeContractType(query.contract_type);
  if (contractType !== null && !VALID_CONTRACT_TYPES.has(contractType)) {
    throw integrationContractErrors.invalidPayload('contract_type 非法');
  }
  const status = query.status === undefined
    ? null
    : normalizeContractStatus(query.status);
  if (status !== null && !VALID_CONTRACT_STATUSES.has(status)) {
    throw integrationContractErrors.invalidPayload('status 非法');
  }
  return {
    contractType,
    status
  };
};

const parseCreatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw integrationContractErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(payload).filter(
    (key) => !CREATE_ALLOWED_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw integrationContractErrors.invalidPayload();
  }
  const requiredFields = [
    'contract_type',
    'contract_version',
    'schema_ref',
    'schema_checksum'
  ];
  for (const field of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(payload, field)) {
      throw integrationContractErrors.invalidPayload(`${field} 必填`);
    }
  }
  const contractType = normalizeContractType(payload.contract_type);
  const contractVersion = normalizeContractVersion(payload.contract_version);
  const schemaRef = normalizeStrictRequiredString(payload.schema_ref);
  const schemaChecksum = normalizeSchemaChecksum(payload.schema_checksum);
  const status = Object.prototype.hasOwnProperty.call(payload, 'status')
    ? normalizeContractStatus(payload.status)
    : 'candidate';
  const isBackwardCompatible = Object.prototype.hasOwnProperty.call(
    payload,
    'is_backward_compatible'
  )
    ? payload.is_backward_compatible
    : false;
  const compatibilityNotes = Object.prototype.hasOwnProperty.call(
    payload,
    'compatibility_notes'
  )
    ? normalizeStrictOptionalString({
      value: payload.compatibility_notes,
      maxLength: MAX_COMPATIBILITY_NOTES_LENGTH
    })
    : null;
  if (
    !VALID_CONTRACT_TYPES.has(contractType)
    || !contractVersion
    || contractVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || !schemaRef
    || schemaRef.length > MAX_SCHEMA_REF_LENGTH
    || !schemaChecksum
    || schemaChecksum.length > MAX_SCHEMA_CHECKSUM_LENGTH
    || !HEX_SHA256_PATTERN.test(schemaChecksum)
    || !VALID_CONTRACT_STATUSES.has(status)
    || compatibilityNotes === undefined
    || typeof isBackwardCompatible !== 'boolean'
  ) {
    throw integrationContractErrors.invalidPayload();
  }
  if (status === 'active') {
    throw integrationContractErrors.activationBlocked({
      reason: 'active_status_requires_activation_flow'
    });
  }
  return {
    contractType,
    contractVersion,
    schemaRef,
    schemaChecksum,
    status,
    isBackwardCompatible,
    compatibilityNotes
  };
};

const resolveBreakingChangeCount = ({
  payload,
  diffSummary
}) => {
  const parseCount = ({ value, field }) => {
    if (typeof value !== 'number' || !Number.isFinite(value)) {
      throw integrationContractErrors.invalidPayload(`${field} 非法`);
    }
    const parsed = Number(value);
    if (
      !Number.isInteger(parsed)
      || parsed < 0
      || parsed > MAX_BREAKING_CHANGE_COUNT
    ) {
      throw integrationContractErrors.invalidPayload(`${field} 非法`);
    }
    return parsed;
  };
  const hasExplicitBreakingChangeCount = Object.prototype.hasOwnProperty.call(
    payload,
    'breaking_change_count'
  );
  let inferredBreakingChangeCount = null;
  const reconcileInferredCount = ({ value, field }) => {
    const parsed = parseCount({ value, field });
    if (
      inferredBreakingChangeCount !== null
      && inferredBreakingChangeCount !== parsed
    ) {
      throw integrationContractErrors.invalidPayload(
        'diff_summary.breaking_change_count 与 diff_summary.breaking_changes 不一致'
      );
    }
    inferredBreakingChangeCount = parsed;
  };

  if (Array.isArray(diffSummary)) {
    reconcileInferredCount({
      value: diffSummary.length,
      field: 'diff_summary.breaking_changes'
    });
  }
  if (isPlainObject(diffSummary)) {
    if (Array.isArray(diffSummary.breaking_changes)) {
      reconcileInferredCount({
        value: diffSummary.breaking_changes.length,
        field: 'diff_summary.breaking_changes'
      });
    }
    if (Object.prototype.hasOwnProperty.call(diffSummary, 'breaking_change_count')) {
      reconcileInferredCount({
        value: diffSummary.breaking_change_count,
        field: 'diff_summary.breaking_change_count'
      });
    }
  }

  if (hasExplicitBreakingChangeCount) {
    const explicitCount = parseCount({
      value: payload.breaking_change_count,
      field: 'breaking_change_count'
    });
    if (
      inferredBreakingChangeCount !== null
      && explicitCount !== inferredBreakingChangeCount
    ) {
      throw integrationContractErrors.invalidPayload(
        'breaking_change_count 与 diff_summary 不一致'
      );
    }
    return explicitCount;
  }
  return inferredBreakingChangeCount === null
    ? 0
    : inferredBreakingChangeCount;
};

const hasConsistentCompatibilityCheckEvaluation = ({
  record
} = {}) => {
  if (!record || typeof record !== 'object') {
    return false;
  }
  if (
    !Number.isInteger(record.breaking_change_count)
    || record.breaking_change_count < 0
    || record.breaking_change_count > MAX_BREAKING_CHANGE_COUNT
  ) {
    return false;
  }
  if (!VALID_EVALUATION_RESULTS.has(record.evaluation_result)) {
    return false;
  }
  try {
    const resolvedBreakingChangeCount = resolveBreakingChangeCount({
      payload: {
        breaking_change_count: record.breaking_change_count
      },
      diffSummary: record.diff_summary
    });
    if (resolvedBreakingChangeCount !== record.breaking_change_count) {
      return false;
    }
  } catch (_error) {
    return false;
  }
  const expectedEvaluationResult =
    record.breaking_change_count > 0
      ? 'incompatible'
      : 'compatible';
  return record.evaluation_result === expectedEvaluationResult;
};

const parseCompatibilityPayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw integrationContractErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(payload).filter(
    (key) => !COMPATIBILITY_ALLOWED_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw integrationContractErrors.invalidPayload();
  }
  const requiredFields = [
    'contract_type',
    'baseline_version',
    'candidate_version'
  ];
  for (const field of requiredFields) {
    if (!Object.prototype.hasOwnProperty.call(payload, field)) {
      throw integrationContractErrors.invalidPayload(`${field} 必填`);
    }
  }
  const contractType = normalizeContractType(payload.contract_type);
  const baselineVersion = normalizeContractVersion(payload.baseline_version);
  const candidateVersion = normalizeContractVersion(payload.candidate_version);
  const diffSummary = Object.prototype.hasOwnProperty.call(payload, 'diff_summary')
    ? payload.diff_summary
    : null;
  if (
    !VALID_CONTRACT_TYPES.has(contractType)
    || !baselineVersion
    || baselineVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || !candidateVersion
    || candidateVersion.length > MAX_CONTRACT_VERSION_LENGTH
    || (
      diffSummary !== null
      && !isPlainObject(diffSummary)
      && !Array.isArray(diffSummary)
    )
  ) {
    throw integrationContractErrors.invalidPayload();
  }
  if (diffSummary !== null) {
    let serializedDiffSummary;
    try {
      serializedDiffSummary = JSON.stringify(diffSummary);
    } catch (_error) {
      throw integrationContractErrors.invalidPayload('diff_summary 非法');
    }
    if (
      !serializedDiffSummary
      || serializedDiffSummary.length > MAX_DIFF_SUMMARY_LENGTH
    ) {
      throw integrationContractErrors.invalidPayload('diff_summary 超长');
    }
  }
  const breakingChangeCount = resolveBreakingChangeCount({
    payload,
    diffSummary
  });
  return {
    contractType,
    baselineVersion,
    candidateVersion,
    diffSummary,
    breakingChangeCount,
    evaluationResult:
      breakingChangeCount > 0
        ? 'incompatible'
        : 'compatible'
  };
};

const parseActivatePayload = (payload = {}) => {
  if (!isPlainObject(payload)) {
    throw integrationContractErrors.invalidPayload();
  }
  const unknownKeys = Object.keys(payload).filter(
    (key) => !ACTIVATE_ALLOWED_FIELDS.has(key)
  );
  if (unknownKeys.length > 0) {
    throw integrationContractErrors.invalidPayload();
  }
  if (!Object.prototype.hasOwnProperty.call(payload, 'contract_type')) {
    throw integrationContractErrors.invalidPayload('contract_type 必填');
  }
  const contractType = normalizeContractType(payload.contract_type);
  if (!VALID_CONTRACT_TYPES.has(contractType)) {
    throw integrationContractErrors.invalidPayload('contract_type 非法');
  }
  const baselineVersion = Object.prototype.hasOwnProperty.call(
    payload,
    'baseline_version'
  )
    ? normalizeContractVersion(payload.baseline_version)
    : null;
  if (
    baselineVersion !== null
    && (
      !baselineVersion
      || baselineVersion.length > MAX_CONTRACT_VERSION_LENGTH
    )
  ) {
    throw integrationContractErrors.invalidPayload('baseline_version 非法');
  }
  return {
    contractType,
    baselineVersion
  };
};

const createPlatformIntegrationContractService = ({ authService } = {}) => {
  const auditTrail = [];

  const addAuditEvent = ({
    type,
    requestId,
    operatorUserId = 'unknown',
    integrationId = null,
    detail,
    metadata = {}
  }) => {
    const event = {
      type: String(type || '').trim() || 'platform.integration.contract.unknown',
      at: new Date().toISOString(),
      request_id: String(requestId || '').trim() || 'request_id_unset',
      operator_user_id: String(operatorUserId || '').trim() || 'unknown',
      integration_id: integrationId ? String(integrationId) : null,
      detail: String(detail || '').trim(),
      ...metadata
    };
    auditTrail.push(event);
    if (auditTrail.length > MAX_AUDIT_TRAIL_ENTRIES) {
      auditTrail.splice(0, auditTrail.length - MAX_AUDIT_TRAIL_ENTRIES);
    }
    log('info', 'Platform integration contract audit event', event);
  };

  const assertAuthServiceMethod = (methodName) => {
    if (!authService || typeof authService[methodName] !== 'function') {
      throw integrationContractErrors.dependencyUnavailable({
        reason: `auth-service-${methodName}-unsupported`
      });
    }
  };

  const resolveAuthStore = () => authService?._internals?.authStore || null;

  const assertAuthStoreMethod = (methodName) => {
    const authStore = resolveAuthStore();
    if (!authStore || typeof authStore[methodName] !== 'function') {
      throw integrationContractErrors.dependencyUnavailable({
        reason: `auth-store-${methodName}-unsupported`
      });
    }
    return authStore;
  };

  const resolvePreauthorizedOperatorContext = ({
    authorizationContext = null,
    expectedPermissionCode = PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
  } = {}) => {
    const preauthorizedContext = resolveRoutePreauthorizedContext({
      authorizationContext,
      expectedPermissionCode,
      expectedScope: PLATFORM_INTEGRATION_CONTRACT_SCOPE,
      expectedEntryDomain: PLATFORM_INTEGRATION_CONTRACT_SCOPE
    });
    if (!preauthorizedContext) {
      return null;
    }
    return {
      operatorUserId: preauthorizedContext.userId,
      operatorSessionId: preauthorizedContext.sessionId
    };
  };

  const resolveOperatorContext = async ({
    requestId,
    accessToken,
    authorizationContext = null,
    permissionCode = PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
  }) => {
    const preauthorizedContext = resolvePreauthorizedOperatorContext({
      authorizationContext,
      expectedPermissionCode: permissionCode
    });
    if (preauthorizedContext) {
      return preauthorizedContext;
    }
    assertAuthServiceMethod('authorizeRoute');
    const authorized = await authService.authorizeRoute({
      requestId,
      accessToken,
      permissionCode,
      scope: PLATFORM_INTEGRATION_CONTRACT_SCOPE,
      authorizationContext
    });
    const operatorUserId = normalizeStrictRequiredString(
      authorized?.user_id || authorized?.userId
    );
    const operatorSessionId = normalizeStrictRequiredString(
      authorized?.session_id || authorized?.sessionId
    );
    if (!operatorUserId || !operatorSessionId) {
      throw integrationContractErrors.forbidden();
    }
    return {
      operatorUserId,
      operatorSessionId
    };
  };

  const getIntegrationEntry = async ({ integrationId }) => {
    const authStore = assertAuthStoreMethod(
      'findPlatformIntegrationCatalogEntryByIntegrationId'
    );
    let record;
    try {
      record = await authStore.findPlatformIntegrationCatalogEntryByIntegrationId({
        integrationId
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!record) {
      return null;
    }
    const requestedIntegrationId = normalizeIntegrationId(integrationId);
    const recordIntegrationId = normalizeIntegrationId(
      record.integrationId || record.integration_id
    );
    const lifecycleStatus = String(
      record.lifecycleStatus === undefined
        ? record.lifecycle_status
        : record.lifecycleStatus
    ).trim().toLowerCase();
    if (
      !requestedIntegrationId
      || !recordIntegrationId
      || recordIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      || recordIntegrationId !== requestedIntegrationId
      || !VALID_INTEGRATION_LIFECYCLE_STATUSES.has(lifecycleStatus)
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-catalog-record-invalid'
      });
    }
    return {
      integration_id: recordIntegrationId,
      lifecycle_status: lifecycleStatus
    };
  };

  const listContracts = async ({
    requestId,
    accessToken,
    integrationId,
    query = {},
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (!normalizedIntegrationId || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH) {
      throw integrationContractErrors.invalidPayload('integration_id 非法');
    }
    const filters = parseListQuery(query || {});
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_CONTRACT_VIEW_PERMISSION_CODE
    });
    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw integrationContractErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }
    const authStore = assertAuthStoreMethod('listPlatformIntegrationContractVersions');
    let records;
    try {
      records = await authStore.listPlatformIntegrationContractVersions({
        integrationId: normalizedIntegrationId,
        contractType: filters.contractType,
        status: filters.status
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    if (!Array.isArray(records) || records.length > MAX_LIST_SIZE) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-list-invalid'
      });
    }
    const mappedContracts = records.map((record) =>
      mapContractRecord({
        record,
        requestId: resolvedRequestId
      })
    );
    if (mappedContracts.some((record) => !record)) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-list-result-malformed'
      });
    }
    if (
      mappedContracts.some(
        (record) =>
          !matchesExpectedContractLookup({
            record,
            integrationId: normalizedIntegrationId,
            contractType: filters.contractType,
            status: filters.status
          })
      )
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-list-result-malformed'
      });
    }
    const activeContracts = mappedContracts.filter(
      (record) => record.status === 'active'
    );
    addAuditEvent({
      type: 'platform.integration.contract.list.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      integrationId: normalizedIntegrationId,
      detail: 'integration contracts listed',
      metadata: {
        total: mappedContracts.length
      }
    });
    return {
      integration_id: normalizedIntegrationId,
      lifecycle_status: integrationEntry.lifecycle_status,
      contracts: mappedContracts,
      active_contracts: activeContracts,
      request_id: resolvedRequestId
    };
  };

  const createContract = async ({
    requestId,
    accessToken,
    integrationId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (!normalizedIntegrationId || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH) {
      throw integrationContractErrors.invalidPayload('integration_id 非法');
    }
    const parsedPayload = parseCreatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
    });
    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw integrationContractErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }
    const authStore = assertAuthStoreMethod('createPlatformIntegrationContractVersion');
    let createdRecord;
    try {
      createdRecord = await authStore.createPlatformIntegrationContractVersion({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: parsedPayload.contractVersion,
        schemaRef: parsedPayload.schemaRef,
        schemaChecksum: parsedPayload.schemaChecksum,
        status: parsedPayload.status,
        isBackwardCompatible: parsedPayload.isBackwardCompatible,
        compatibilityNotes: parsedPayload.compatibilityNotes,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    const mapped = mapContractRecord({
      record: createdRecord,
      requestId: resolvedRequestId
    });
    if (
      !mapped
      || !matchesExpectedContractLookup({
        record: mapped,
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: parsedPayload.contractVersion,
        status: parsedPayload.status
      })
      || !matchesExpectedCreateContractPayload({
        record: mapped,
        schemaRef: parsedPayload.schemaRef,
        schemaChecksum: parsedPayload.schemaChecksum,
        isBackwardCompatible: parsedPayload.isBackwardCompatible,
        compatibilityNotes: parsedPayload.compatibilityNotes
      })
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-create-result-invalid'
      });
    }
    return mapped;
  };

  const evaluateCompatibility = async ({
    requestId,
    accessToken,
    integrationId,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    if (!normalizedIntegrationId || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH) {
      throw integrationContractErrors.invalidPayload('integration_id 非法');
    }
    const parsedPayload = parseCompatibilityPayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
    });
    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw integrationContractErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }
    const authStore = assertAuthStoreMethod('findPlatformIntegrationContractVersion');
    let baselineRecord;
    let candidateRecord;
    try {
      baselineRecord = await authStore.findPlatformIntegrationContractVersion({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: parsedPayload.baselineVersion
      });
      candidateRecord = await authStore.findPlatformIntegrationContractVersion({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: parsedPayload.candidateVersion
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    const mappedBaselineRecord = baselineRecord
      ? mapContractRecord({
        record: baselineRecord,
        requestId: resolvedRequestId
      })
      : null;
    const mappedCandidateRecord = candidateRecord
      ? mapContractRecord({
        record: candidateRecord,
        requestId: resolvedRequestId
      })
      : null;
    if (
      baselineRecord
      && (
        !mappedBaselineRecord
        || !matchesExpectedContractLookup({
          record: mappedBaselineRecord,
          integrationId: normalizedIntegrationId,
          contractType: parsedPayload.contractType,
          contractVersion: parsedPayload.baselineVersion
        })
      )
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-baseline-read-result-malformed'
      });
    }
    if (
      candidateRecord
      && (
        !mappedCandidateRecord
        || !matchesExpectedContractLookup({
          record: mappedCandidateRecord,
          integrationId: normalizedIntegrationId,
          contractType: parsedPayload.contractType,
          contractVersion: parsedPayload.candidateVersion
        })
      )
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-candidate-read-result-malformed'
      });
    }
    if (!baselineRecord) {
      throw integrationContractErrors.contractNotFound({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: parsedPayload.baselineVersion
      });
    }
    if (!candidateRecord) {
      throw integrationContractErrors.contractNotFound({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: parsedPayload.candidateVersion
      });
    }

    const checkStore = assertAuthStoreMethod(
      'createPlatformIntegrationContractCompatibilityCheck'
    );
    let compatibilityCheckRecord;
    try {
      compatibilityCheckRecord = await checkStore.createPlatformIntegrationContractCompatibilityCheck({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        baselineVersion: parsedPayload.baselineVersion,
        candidateVersion: parsedPayload.candidateVersion,
        evaluationResult: parsedPayload.evaluationResult,
        breakingChangeCount: parsedPayload.breakingChangeCount,
        diffSummary: parsedPayload.diffSummary,
        requestId: resolvedRequestId,
        checkedByUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    const mapped = mapCompatibilityCheckRecord({
      record: compatibilityCheckRecord
    });
    if (
      !mapped
      || !matchesExpectedCompatibilityCheckLookup({
        record: mapped,
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        baselineVersion: parsedPayload.baselineVersion,
        candidateVersion: parsedPayload.candidateVersion,
        evaluationResult: parsedPayload.evaluationResult
      })
      || !matchesExpectedCompatibilityResultPayload({
        record: mapped,
        requestId: resolvedRequestId,
        breakingChangeCount: parsedPayload.breakingChangeCount,
        diffSummary: parsedPayload.diffSummary
      })
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-compatibility-result-invalid'
      });
    }
    return mapped;
  };

  const activateContract = async ({
    requestId,
    accessToken,
    integrationId,
    contractVersion,
    payload = {},
    traceparent = null,
    authorizationContext = null
  }) => {
    const resolvedRequestId = String(requestId || '').trim() || 'request_id_unset';
    const normalizedIntegrationId = normalizeIntegrationId(integrationId);
    const normalizedContractVersion = normalizeContractVersion(contractVersion);
    if (
      !normalizedIntegrationId
      || normalizedIntegrationId.length > MAX_INTEGRATION_ID_LENGTH
      || !normalizedContractVersion
      || normalizedContractVersion.length > MAX_CONTRACT_VERSION_LENGTH
    ) {
      throw integrationContractErrors.invalidPayload();
    }
    const parsedPayload = parseActivatePayload(payload);
    const operatorContext = await resolveOperatorContext({
      requestId: resolvedRequestId,
      accessToken,
      authorizationContext,
      permissionCode: PLATFORM_INTEGRATION_CONTRACT_OPERATE_PERMISSION_CODE
    });
    const integrationEntry = await getIntegrationEntry({
      integrationId: normalizedIntegrationId
    });
    if (!integrationEntry) {
      throw integrationContractErrors.integrationNotFound({
        integrationId: normalizedIntegrationId
      });
    }

    const findContractStore = assertAuthStoreMethod('findPlatformIntegrationContractVersion');
    let candidateRecord;
    try {
      candidateRecord = await findContractStore.findPlatformIntegrationContractVersion({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: normalizedContractVersion
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    const mappedCandidate = mapContractRecord({
      record: candidateRecord,
      requestId: resolvedRequestId
    });
    if (
      candidateRecord
      && (
        !mappedCandidate
        || !matchesExpectedContractLookup({
          record: mappedCandidate,
          integrationId: normalizedIntegrationId,
          contractType: parsedPayload.contractType,
          contractVersion: normalizedContractVersion
        })
      )
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-candidate-read-result-malformed'
      });
    }
    if (!candidateRecord) {
      throw integrationContractErrors.contractNotFound({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: normalizedContractVersion
      });
    }

    const activeContractLookupStore = assertAuthStoreMethod(
      'findLatestActivePlatformIntegrationContractVersion'
    );
    let currentActiveRecord;
    try {
      currentActiveRecord =
        await activeContractLookupStore.findLatestActivePlatformIntegrationContractVersion({
          integrationId: normalizedIntegrationId,
          contractType: parsedPayload.contractType
        });
    } catch (error) {
      throw mapStoreError(error);
    }
    const mappedCurrentActive = mapContractRecord({
      record: currentActiveRecord,
      requestId: resolvedRequestId
    });
    if (
      currentActiveRecord
      && (
        !mappedCurrentActive
        || !matchesExpectedContractLookup({
          record: mappedCurrentActive,
          integrationId: normalizedIntegrationId,
          contractType: parsedPayload.contractType,
          status: 'active'
        })
      )
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-active-read-result-malformed'
      });
    }

    const currentActiveVersion = mappedCurrentActive?.contract_version || null;
    let baselineVersion = parsedPayload.baselineVersion || currentActiveVersion || null;
    if (
      currentActiveVersion
      && parsedPayload.baselineVersion
      && parsedPayload.baselineVersion !== currentActiveVersion
    ) {
      throw integrationContractErrors.activationBlocked({
        reason: 'baseline_version_mismatch',
        baselineVersion: currentActiveVersion,
        candidateVersion: mappedCandidate.contract_version
      });
    }
    if (!currentActiveVersion && baselineVersion && baselineVersion !== mappedCandidate.contract_version) {
      throw integrationContractErrors.activationBlocked({
        reason: 'baseline_version_without_active_contract',
        baselineVersion,
        candidateVersion: mappedCandidate.contract_version
      });
    }
    if (currentActiveVersion) {
      baselineVersion = currentActiveVersion;
    }

    if (mappedCandidate.status === 'retired') {
      throw integrationContractErrors.activationBlocked({
        reason: 'retired_version',
        baselineVersion,
        candidateVersion: mappedCandidate.contract_version
      });
    }

    if (
      currentActiveVersion
      && mappedCandidate.contract_version !== currentActiveVersion
    ) {
      const findCheckStore = assertAuthStoreMethod(
        'findLatestPlatformIntegrationContractCompatibilityCheck'
      );
      let latestCheck;
      try {
        latestCheck =
          await findCheckStore.findLatestPlatformIntegrationContractCompatibilityCheck({
            integrationId: normalizedIntegrationId,
            contractType: parsedPayload.contractType,
            baselineVersion: currentActiveVersion,
            candidateVersion: mappedCandidate.contract_version
          });
      } catch (error) {
        throw mapStoreError(error);
      }
      const mappedLatestCheck = mapCompatibilityCheckRecord({
        record: latestCheck,
        requestId: resolvedRequestId
      });
      if (!latestCheck) {
        throw integrationContractErrors.activationBlocked({
          reason: 'missing_compatibility_check',
          baselineVersion,
          candidateVersion: mappedCandidate.contract_version
        });
      }
      if (
        !mappedLatestCheck
        || !matchesExpectedCompatibilityCheckLookup({
          record: mappedLatestCheck,
          integrationId: normalizedIntegrationId,
          contractType: parsedPayload.contractType,
          baselineVersion: currentActiveVersion,
          candidateVersion: mappedCandidate.contract_version
        })
        || !hasConsistentCompatibilityCheckEvaluation({
          record: mappedLatestCheck
        })
      ) {
        throw integrationContractErrors.dependencyUnavailable({
          reason: 'integration-contract-compatibility-check-read-result-malformed'
        });
      }
      if (mappedLatestCheck.evaluation_result !== 'compatible') {
        throw integrationContractErrors.contractIncompatible({
          baselineVersion,
          candidateVersion: mappedCandidate.contract_version,
          breakingChangeCount: mappedLatestCheck.breaking_change_count
        });
      }
    }

    const activateStore = assertAuthStoreMethod('activatePlatformIntegrationContractVersion');
    let activatedRecord;
    try {
      activatedRecord = await activateStore.activatePlatformIntegrationContractVersion({
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: mappedCandidate.contract_version,
        operatorUserId: operatorContext.operatorUserId,
        operatorSessionId: operatorContext.operatorSessionId,
        auditContext: {
          requestId: resolvedRequestId,
          traceparent,
          actorUserId: operatorContext.operatorUserId,
          actorSessionId: operatorContext.operatorSessionId
        }
      });
    } catch (error) {
      throw mapStoreError(error);
    }
    const mapped = mapContractRecord({
      record: activatedRecord,
      requestId: resolvedRequestId
    });
    if (
      !mapped
      || !matchesExpectedContractLookup({
        record: mapped,
        integrationId: normalizedIntegrationId,
        contractType: parsedPayload.contractType,
        contractVersion: mappedCandidate.contract_version,
        status: 'active'
      })
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-activation-result-invalid'
      });
    }
    const previousStatus = normalizeContractStatus(
      activatedRecord.previousStatus || activatedRecord.previous_status || ''
    );
    const currentStatus = normalizeContractStatus(
      activatedRecord.currentStatus || activatedRecord.current_status || ''
    );
    if (
      !VALID_CONTRACT_STATUSES.has(previousStatus)
      || !VALID_CONTRACT_STATUSES.has(currentStatus)
      || currentStatus !== mapped.status
    ) {
      throw integrationContractErrors.dependencyUnavailable({
        reason: 'integration-contract-activation-result-malformed'
      });
    }

    addAuditEvent({
      type: 'platform.integration.contract.activate.succeeded',
      requestId: resolvedRequestId,
      operatorUserId: operatorContext.operatorUserId,
      integrationId: normalizedIntegrationId,
      detail: 'integration contract activated',
      metadata: {
        contract_type: parsedPayload.contractType,
        contract_version: mapped.contract_version,
        previous_status: previousStatus,
        current_status: currentStatus
      }
    });

    return {
      ...mapped,
      previous_status: previousStatus,
      current_status: currentStatus
    };
  };

  return {
    listContracts,
    createContract,
    evaluateCompatibility,
    activateContract,
    _internals: {
      authService,
      auditTrail
    }
  };
};

module.exports = {
  createPlatformIntegrationContractService
};
