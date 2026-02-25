'use strict';

const { log } = require('../../../../../common/logger');
const { AuthProblemError } = require('../../../../../shared-kernel/auth/auth-problem-error');
const {
  resolveRoutePreauthorizedContext
} = require('../../../../../shared-kernel/auth/route-authz');
const {
  PLATFORM_INTEGRATION_DIRECTIONS,
  PLATFORM_INTEGRATION_LIFECYCLE_STATUSES,
  PLATFORM_INTEGRATION_VIEW_PERMISSION_CODE,
  PLATFORM_INTEGRATION_OPERATE_PERMISSION_CODE,
  PLATFORM_INTEGRATION_SCOPE
} = require('../constants');

const { normalizeIntegrationId, normalizeStoreIsoTimestamp } = require('./service.helpers');

const integrationProblem = ({
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

const integrationErrors = {
  invalidPayload: (detail = '请求参数不完整或格式错误') =>
    integrationProblem({
      status: 400,
      title: 'Bad Request',
      detail,
      errorCode: 'INT-400-INVALID-PAYLOAD'
    }),

  forbidden: () =>
    integrationProblem({
      status: 403,
      title: 'Forbidden',
      detail: '当前操作无权限',
      errorCode: 'AUTH-403-FORBIDDEN'
    }),

  integrationNotFound: () =>
    integrationProblem({
      status: 404,
      title: 'Not Found',
      detail: '目标集成目录不存在',
      errorCode: 'INT-404-NOT-FOUND',
      extensions: {
        retryable: false
      }
    }),

  codeConflict: () =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '集成编码冲突，请使用其他 code',
      errorCode: 'INT-409-CODE-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  integrationIdConflict: () =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '集成标识冲突，请重试创建流程',
      errorCode: 'INT-409-INTEGRATION-ID-CONFLICT',
      extensions: {
        retryable: false
      }
    }),

  lifecycleConflict: ({
    previousStatus = null,
    requestedStatus = null
  } = {}) =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '生命周期状态流转冲突',
      errorCode: 'INT-409-LIFECYCLE-CONFLICT',
      extensions: {
        retryable: false,
        previous_status: previousStatus,
        requested_status: requestedStatus
      }
    }),

  freezeBlocked: ({
    freezeId = null,
    frozenAt = null
  } = {}) =>
    integrationProblem({
      status: 409,
      title: 'Conflict',
      detail: '发布冻结窗口生效，当前集成变更操作已阻断',
      errorCode: 'INT-409-INTEGRATION-FREEZE-BLOCKED',
      extensions: {
        retryable: false,
        freeze_id: freezeId,
        frozen_at: frozenAt
      }
    }),

  dependencyUnavailable: ({ reason = 'dependency-unavailable' } = {}) =>
    integrationProblem({
      status: 503,
      title: 'Service Unavailable',
      detail: '集成目录治理依赖暂不可用，请稍后重试',
      errorCode: 'INT-503-DEPENDENCY-UNAVAILABLE',
      extensions: {
        retryable: true,
        degradation_reason: String(reason || 'dependency-unavailable').trim()
      }
    })
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
    const conflictTarget = String(
      error?.platformIntegrationCatalogConflictTarget
      || error?.conflictTarget
      || ''
    ).trim().toLowerCase();
    return conflictTarget === 'integration_id'
      ? integrationErrors.integrationIdConflict()
      : integrationErrors.codeConflict();
  }
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_LIFECYCLE_CONFLICT') {
    return integrationErrors.lifecycleConflict({
      previousStatus: error?.previousStatus || null,
      requestedStatus: error?.requestedStatus || null
    });
  }
  if (normalizedErrorCode === 'ERR_PLATFORM_INTEGRATION_FREEZE_ACTIVE_CONFLICT') {
    return integrationErrors.freezeBlocked({
      freezeId: normalizeIntegrationId(error?.freezeId) || null,
      frozenAt: normalizeStoreIsoTimestamp(error?.frozenAt) || null
    });
  }
  return integrationErrors.dependencyUnavailable({
    reason: normalizedErrorCode
      || String(error?.message || 'dependency-unavailable').trim().toLowerCase()
  });
};

module.exports = {
  integrationErrors,
  integrationProblem,
  mapStoreError
};
