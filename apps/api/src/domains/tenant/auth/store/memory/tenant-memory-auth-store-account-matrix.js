'use strict';

const ACCOUNT_STATUS_SET = new Set(['enabled', 'disabled']);
const ACCOUNT_STATUS_MAPPING = Object.freeze({
  active: 'enabled',
  inactive: 'disabled'
});
const MAX_WECHAT_ID_LENGTH = 128;
const MAX_NICKNAME_LENGTH = 128;
const MAX_OPERATION_CONTENT_LENGTH = 1024;
const MAX_OPERATION_TYPE_LENGTH = 64;
const MAX_OPERATOR_NAME_LENGTH = 128;
const MAX_OPERATION_LOG_LIMIT = 200;

const createTenantMemoryAuthStoreAccountMatrix = ({
  randomUUID,
  CONTROL_CHAR_PATTERN,
  tenantsByUserId,
  tenantAccountsByAccountId,
  tenantAccountIdsByTenantId,
  tenantAccountWechatIndexByTenantId,
  tenantAccountAssistantsByAccountId,
  tenantAccountOperationLogsByAccountId,
  clone
} = {}) => {
  const normalizeRequiredString = (value) =>
    typeof value === 'string' ? value.trim() : '';

  const normalizeTenantId = (tenantId) => normalizeRequiredString(tenantId);

  const normalizeWechatId = (wechatId) => {
    const normalized = normalizeRequiredString(wechatId);
    if (
      !normalized
      || normalized.length > MAX_WECHAT_ID_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeNickname = (nickname) => {
    const normalized = normalizeRequiredString(nickname);
    if (
      !normalized
      || normalized.length > MAX_NICKNAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeMembershipId = (membershipId) => {
    const normalized = normalizeRequiredString(membershipId);
    if (
      !normalized
      || normalized.length > 64
      || CONTROL_CHAR_PATTERN.test(normalized)
      || /\s/.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeAccountId = (accountId) => {
    const normalized = normalizeRequiredString(accountId).toLowerCase();
    if (
      !normalized
      || normalized.length > 64
      || CONTROL_CHAR_PATTERN.test(normalized)
      || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeAccountStatus = (status) => {
    const normalized = normalizeRequiredString(status).toLowerCase();
    if (!normalized) {
      return '';
    }
    const mapped = ACCOUNT_STATUS_MAPPING[normalized] || normalized;
    if (!ACCOUNT_STATUS_SET.has(mapped)) {
      return '';
    }
    return mapped;
  };

  const normalizeAssistantMembershipIds = (assistantMembershipIds = []) => {
    const deduped = new Set();
    for (const membershipId of Array.isArray(assistantMembershipIds)
      ? assistantMembershipIds
      : []) {
      const normalizedMembershipId = normalizeMembershipId(membershipId);
      if (normalizedMembershipId) {
        deduped.add(normalizedMembershipId);
      }
    }
    return [...deduped].sort((left, right) => left.localeCompare(right));
  };

  const toIsoTimestamp = (value) => {
    if (value instanceof Date) {
      return value.toISOString();
    }
    if (value === null || value === undefined) {
      return '';
    }
    const asDate = new Date(value);
    if (Number.isNaN(asDate.getTime())) {
      return '';
    }
    return asDate.toISOString();
  };

  const toNonNegativeInteger = (value) => {
    const parsed = Number(value);
    if (!Number.isFinite(parsed) || parsed < 0) {
      return 0;
    }
    return Math.floor(parsed);
  };

  const createWechatConflictError = () => {
    const error = new Error('tenant account wechat conflict');
    error.code = 'ERR_TENANT_ACCOUNT_WECHAT_CONFLICT';
    return error;
  };

  const createNotFoundError = () => {
    const error = new Error('tenant account not found');
    error.code = 'ERR_TENANT_ACCOUNT_NOT_FOUND';
    return error;
  };

  const toAccountIdSetForTenant = (tenantId) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const existing = tenantAccountIdsByTenantId.get(normalizedTenantId);
    if (existing instanceof Set) {
      return existing;
    }
    const next = new Set();
    tenantAccountIdsByTenantId.set(normalizedTenantId, next);
    return next;
  };

  const toWechatIndexForTenant = (tenantId) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const existing = tenantAccountWechatIndexByTenantId.get(normalizedTenantId);
    if (existing instanceof Map) {
      return existing;
    }
    const next = new Map();
    tenantAccountWechatIndexByTenantId.set(normalizedTenantId, next);
    return next;
  };

  const createAccountId = () =>
    `acc_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createOperationId = () =>
    `op_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const resolveTenantMembershipNameById = ({ tenantId, membershipId }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedMembershipId = normalizeMembershipId(membershipId);
    if (!normalizedTenantId || !normalizedMembershipId) {
      return '';
    }
    for (const memberships of tenantsByUserId.values()) {
      for (const membership of Array.isArray(memberships) ? memberships : []) {
        const membershipTenantId = normalizeTenantId(
          membership?.tenantId || membership?.tenant_id
        );
        const currentMembershipId = normalizeMembershipId(
          membership?.membershipId || membership?.membership_id
        );
        if (
          membershipTenantId !== normalizedTenantId
          || currentMembershipId !== normalizedMembershipId
        ) {
          continue;
        }
        const displayName = normalizeRequiredString(
          membership?.displayName || membership?.display_name
        );
        if (displayName) {
          return displayName;
        }
        const userId = normalizeRequiredString(
          membership?.userId || membership?.user_id
        );
        if (userId) {
          return userId;
        }
      }
    }
    return '';
  };

  const toStoredRecord = ({
    accountId,
    tenantId,
    wechatId,
    nickname,
    ownerMembershipId,
    customerCount = 0,
    groupChatCount = 0,
    status = 'enabled',
    avatarUrl = null,
    createdByUserId,
    updatedByUserId,
    createdAt,
    updatedAt
  }) => ({
    account_id: accountId,
    tenant_id: tenantId,
    wechat_id: wechatId,
    nickname,
    owner_membership_id: ownerMembershipId,
    customer_count: toNonNegativeInteger(customerCount),
    group_chat_count: toNonNegativeInteger(groupChatCount),
    status,
    avatar_url: avatarUrl === null || avatarUrl === undefined ? null : String(avatarUrl),
    created_by_user_id: normalizeRequiredString(createdByUserId) || null,
    updated_by_user_id: normalizeRequiredString(updatedByUserId) || null,
    created_at: toIsoTimestamp(createdAt),
    updated_at: toIsoTimestamp(updatedAt)
  });

  const cloneAccountRecord = (record = null) => {
    if (!record || typeof record !== 'object') {
      return null;
    }
    const accountId = normalizeAccountId(record.account_id || record.accountId);
    if (!accountId) {
      return null;
    }
    return {
      ...clone(record),
      assistant_membership_ids: clone(
        tenantAccountAssistantsByAccountId.get(accountId) || []
      )
    };
  };

  const appendOperationLog = ({
    accountId,
    tenantId,
    operationType,
    operationContent,
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  }) => {
    const normalizedAccountId = normalizeAccountId(accountId);
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedAccountId || !normalizedTenantId) {
      return;
    }
    const operationLogs = tenantAccountOperationLogsByAccountId.get(normalizedAccountId) || [];
    const normalizedOperationType =
      normalizeRequiredString(operationType).slice(0, MAX_OPERATION_TYPE_LENGTH)
      || 'update';
    const normalizedOperatorName = normalizeRequiredString(operatorName)
      .slice(0, MAX_OPERATOR_NAME_LENGTH)
      || resolveTenantMembershipNameById({
        tenantId: normalizedTenantId,
        membershipId: operatorUserId
      })
      || null;
    const normalizedOperationContent = normalizeRequiredString(operationContent)
      .slice(0, MAX_OPERATION_CONTENT_LENGTH)
      || null;
    operationLogs.push({
      operation_id: createOperationId(),
      account_id: normalizedAccountId,
      tenant_id: normalizedTenantId,
      operation_type: normalizedOperationType,
      operation_content: normalizedOperationContent,
      operator_user_id: normalizeRequiredString(operatorUserId) || null,
      operator_name: normalizedOperatorName,
      operation_time: toIsoTimestamp(operationAt),
      created_at: toIsoTimestamp(operationAt)
    });
    tenantAccountOperationLogsByAccountId.set(normalizedAccountId, operationLogs);
  };

  const listTenantAccountsByTenantId = async ({
    tenantId,
    filters = {}
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      return [];
    }

    const normalizedWechatFilter = normalizeRequiredString(filters?.wechatId || '').toLowerCase();
    const normalizedNicknameFilter = normalizeRequiredString(filters?.nickname || '').toLowerCase();
    const normalizedOwnerKeywordFilter = normalizeRequiredString(filters?.ownerKeyword || '').toLowerCase();
    const normalizedAssistantKeywordFilter = normalizeRequiredString(filters?.assistantKeyword || '').toLowerCase();
    const normalizedStatusFilter = normalizeAccountStatus(filters?.status || '') || '';
    const createdAtStartEpoch = filters?.createdAtStart
      ? Date.parse(filters.createdAtStart)
      : Number.NaN;
    const createdAtEndEpoch = filters?.createdAtEnd
      ? Date.parse(filters.createdAtEnd)
      : Number.NaN;

    const accountIds = [...(toAccountIdSetForTenant(normalizedTenantId) || [])];
    const records = accountIds
      .map((accountId) => cloneAccountRecord(tenantAccountsByAccountId.get(accountId)))
      .filter(Boolean)
      .filter((record) => {
        const wechatId = normalizeRequiredString(record.wechat_id).toLowerCase();
        const nickname = normalizeRequiredString(record.nickname).toLowerCase();
        const status = normalizeAccountStatus(record.status);
        if (normalizedWechatFilter && wechatId !== normalizedWechatFilter) {
          return false;
        }
        if (normalizedNicknameFilter && !nickname.includes(normalizedNicknameFilter)) {
          return false;
        }
        if (normalizedStatusFilter && status !== normalizedStatusFilter) {
          return false;
        }

        if (!Number.isNaN(createdAtStartEpoch) || !Number.isNaN(createdAtEndEpoch)) {
          const createdAtEpoch = Date.parse(record.created_at);
          if (Number.isNaN(createdAtEpoch)) {
            return false;
          }
          if (!Number.isNaN(createdAtStartEpoch) && createdAtEpoch < createdAtStartEpoch) {
            return false;
          }
          if (!Number.isNaN(createdAtEndEpoch) && createdAtEpoch > createdAtEndEpoch) {
            return false;
          }
        }

        if (normalizedOwnerKeywordFilter) {
          const ownerName = resolveTenantMembershipNameById({
            tenantId: normalizedTenantId,
            membershipId: record.owner_membership_id
          }).toLowerCase();
          if (!ownerName.includes(normalizedOwnerKeywordFilter)) {
            return false;
          }
        }

        if (normalizedAssistantKeywordFilter) {
          const assistants = Array.isArray(record.assistant_membership_ids)
            ? record.assistant_membership_ids
            : [];
          const hasMatchedAssistant = assistants.some((assistantMembershipId) =>
            resolveTenantMembershipNameById({
              tenantId: normalizedTenantId,
              membershipId: assistantMembershipId
            }).toLowerCase().includes(normalizedAssistantKeywordFilter)
          );
          if (!hasMatchedAssistant) {
            return false;
          }
        }

        return true;
      })
      .sort((left, right) => {
        const leftCreatedAt = Date.parse(left.created_at || 0);
        const rightCreatedAt = Date.parse(right.created_at || 0);
        if (leftCreatedAt !== rightCreatedAt) {
          return rightCreatedAt - leftCreatedAt;
        }
        return String(right.account_id).localeCompare(String(left.account_id));
      });

    return records;
  };

  const findTenantAccountByAccountId = async ({
    tenantId,
    accountId
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountId = normalizeAccountId(accountId);
    if (!normalizedTenantId || !normalizedAccountId) {
      return null;
    }
    const record = cloneAccountRecord(tenantAccountsByAccountId.get(normalizedAccountId));
    if (!record) {
      return null;
    }
    if (normalizeTenantId(record.tenant_id) !== normalizedTenantId) {
      return null;
    }
    return record;
  };

  const createTenantAccount = async ({
    tenantId,
    wechatId,
    nickname,
    ownerMembershipId,
    assistantMembershipIds = [],
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedWechatId = normalizeWechatId(wechatId);
    const normalizedWechatIdKey = normalizedWechatId.toLowerCase();
    const normalizedNickname = normalizeNickname(nickname);
    const normalizedOwnerMembershipId = normalizeMembershipId(ownerMembershipId);
    const normalizedAssistantMembershipIds = normalizeAssistantMembershipIds(
      assistantMembershipIds
    );

    if (
      !normalizedTenantId
      || !normalizedWechatId
      || !normalizedNickname
      || !normalizedOwnerMembershipId
    ) {
      throw new Error('invalid account payload');
    }

    const wechatIndex = toWechatIndexForTenant(normalizedTenantId);
    if (wechatIndex.has(normalizedWechatIdKey)) {
      throw createWechatConflictError();
    }

    let normalizedAccountId = '';
    do {
      normalizedAccountId = normalizeAccountId(createAccountId());
    } while (
      !normalizedAccountId
      || tenantAccountsByAccountId.has(normalizedAccountId)
    );

    const normalizedOperationAt = toIsoTimestamp(operationAt) || new Date().toISOString();
    const record = toStoredRecord({
      accountId: normalizedAccountId,
      tenantId: normalizedTenantId,
      wechatId: normalizedWechatId,
      nickname: normalizedNickname,
      ownerMembershipId: normalizedOwnerMembershipId,
      customerCount: 0,
      groupChatCount: 0,
      status: 'enabled',
      avatarUrl: null,
      createdByUserId: operatorUserId,
      updatedByUserId: operatorUserId,
      createdAt: normalizedOperationAt,
      updatedAt: normalizedOperationAt
    });

    tenantAccountsByAccountId.set(normalizedAccountId, record);
    toAccountIdSetForTenant(normalizedTenantId).add(normalizedAccountId);
    wechatIndex.set(normalizedWechatIdKey, normalizedAccountId);
    tenantAccountAssistantsByAccountId.set(
      normalizedAccountId,
      normalizedAssistantMembershipIds
    );

    appendOperationLog({
      accountId: normalizedAccountId,
      tenantId: normalizedTenantId,
      operationType: 'create',
      operationContent: `新建账号：${normalizedWechatId}`,
      operatorUserId,
      operatorName,
      operationAt: normalizedOperationAt
    });

    return cloneAccountRecord(record);
  };

  const updateTenantAccount = async ({
    tenantId,
    accountId,
    wechatId,
    nickname,
    ownerMembershipId,
    assistantMembershipIds = [],
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountId = normalizeAccountId(accountId);
    const normalizedWechatId = normalizeWechatId(wechatId);
    const normalizedWechatIdKey = normalizedWechatId.toLowerCase();
    const normalizedNickname = normalizeNickname(nickname);
    const normalizedOwnerMembershipId = normalizeMembershipId(ownerMembershipId);
    const normalizedAssistantMembershipIds = normalizeAssistantMembershipIds(
      assistantMembershipIds
    );

    if (
      !normalizedTenantId
      || !normalizedAccountId
      || !normalizedWechatId
      || !normalizedNickname
      || !normalizedOwnerMembershipId
    ) {
      throw new Error('invalid account payload');
    }

    const existingRecord = tenantAccountsByAccountId.get(normalizedAccountId);
    if (!existingRecord) {
      return null;
    }
    if (normalizeTenantId(existingRecord.tenant_id) !== normalizedTenantId) {
      return null;
    }

    const previousWechatIdKey = normalizeWechatId(existingRecord.wechat_id).toLowerCase();
    const wechatIndex = toWechatIndexForTenant(normalizedTenantId);
    const duplicateAccountId = normalizeAccountId(wechatIndex.get(normalizedWechatIdKey));
    if (
      duplicateAccountId
      && duplicateAccountId !== normalizedAccountId
    ) {
      throw createWechatConflictError();
    }

    const normalizedOperationAt = toIsoTimestamp(operationAt) || new Date().toISOString();
    const nextRecord = toStoredRecord({
      accountId: normalizedAccountId,
      tenantId: normalizedTenantId,
      wechatId: normalizedWechatId,
      nickname: normalizedNickname,
      ownerMembershipId: normalizedOwnerMembershipId,
      customerCount: existingRecord.customer_count,
      groupChatCount: existingRecord.group_chat_count,
      status: normalizeAccountStatus(existingRecord.status) || 'enabled',
      avatarUrl: existingRecord.avatar_url,
      createdByUserId: existingRecord.created_by_user_id,
      updatedByUserId: operatorUserId,
      createdAt: existingRecord.created_at,
      updatedAt: normalizedOperationAt
    });

    tenantAccountsByAccountId.set(normalizedAccountId, nextRecord);
    tenantAccountAssistantsByAccountId.set(
      normalizedAccountId,
      normalizedAssistantMembershipIds
    );
    if (previousWechatIdKey !== normalizedWechatIdKey) {
      wechatIndex.delete(previousWechatIdKey);
      wechatIndex.set(normalizedWechatIdKey, normalizedAccountId);
    }

    appendOperationLog({
      accountId: normalizedAccountId,
      tenantId: normalizedTenantId,
      operationType: 'update',
      operationContent: `编辑账号：${normalizedWechatId}`,
      operatorUserId,
      operatorName,
      operationAt: normalizedOperationAt
    });

    return cloneAccountRecord(nextRecord);
  };

  const updateTenantAccountStatus = async ({
    tenantId,
    accountId,
    status,
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountId = normalizeAccountId(accountId);
    const normalizedStatus = normalizeAccountStatus(status);
    if (!normalizedTenantId || !normalizedAccountId || !normalizedStatus) {
      throw new Error('invalid account status payload');
    }

    const existingRecord = tenantAccountsByAccountId.get(normalizedAccountId);
    if (!existingRecord) {
      return null;
    }
    if (normalizeTenantId(existingRecord.tenant_id) !== normalizedTenantId) {
      return null;
    }

    const normalizedOperationAt = toIsoTimestamp(operationAt) || new Date().toISOString();
    const nextRecord = toStoredRecord({
      accountId: normalizedAccountId,
      tenantId: normalizedTenantId,
      wechatId: existingRecord.wechat_id,
      nickname: existingRecord.nickname,
      ownerMembershipId: existingRecord.owner_membership_id,
      customerCount: existingRecord.customer_count,
      groupChatCount: existingRecord.group_chat_count,
      status: normalizedStatus,
      avatarUrl: existingRecord.avatar_url,
      createdByUserId: existingRecord.created_by_user_id,
      updatedByUserId: operatorUserId,
      createdAt: existingRecord.created_at,
      updatedAt: normalizedOperationAt
    });

    tenantAccountsByAccountId.set(normalizedAccountId, nextRecord);

    appendOperationLog({
      accountId: normalizedAccountId,
      tenantId: normalizedTenantId,
      operationType: 'status',
      operationContent: `账号状态更新为：${normalizedStatus}`,
      operatorUserId,
      operatorName,
      operationAt: normalizedOperationAt
    });

    return cloneAccountRecord(nextRecord);
  };

  const listTenantAccountOperationLogs = async ({
    tenantId,
    accountId,
    limit = MAX_OPERATION_LOG_LIMIT
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountId = normalizeAccountId(accountId);
    if (!normalizedTenantId || !normalizedAccountId) {
      return [];
    }

    const account = tenantAccountsByAccountId.get(normalizedAccountId);
    if (!account || normalizeTenantId(account.tenant_id) !== normalizedTenantId) {
      return [];
    }

    const normalizedLimit = Number.isFinite(Number(limit))
      ? Math.max(1, Math.min(MAX_OPERATION_LOG_LIMIT, Math.floor(Number(limit))))
      : MAX_OPERATION_LOG_LIMIT;

    const operationLogs = tenantAccountOperationLogsByAccountId.get(normalizedAccountId) || [];
    return [...operationLogs]
      .map((operationLog) => clone(operationLog))
      .sort((left, right) => {
        const leftAt = Date.parse(left?.operation_time || left?.created_at || 0);
        const rightAt = Date.parse(right?.operation_time || right?.created_at || 0);
        if (leftAt !== rightAt) {
          return rightAt - leftAt;
        }
        return String(right?.operation_id || '').localeCompare(String(left?.operation_id || ''));
      })
      .slice(0, normalizedLimit);
  };

  return {
    listTenantAccountsByTenantId,
    createTenantAccount,
    updateTenantAccount,
    updateTenantAccountStatus,
    findTenantAccountByAccountId,
    listTenantAccountOperationLogs
  };
};

module.exports = {
  createTenantMemoryAuthStoreAccountMatrix
};
