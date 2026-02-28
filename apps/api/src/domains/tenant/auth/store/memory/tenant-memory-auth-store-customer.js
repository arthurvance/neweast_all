'use strict';

const CUSTOMER_STATUS_SET = new Set(['enabled', 'disabled']);
const SOURCE_VALUE_SET = new Set(['ground', 'fission', 'other']);
const MAX_CUSTOMER_ID_LENGTH = 64;
const MAX_ACCOUNT_ID_LENGTH = 64;
const MAX_WECHAT_ID_LENGTH = 128;
const MAX_NICKNAME_LENGTH = 128;
const MAX_SOURCE_LENGTH = 16;
const MAX_REAL_NAME_LENGTH = 64;
const MAX_SCHOOL_LENGTH = 128;
const MAX_CLASS_NAME_LENGTH = 128;
const MAX_RELATION_LENGTH = 128;
const MAX_PHONE_LENGTH = 32;
const MAX_ADDRESS_LENGTH = 255;
const MAX_OPERATION_TYPE_LENGTH = 64;
const MAX_OPERATION_CONTENT_LENGTH = 2048;
const MAX_OPERATOR_NAME_LENGTH = 128;
const MAX_OPERATION_LOG_LIMIT = 200;

const createTenantMemoryAuthStoreCustomer = ({
  randomUUID,
  CONTROL_CHAR_PATTERN,
  tenantsByUserId,
  tenantAccountsByAccountId,
  tenantAccountAssistantsByAccountId,
  tenantCustomersByCustomerId,
  tenantCustomerIdsByTenantId,
  tenantCustomerWechatIndexByTenantId,
  tenantCustomerProfileByCustomerId,
  tenantCustomerOperationLogsByCustomerId,
  clone
} = {}) => {
  const cloneValue = (value) => {
    if (typeof clone === 'function') {
      return clone(value);
    }
    if (value === null || value === undefined) {
      return value;
    }
    return JSON.parse(JSON.stringify(value));
  };

  const normalizeRequiredString = (value) =>
    typeof value === 'string' ? value.trim() : '';

  const normalizeTenantId = (tenantId) => normalizeRequiredString(tenantId);

  const normalizeAccountId = (accountId) => {
    const normalized = normalizeRequiredString(accountId).toLowerCase();
    if (
      !normalized
      || normalized.length > MAX_ACCOUNT_ID_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
      || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeCustomerId = (customerId) => {
    const normalized = normalizeRequiredString(customerId).toLowerCase();
    if (
      !normalized
      || normalized.length > MAX_CUSTOMER_ID_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
      || !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeOptionalWechatId = (wechatId, { allowUndefined = false } = {}) => {
    if (wechatId === undefined) {
      return allowUndefined ? undefined : null;
    }
    if (wechatId === null) {
      return null;
    }
    const normalized = normalizeRequiredString(wechatId);
    if (!normalized) {
      return null;
    }
    if (
      normalized.length > MAX_WECHAT_ID_LENGTH
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

  const normalizeSource = (source) => {
    const normalized = normalizeRequiredString(source).toLowerCase();
    if (
      !normalized
      || normalized.length > MAX_SOURCE_LENGTH
      || !SOURCE_VALUE_SET.has(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeStatus = (status) => {
    const normalized = normalizeRequiredString(status).toLowerCase();
    if (!normalized || !CUSTOMER_STATUS_SET.has(normalized)) {
      return '';
    }
    return normalized;
  };

  const normalizeOptionalProfileField = ({
    value,
    maxLength
  } = {}) => {
    if (value === undefined) {
      return undefined;
    }
    if (value === null) {
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

  const toNullableProfileField = (value) =>
    value === undefined ? null : value;

  const toIsoTimestamp = (value) => {
    if (value instanceof Date) {
      return value.toISOString();
    }
    if (value === null || value === undefined) {
      return '';
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '';
    }
    return parsed.toISOString();
  };

  const createWechatConflictError = () => {
    const error = new Error('tenant customer wechat conflict');
    error.code = 'ERR_TENANT_CUSTOMER_WECHAT_CONFLICT';
    return error;
  };

  const createAccountNotFoundError = () => {
    const error = new Error('tenant customer account not found');
    error.code = 'ERR_TENANT_CUSTOMER_ACCOUNT_NOT_FOUND';
    return error;
  };

  const createCustomerId = () =>
    `cus_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createOperationId = () =>
    `cop_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const toCustomerIdSetForTenant = (tenantId) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const existing = tenantCustomerIdsByTenantId.get(normalizedTenantId);
    if (existing instanceof Set) {
      return existing;
    }
    const next = new Set();
    tenantCustomerIdsByTenantId.set(normalizedTenantId, next);
    return next;
  };

  const toWechatIndexForTenant = (tenantId) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const existing = tenantCustomerWechatIndexByTenantId.get(normalizedTenantId);
    if (existing instanceof Map) {
      return existing;
    }
    const next = new Map();
    tenantCustomerWechatIndexByTenantId.set(normalizedTenantId, next);
    return next;
  };

  const toProfileRecord = ({
    customerId,
    tenantId,
    realName = null,
    school = null,
    className = null,
    relation = null,
    phone = null,
    address = null,
    createdAt,
    updatedAt
  }) => ({
    customer_id: customerId,
    tenant_id: tenantId,
    real_name: realName,
    school,
    class_name: className,
    relation,
    phone,
    address,
    created_at: toIsoTimestamp(createdAt),
    updated_at: toIsoTimestamp(updatedAt)
  });

  const toCustomerRecord = ({
    customerId,
    tenantId,
    accountId,
    wechatId,
    nickname,
    source,
    status,
    createdByUserId = null,
    updatedByUserId = null,
    createdAt,
    updatedAt
  }) => ({
    customer_id: customerId,
    tenant_id: tenantId,
    account_id: accountId,
    wechat_id: wechatId,
    nickname,
    source,
    status,
    created_by_user_id: normalizeRequiredString(createdByUserId) || null,
    updated_by_user_id: normalizeRequiredString(updatedByUserId) || null,
    created_at: toIsoTimestamp(createdAt),
    updated_at: toIsoTimestamp(updatedAt)
  });

  const appendOperationLog = ({
    tenantId,
    customerId,
    operationType,
    operationContent,
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedCustomerId = normalizeCustomerId(customerId);
    if (!normalizedTenantId || !normalizedCustomerId) {
      return;
    }
    const operationLogs = tenantCustomerOperationLogsByCustomerId.get(normalizedCustomerId) || [];
    const normalizedOperationType =
      normalizeRequiredString(operationType).slice(0, MAX_OPERATION_TYPE_LENGTH)
      || 'update';
    const normalizedOperationContent = normalizeRequiredString(operationContent)
      .slice(0, MAX_OPERATION_CONTENT_LENGTH)
      || null;
    const normalizedOperationAt = toIsoTimestamp(operationAt) || new Date().toISOString();
    operationLogs.push({
      operation_id: createOperationId(),
      customer_id: normalizedCustomerId,
      tenant_id: normalizedTenantId,
      operation_type: normalizedOperationType,
      operation_content: normalizedOperationContent,
      operator_user_id: normalizeRequiredString(operatorUserId) || null,
      operator_name: normalizeRequiredString(operatorName).slice(0, MAX_OPERATOR_NAME_LENGTH) || null,
      operation_time: normalizedOperationAt,
      created_at: normalizedOperationAt
    });
    tenantCustomerOperationLogsByCustomerId.set(normalizedCustomerId, operationLogs);
  };

  const toCombinedCustomerRecord = (customerRecord = null) => {
    if (!customerRecord || typeof customerRecord !== 'object') {
      return null;
    }
    const normalizedCustomerId = normalizeCustomerId(customerRecord.customer_id);
    if (!normalizedCustomerId) {
      return null;
    }
    const profileRecord = tenantCustomerProfileByCustomerId.get(normalizedCustomerId);
    return {
      ...cloneValue(customerRecord),
      real_name: profileRecord?.real_name ?? null,
      school: profileRecord?.school ?? null,
      class_name: profileRecord?.class_name ?? null,
      relation: profileRecord?.relation ?? null,
      phone: profileRecord?.phone ?? null,
      address: profileRecord?.address ?? null
    };
  };

  const resolveMembershipIdSetForOperator = ({
    tenantId,
    operatorUserId
  }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedOperatorUserId = normalizeRequiredString(operatorUserId);
    if (!normalizedTenantId || !normalizedOperatorUserId) {
      return new Set();
    }
    const memberships = tenantsByUserId.get(normalizedOperatorUserId);
    const membershipIdSet = new Set();
    for (const membership of Array.isArray(memberships) ? memberships : []) {
      const membershipTenantId = normalizeTenantId(
        membership?.tenantId || membership?.tenant_id
      );
      const membershipId = normalizeRequiredString(
        membership?.membershipId || membership?.membership_id
      );
      const membershipStatus = normalizeRequiredString(membership?.status).toLowerCase();
      if (
        membershipTenantId === normalizedTenantId
        && membershipId
        && (membershipStatus === 'active' || membershipStatus === 'enabled')
      ) {
        membershipIdSet.add(membershipId);
      }
    }
    return membershipIdSet;
  };

  const hasScopeAccess = ({
    customerRecord,
    scope,
    operatorMembershipIdSet
  }) => {
    if (scope === 'all') {
      return true;
    }
    if (!(operatorMembershipIdSet instanceof Set) || operatorMembershipIdSet.size < 1) {
      return false;
    }
    const accountId = normalizeAccountId(customerRecord?.account_id);
    if (!accountId) {
      return false;
    }
    const accountRecord = tenantAccountsByAccountId.get(accountId);
    if (!accountRecord || typeof accountRecord !== 'object') {
      return false;
    }
    if (scope === 'my') {
      const ownerMembershipId = normalizeRequiredString(accountRecord.owner_membership_id);
      return operatorMembershipIdSet.has(ownerMembershipId);
    }
    if (scope === 'assist') {
      const assistants = tenantAccountAssistantsByAccountId.get(accountId) || [];
      for (const assistantMembershipId of Array.isArray(assistants) ? assistants : []) {
        if (operatorMembershipIdSet.has(normalizeRequiredString(assistantMembershipId))) {
          return true;
        }
      }
      return false;
    }
    return false;
  };

  const toScopeSet = (scopes) => {
    const source = scopes instanceof Set
      ? [...scopes]
      : (Array.isArray(scopes) ? scopes : [scopes]);
    return new Set(
      source
        .map((scope) => normalizeRequiredString(scope).toLowerCase())
        .filter((scope) => scope === 'my' || scope === 'assist' || scope === 'all')
    );
  };

  const hasAnyScopeAccess = ({
    customerRecord,
    operatorMembershipIdSet,
    scopeSet
  }) => {
    if (!(scopeSet instanceof Set) || scopeSet.size < 1) {
      return false;
    }
    if (scopeSet.has('all')) {
      return true;
    }
    if (scopeSet.has('my') && hasScopeAccess({ customerRecord, scope: 'my', operatorMembershipIdSet })) {
      return true;
    }
    if (
      scopeSet.has('assist')
      && hasScopeAccess({ customerRecord, scope: 'assist', operatorMembershipIdSet })
    ) {
      return true;
    }
    return false;
  };

  const listTenantCustomersByTenantId = async ({
    tenantId,
    operatorUserId,
    scope = 'my',
    filters = {}
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      return [];
    }

    const normalizedScope = normalizeRequiredString(scope).toLowerCase();
    const operatorMembershipIdSet = resolveMembershipIdSetForOperator({
      tenantId: normalizedTenantId,
      operatorUserId
    });

    const normalizedWechatId = normalizeRequiredString(filters?.wechatId).toLowerCase();
    const normalizedNickname = normalizeRequiredString(filters?.nickname).toLowerCase();
    const normalizedSource = normalizeRequiredString(filters?.source).toLowerCase();
    const normalizedRealName = normalizeRequiredString(filters?.realName).toLowerCase();
    const normalizedPhone = normalizeRequiredString(filters?.phone);
    const normalizedStatus = normalizeRequiredString(filters?.status).toLowerCase();
    const normalizedAccountIds = new Set(
      (Array.isArray(filters?.accountIds) ? filters.accountIds : [])
        .map((accountId) => normalizeAccountId(accountId))
        .filter((accountId) => accountId.length > 0)
    );
    const createdAtStartEpoch = filters?.createdAtStart
      ? Date.parse(filters.createdAtStart)
      : Number.NaN;
    const createdAtEndEpoch = filters?.createdAtEnd
      ? Date.parse(filters.createdAtEnd)
      : Number.NaN;

    const customerIdSet = toCustomerIdSetForTenant(normalizedTenantId);
    return [...customerIdSet]
      .map((customerId) => toCombinedCustomerRecord(tenantCustomersByCustomerId.get(customerId)))
      .filter(Boolean)
      .filter((customerRecord) => {
        if (
          normalizedScope
          && normalizedScope !== 'all'
          && normalizedScope !== 'my'
          && normalizedScope !== 'assist'
        ) {
          return false;
        }
        if (
          normalizedScope
          && !hasScopeAccess({
            customerRecord,
            scope: normalizedScope,
            operatorMembershipIdSet
          })
        ) {
          return false;
        }
        if (
          normalizedWechatId
          && !normalizeRequiredString(customerRecord.wechat_id).toLowerCase().includes(normalizedWechatId)
        ) {
          return false;
        }
        if (
          normalizedAccountIds.size > 0
          && !normalizedAccountIds.has(normalizeAccountId(customerRecord.account_id))
        ) {
          return false;
        }
        if (
          normalizedNickname
          && !normalizeRequiredString(customerRecord.nickname).toLowerCase().includes(normalizedNickname)
        ) {
          return false;
        }
        if (
          normalizedSource
          && normalizeRequiredString(customerRecord.source).toLowerCase() !== normalizedSource
        ) {
          return false;
        }
        if (
          normalizedRealName
          && !normalizeRequiredString(customerRecord.real_name).toLowerCase().includes(normalizedRealName)
        ) {
          return false;
        }
        if (
          normalizedPhone
          && normalizeRequiredString(customerRecord.phone) !== normalizedPhone
        ) {
          return false;
        }
        if (
          normalizedStatus
          && normalizeRequiredString(customerRecord.status).toLowerCase() !== normalizedStatus
        ) {
          return false;
        }
        if (!Number.isNaN(createdAtStartEpoch) || !Number.isNaN(createdAtEndEpoch)) {
          const createdAtEpoch = Date.parse(customerRecord.created_at);
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
        return true;
      })
      .sort((left, right) => {
        const leftCreatedAt = Date.parse(left.created_at || 0);
        const rightCreatedAt = Date.parse(right.created_at || 0);
        if (leftCreatedAt !== rightCreatedAt) {
          return rightCreatedAt - leftCreatedAt;
        }
        return String(right.customer_id).localeCompare(String(left.customer_id));
      });
  };

  const createTenantCustomer = async ({
    tenantId,
    accountId,
    wechatId,
    nickname,
    source,
    status = 'enabled',
    realName = null,
    school = null,
    className = null,
    relation = null,
    phone = null,
    address = null,
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountId = normalizeAccountId(accountId);
    const normalizedWechatId = normalizeOptionalWechatId(wechatId, {
      allowUndefined: true
    });
    const normalizedNickname = normalizeNickname(nickname);
    const normalizedSource = normalizeSource(source);
    const normalizedStatus = normalizeStatus(status) || 'enabled';
    if (
      !normalizedTenantId
      || !normalizedAccountId
      || normalizedWechatId === ''
      || !normalizedNickname
      || !normalizedSource
      || !normalizedStatus
    ) {
      throw new Error('invalid customer payload');
    }

    const accountRecord = tenantAccountsByAccountId.get(normalizedAccountId);
    if (
      !accountRecord
      || normalizeTenantId(accountRecord.tenant_id) !== normalizedTenantId
      || normalizeStatus(accountRecord.status) !== 'enabled'
    ) {
      throw createAccountNotFoundError();
    }

    const tenantWechatIndex = toWechatIndexForTenant(normalizedTenantId);
    const normalizedWechatKey = typeof normalizedWechatId === 'string'
      ? normalizedWechatId.toLowerCase()
      : '';
    if (normalizedWechatKey && tenantWechatIndex.has(normalizedWechatKey)) {
      throw createWechatConflictError();
    }

    let normalizedCustomerId = '';
    do {
      normalizedCustomerId = normalizeCustomerId(createCustomerId());
    } while (
      !normalizedCustomerId
      || tenantCustomersByCustomerId.has(normalizedCustomerId)
    );

    const normalizedOperationAt = toIsoTimestamp(operationAt) || new Date().toISOString();
    const customerRecord = toCustomerRecord({
      customerId: normalizedCustomerId,
      tenantId: normalizedTenantId,
      accountId: normalizedAccountId,
      wechatId: normalizedWechatId === undefined ? null : normalizedWechatId,
      nickname: normalizedNickname,
      source: normalizedSource,
      status: normalizedStatus,
      createdByUserId: operatorUserId,
      updatedByUserId: operatorUserId,
      createdAt: normalizedOperationAt,
      updatedAt: normalizedOperationAt
    });

    tenantCustomersByCustomerId.set(normalizedCustomerId, customerRecord);
    toCustomerIdSetForTenant(normalizedTenantId).add(normalizedCustomerId);
    if (normalizedWechatKey) {
      tenantWechatIndex.set(normalizedWechatKey, normalizedCustomerId);
    }
    const normalizedAccountCustomerCount = Number.isFinite(Number(accountRecord.customer_count))
      ? Math.max(0, Math.floor(Number(accountRecord.customer_count)))
      : 0;
    tenantAccountsByAccountId.set(normalizedAccountId, {
      ...accountRecord,
      customer_count: normalizedAccountCustomerCount + 1
    });
    tenantCustomerProfileByCustomerId.set(
      normalizedCustomerId,
      toProfileRecord({
        customerId: normalizedCustomerId,
        tenantId: normalizedTenantId,
        realName: toNullableProfileField(normalizeOptionalProfileField({
          value: realName,
          maxLength: MAX_REAL_NAME_LENGTH
        })),
        school: toNullableProfileField(normalizeOptionalProfileField({
          value: school,
          maxLength: MAX_SCHOOL_LENGTH
        })),
        className: toNullableProfileField(normalizeOptionalProfileField({
          value: className,
          maxLength: MAX_CLASS_NAME_LENGTH
        })),
        relation: toNullableProfileField(normalizeOptionalProfileField({
          value: relation,
          maxLength: MAX_RELATION_LENGTH
        })),
        phone: toNullableProfileField(normalizeOptionalProfileField({
          value: phone,
          maxLength: MAX_PHONE_LENGTH
        })),
        address: toNullableProfileField(normalizeOptionalProfileField({
          value: address,
          maxLength: MAX_ADDRESS_LENGTH
        })),
        createdAt: normalizedOperationAt,
        updatedAt: normalizedOperationAt
      })
    );
    appendOperationLog({
      tenantId: normalizedTenantId,
      customerId: normalizedCustomerId,
      operationType: 'create',
      operationContent: JSON.stringify({
        source: normalizedSource,
        status: normalizedStatus
      }),
      operatorUserId,
      operatorName,
      operationAt: normalizedOperationAt
    });

    return toCombinedCustomerRecord(customerRecord);
  };

  const findTenantCustomerByCustomerId = async ({
    tenantId,
    customerId,
    operatorUserId = null,
    scopes = ['all']
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedCustomerId = normalizeCustomerId(customerId);
    if (!normalizedTenantId || !normalizedCustomerId) {
      return null;
    }
    const customerRecord = tenantCustomersByCustomerId.get(normalizedCustomerId);
    if (!customerRecord) {
      return null;
    }
    if (normalizeTenantId(customerRecord.tenant_id) !== normalizedTenantId) {
      return null;
    }
    const scopeSet = toScopeSet(scopes);
    if (!scopeSet.has('all')) {
      const operatorMembershipIdSet = resolveMembershipIdSetForOperator({
        tenantId: normalizedTenantId,
        operatorUserId
      });
      if (
        !hasAnyScopeAccess({
          customerRecord,
          operatorMembershipIdSet,
          scopeSet
        })
      ) {
        return null;
      }
    }
    return toCombinedCustomerRecord(customerRecord);
  };

  const updateTenantCustomer = async ({
    tenantId,
    customerId,
    scopes = ['all'],
    wechatId = undefined,
    nickname,
    source,
    realName = undefined,
    school = undefined,
    className = undefined,
    relation = undefined,
    phone = undefined,
    address = undefined,
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedCustomerId = normalizeCustomerId(customerId);
    const normalizedWechatId = normalizeOptionalWechatId(wechatId, {
      allowUndefined: true
    });
    const normalizedNickname = normalizeNickname(nickname);
    const normalizedSource = normalizeSource(source);
    if (
      !normalizedTenantId
      || !normalizedCustomerId
      || normalizedWechatId === ''
      || !normalizedNickname
      || !normalizedSource
    ) {
      throw new Error('invalid customer update payload');
    }
    const existing = tenantCustomersByCustomerId.get(normalizedCustomerId);
    if (!existing || normalizeTenantId(existing.tenant_id) !== normalizedTenantId) {
      return null;
    }
    const scopeSet = toScopeSet(scopes);
    const operatorMembershipIdSet = resolveMembershipIdSetForOperator({
      tenantId: normalizedTenantId,
      operatorUserId
    });
    if (
      !hasAnyScopeAccess({
        customerRecord: existing,
        operatorMembershipIdSet,
        scopeSet
      })
    ) {
      return null;
    }
    const normalizedOperationAt = toIsoTimestamp(operationAt) || new Date().toISOString();
    const existingWechatId = normalizeOptionalWechatId(existing.wechat_id);
    if (existingWechatId === '') {
      throw new Error('invalid persisted customer wechat_id');
    }
    const resolvedWechatId =
      normalizedWechatId === undefined
        ? existingWechatId
        : normalizedWechatId;
    const existingWechatKey = typeof existingWechatId === 'string'
      ? existingWechatId.toLowerCase()
      : '';
    const resolvedWechatKey = typeof resolvedWechatId === 'string'
      ? resolvedWechatId.toLowerCase()
      : '';
    const tenantWechatIndex = toWechatIndexForTenant(normalizedTenantId);
    if (resolvedWechatKey && resolvedWechatKey !== existingWechatKey) {
      const existingWechatOwnerId = normalizeCustomerId(tenantWechatIndex.get(resolvedWechatKey));
      if (existingWechatOwnerId && existingWechatOwnerId !== normalizedCustomerId) {
        throw createWechatConflictError();
      }
    }

    const existingProfile = tenantCustomerProfileByCustomerId.get(normalizedCustomerId) || {};
    const nextRealName = normalizeOptionalProfileField({
      value: realName,
      maxLength: MAX_REAL_NAME_LENGTH
    });
    const nextSchool = normalizeOptionalProfileField({
      value: school,
      maxLength: MAX_SCHOOL_LENGTH
    });
    const nextClassName = normalizeOptionalProfileField({
      value: className,
      maxLength: MAX_CLASS_NAME_LENGTH
    });
    const nextRelation = normalizeOptionalProfileField({
      value: relation,
      maxLength: MAX_RELATION_LENGTH
    });
    const nextPhone = normalizeOptionalProfileField({
      value: phone,
      maxLength: MAX_PHONE_LENGTH
    });
    const nextAddress = normalizeOptionalProfileField({
      value: address,
      maxLength: MAX_ADDRESS_LENGTH
    });
    tenantCustomerProfileByCustomerId.set(
      normalizedCustomerId,
      toProfileRecord({
        customerId: normalizedCustomerId,
        tenantId: normalizedTenantId,
        realName: nextRealName === undefined ? existingProfile.real_name ?? null : nextRealName,
        school: nextSchool === undefined ? existingProfile.school ?? null : nextSchool,
        className: nextClassName === undefined ? existingProfile.class_name ?? null : nextClassName,
        relation: nextRelation === undefined ? existingProfile.relation ?? null : nextRelation,
        phone: nextPhone === undefined ? existingProfile.phone ?? null : nextPhone,
        address: nextAddress === undefined ? existingProfile.address ?? null : nextAddress,
        createdAt: existingProfile.created_at || normalizedOperationAt,
        updatedAt: normalizedOperationAt
      })
    );

    const nextRecord = toCustomerRecord({
      customerId: normalizedCustomerId,
      tenantId: normalizedTenantId,
      accountId: existing.account_id,
      wechatId: resolvedWechatId,
      nickname: normalizedNickname,
      source: normalizedSource,
      status: existing.status,
      createdByUserId: existing.created_by_user_id,
      updatedByUserId: operatorUserId,
      createdAt: existing.created_at,
      updatedAt: normalizedOperationAt
    });
    tenantCustomersByCustomerId.set(normalizedCustomerId, nextRecord);
    if (existingWechatKey && existingWechatKey !== resolvedWechatKey) {
      tenantWechatIndex.delete(existingWechatKey);
    }
    if (resolvedWechatKey) {
      tenantWechatIndex.set(resolvedWechatKey, normalizedCustomerId);
    }
    appendOperationLog({
      tenantId: normalizedTenantId,
      customerId: normalizedCustomerId,
      operationType: 'update',
      operationContent: JSON.stringify({
        wechat_id: normalizedWechatId,
        nickname: normalizedNickname,
        source: normalizedSource,
        real_name: nextRealName,
        school: nextSchool,
        class_name: nextClassName,
        relation: nextRelation,
        phone: nextPhone,
        address: nextAddress
      }),
      operatorUserId,
      operatorName,
      operationAt: normalizedOperationAt
    });

    return toCombinedCustomerRecord(nextRecord);
  };

  const listTenantCustomerOperationLogs = async ({
    tenantId,
    customerId,
    operatorUserId = null,
    scopes = ['all'],
    limit = MAX_OPERATION_LOG_LIMIT
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedCustomerId = normalizeCustomerId(customerId);
    if (!normalizedTenantId || !normalizedCustomerId) {
      return [];
    }
    const customerRecord = await findTenantCustomerByCustomerId({
      tenantId: normalizedTenantId,
      customerId: normalizedCustomerId,
      operatorUserId,
      scopes
    });
    if (!customerRecord) {
      return [];
    }
    const normalizedLimit = Number.isFinite(Number(limit))
      ? Math.max(1, Math.min(MAX_OPERATION_LOG_LIMIT, Math.floor(Number(limit))))
      : MAX_OPERATION_LOG_LIMIT;
    return [...(tenantCustomerOperationLogsByCustomerId.get(normalizedCustomerId) || [])]
      .map((operationLog) => cloneValue(operationLog))
      .sort((left, right) => {
        const leftTime = Date.parse(left?.operation_time || left?.created_at || 0);
        const rightTime = Date.parse(right?.operation_time || right?.created_at || 0);
        if (leftTime !== rightTime) {
          return rightTime - leftTime;
        }
        return String(right?.operation_id || '').localeCompare(String(left?.operation_id || ''));
      })
      .slice(0, normalizedLimit);
  };

  return {
    listTenantCustomersByTenantId,
    createTenantCustomer,
    findTenantCustomerByCustomerId,
    updateTenantCustomer,
    listTenantCustomerOperationLogs
  };
};

module.exports = {
  createTenantMemoryAuthStoreCustomer
};
