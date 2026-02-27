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
const MAX_OPERATOR_NAME_LENGTH = 128;
const MAX_OPERATION_TYPE_LENGTH = 64;
const MAX_OPERATION_CONTENT_LENGTH = 2048;
const MAX_OPERATION_LOG_LIMIT = 200;
const MAX_CUSTOMER_ID_RETRY = 8;

const createTenantMysqlAuthStoreCustomer = ({
  CONTROL_CHAR_PATTERN,
  dbClient,
  executeWithDeadlockRetry,
  escapeSqlLikePattern,
  formatAuditDateTimeForMySql,
  isDuplicateEntryError,
  normalizeStoreIsoTimestamp,
  randomUUID
} = {}) => {
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

  const toMySqlTimestamp = (value) => {
    const normalizedIsoTimestamp = normalizeStoreIsoTimestamp(value);
    if (!normalizedIsoTimestamp) {
      return '';
    }
    if (typeof formatAuditDateTimeForMySql === 'function') {
      return formatAuditDateTimeForMySql(normalizedIsoTimestamp);
    }
    return `${normalizedIsoTimestamp.slice(0, 19).replace('T', ' ')}.${normalizedIsoTimestamp.slice(20, 23)}`;
  };

  const resolveOperationTimestampForWrite = (value) =>
    toMySqlTimestamp(value) || toMySqlTimestamp(new Date());

  const executeWriteWithRetry = ({ operation, execute }) => {
    if (typeof executeWithDeadlockRetry === 'function') {
      return executeWithDeadlockRetry({
        operation,
        onExhausted: 'throw',
        execute
      });
    }
    return execute();
  };

  const buildInPlaceholders = (size) =>
    new Array(Math.max(0, Number(size) || 0)).fill('?').join(', ');

  const toSqlLikeContains = (keyword) => {
    const normalized = normalizeRequiredString(keyword).toLowerCase();
    if (!normalized) {
      return '';
    }
    return `%${escapeSqlLikePattern(normalized)}%`;
  };

  const toCustomerRecordFromRow = (row = {}) => {
    if (!row || typeof row !== 'object') {
      return null;
    }
    const customerId = normalizeCustomerId(row.customer_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const accountId = normalizeAccountId(row.account_id);
    const wechatId = normalizeWechatId(row.wechat_id);
    const nickname = normalizeNickname(row.nickname);
    const source = normalizeSource(row.source);
    const status = normalizeStatus(row.status);
    const createdAt = normalizeStoreIsoTimestamp(row.created_at);
    const updatedAt = normalizeStoreIsoTimestamp(row.updated_at);
    if (
      !customerId
      || !tenantId
      || !accountId
      || !wechatId
      || !nickname
      || !source
      || !status
      || !createdAt
      || !updatedAt
    ) {
      return null;
    }
    return {
      customer_id: customerId,
      tenant_id: tenantId,
      account_id: accountId,
      wechat_id: wechatId,
      nickname,
      source,
      status,
      real_name: normalizeRequiredString(row.real_name) || null,
      school: normalizeRequiredString(row.school) || null,
      class_name: normalizeRequiredString(row.class_name) || null,
      relation: normalizeRequiredString(row.relation) || null,
      phone: normalizeRequiredString(row.phone) || null,
      address: normalizeRequiredString(row.address) || null,
      created_by_user_id: normalizeRequiredString(row.created_by_user_id) || null,
      updated_by_user_id: normalizeRequiredString(row.updated_by_user_id) || null,
      created_at: createdAt,
      updated_at: updatedAt
    };
  };

  const toOperationLogRecordFromRow = (row = {}) => {
    if (!row || typeof row !== 'object') {
      return null;
    }
    const operationId = normalizeRequiredString(row.operation_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const customerId = normalizeCustomerId(row.customer_id);
    const operationType = normalizeRequiredString(row.operation_type);
    const operationTime = normalizeStoreIsoTimestamp(row.operation_time || row.created_at);
    if (!operationId || !tenantId || !customerId || !operationType || !operationTime) {
      return null;
    }
    return {
      operation_id: operationId,
      tenant_id: tenantId,
      customer_id: customerId,
      operation_type: operationType,
      operation_content: normalizeRequiredString(row.operation_content) || null,
      operator_user_id: normalizeRequiredString(row.operator_user_id) || null,
      operator_name: normalizeRequiredString(row.operator_name) || null,
      operation_time: operationTime,
      created_at: normalizeStoreIsoTimestamp(row.created_at) || operationTime
    };
  };

  const isWechatDuplicateError = (error) =>
    isDuplicateEntryError(error)
    && /uk_tenant_customers_tenant_wechat/i.test(String(error?.message || ''));

  const isCustomerIdDuplicateError = (error) =>
    isDuplicateEntryError(error)
    && /for key 'PRIMARY'/i.test(String(error?.message || ''));

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

  const resolveScopeFilterSql = async ({
    tenantId,
    operatorUserId,
    scopes,
    accountAlias = 'a',
    customerAlias = 'c'
  } = {}) => {
    const scopeSet = toScopeSet(scopes);
    if (scopeSet.has('all')) {
      return {
        denied: false,
        whereSql: '',
        params: []
      };
    }

    const membershipIds = await listMembershipIdsForOperator({
      tenantId,
      operatorUserId
    });
    if (membershipIds.length < 1) {
      return {
        denied: true,
        whereSql: '',
        params: []
      };
    }

    const membershipPlaceholders = buildInPlaceholders(membershipIds.length);
    const scopeClauses = [];
    const scopeParams = [];

    if (scopeSet.has('my')) {
      scopeClauses.push(`${accountAlias}.owner_membership_id IN (${membershipPlaceholders})`);
      scopeParams.push(...membershipIds);
    }
    if (scopeSet.has('assist')) {
      scopeClauses.push(
        `
          EXISTS (
            SELECT 1
            FROM tenant_account_assistants taa
            WHERE taa.account_id = ${customerAlias}.account_id
              AND taa.assistant_membership_id IN (${membershipPlaceholders})
          )
        `
      );
      scopeParams.push(...membershipIds);
    }

    if (scopeClauses.length < 1) {
      return {
        denied: true,
        whereSql: '',
        params: []
      };
    }

    return {
      denied: false,
      whereSql: ` AND (${scopeClauses.join(' OR ')})`,
      params: scopeParams
    };
  };

  const loadCustomerRowByTenantAndCustomerId = async ({
    tenantId,
    customerId,
    operatorUserId = null,
    scopes = ['all'],
    queryClient = dbClient,
    lockForUpdate = false
  } = {}) => {
    const scopeFilter = await resolveScopeFilterSql({
      tenantId,
      operatorUserId,
      scopes,
      accountAlias: 'a',
      customerAlias: 'c'
    });
    if (scopeFilter.denied) {
      return null;
    }
    const rows = await queryClient.query(
      `
        SELECT c.customer_id,
               c.tenant_id,
               c.account_id,
               c.wechat_id,
               c.nickname,
               c.source,
               c.status,
               c.created_by_user_id,
               c.updated_by_user_id,
               c.created_at,
               c.updated_at,
               p.real_name,
               p.school,
               p.class_name,
               p.relation,
               p.phone,
               p.address
        FROM tenant_customers c
        JOIN tenant_accounts a
          ON a.account_id = c.account_id
         AND a.tenant_id = c.tenant_id
        LEFT JOIN tenant_customer_profiles p
          ON p.customer_id = c.customer_id
         AND p.tenant_id = c.tenant_id
        WHERE c.tenant_id = ?
          AND c.customer_id = ?
          ${scopeFilter.whereSql}
        LIMIT 1
        ${lockForUpdate ? 'FOR UPDATE' : ''}
      `,
      [
        tenantId,
        customerId,
        ...scopeFilter.params
      ]
    );
    return rows?.[0] || null;
  };

  const insertCustomerOperationLogTx = async ({
    txClient,
    tenantId,
    customerId,
    operationType,
    operationContent,
    operatorUserId = null,
    operatorName = null,
    operationAt
  } = {}) => {
    const normalizedOperationType =
      normalizeRequiredString(operationType).slice(0, MAX_OPERATION_TYPE_LENGTH)
      || 'update';
    const normalizedOperationContent =
      normalizeRequiredString(operationContent).slice(0, MAX_OPERATION_CONTENT_LENGTH)
      || null;
    const normalizedOperatorName =
      normalizeRequiredString(operatorName).slice(0, MAX_OPERATOR_NAME_LENGTH)
      || null;
    await txClient.query(
      `
        INSERT INTO tenant_customer_operation_logs (
          operation_id,
          tenant_id,
          customer_id,
          operation_type,
          operation_content,
          operator_user_id,
          operator_name,
          operation_time,
          created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        createOperationId(),
        tenantId,
        customerId,
        normalizedOperationType,
        normalizedOperationContent,
        normalizeRequiredString(operatorUserId) || null,
        normalizedOperatorName,
        operationAt,
        operationAt
      ]
    );
  };

  const listMembershipIdsForOperator = async ({
    tenantId,
    operatorUserId
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedOperatorUserId = normalizeRequiredString(operatorUserId);
    if (!normalizedTenantId || !normalizedOperatorUserId) {
      return [];
    }
    const rows = await dbClient.query(
      `
        SELECT membership_id
        FROM tenant_memberships
        WHERE tenant_id = ?
          AND user_id = ?
          AND status IN ('active', 'enabled')
        ORDER BY membership_id ASC
      `,
      [normalizedTenantId, normalizedOperatorUserId]
    );
    return [...new Set(
      (Array.isArray(rows) ? rows : [])
        .map((row) => normalizeRequiredString(row?.membership_id))
        .filter((membershipId) => membershipId.length > 0)
    )];
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

    const normalizedScope = normalizeRequiredString(scope).toLowerCase() || 'my';
    const whereClauses = ['c.tenant_id = ?'];
    const params = [normalizedTenantId];

    if (normalizedScope !== 'all') {
      const membershipIds = await listMembershipIdsForOperator({
        tenantId: normalizedTenantId,
        operatorUserId
      });
      if (membershipIds.length < 1) {
        return [];
      }
      const membershipPlaceholders = buildInPlaceholders(membershipIds.length);
      if (normalizedScope === 'my') {
        whereClauses.push(`a.owner_membership_id IN (${membershipPlaceholders})`);
        params.push(...membershipIds);
      } else if (normalizedScope === 'assist') {
        whereClauses.push(
          `
            EXISTS (
              SELECT 1
              FROM tenant_account_assistants taa
              WHERE taa.account_id = c.account_id
                AND taa.assistant_membership_id IN (${membershipPlaceholders})
            )
          `
        );
        params.push(...membershipIds);
      } else {
        const error = new Error('tenant customer scope forbidden');
        error.code = 'ERR_TENANT_CUSTOMER_SCOPE_FORBIDDEN';
        throw error;
      }
    }

    const normalizedWechatId = normalizeRequiredString(filters?.wechatId);
    if (normalizedWechatId) {
      whereClauses.push('c.wechat_id = ?');
      params.push(normalizedWechatId);
    }

    const normalizedAccountIds = [...new Set(
      (Array.isArray(filters?.accountIds) ? filters.accountIds : [])
        .map((accountId) => normalizeAccountId(accountId))
        .filter((accountId) => accountId.length > 0)
    )];
    if (normalizedAccountIds.length > 0) {
      whereClauses.push(`c.account_id IN (${buildInPlaceholders(normalizedAccountIds.length)})`);
      params.push(...normalizedAccountIds);
    }

    const nicknameLike = toSqlLikeContains(filters?.nickname);
    if (nicknameLike) {
      whereClauses.push("LOWER(c.nickname) LIKE ? ESCAPE '\\\\'");
      params.push(nicknameLike);
    }

    const normalizedSource = normalizeSource(filters?.source);
    if (normalizedSource) {
      whereClauses.push('c.source = ?');
      params.push(normalizedSource);
    }

    const realNameLike = toSqlLikeContains(filters?.realName);
    if (realNameLike) {
      whereClauses.push("LOWER(COALESCE(p.real_name, '')) LIKE ? ESCAPE '\\\\'");
      params.push(realNameLike);
    }

    const normalizedPhone = normalizeRequiredString(filters?.phone);
    if (normalizedPhone) {
      whereClauses.push('p.phone = ?');
      params.push(normalizedPhone);
    }

    const normalizedStatus = normalizeStatus(filters?.status);
    if (normalizedStatus) {
      whereClauses.push('c.status = ?');
      params.push(normalizedStatus);
    }

    const createdAtStart = toMySqlTimestamp(filters?.createdAtStart);
    if (createdAtStart) {
      whereClauses.push('c.created_at >= ?');
      params.push(createdAtStart);
    }

    const createdAtEnd = toMySqlTimestamp(filters?.createdAtEnd);
    if (createdAtEnd) {
      whereClauses.push('c.created_at <= ?');
      params.push(createdAtEnd);
    }

    const rows = await dbClient.query(
      `
        SELECT c.customer_id,
               c.tenant_id,
               c.account_id,
               c.wechat_id,
               c.nickname,
               c.source,
               c.status,
               c.created_by_user_id,
               c.updated_by_user_id,
               c.created_at,
               c.updated_at,
               p.real_name,
               p.school,
               p.class_name,
               p.relation,
               p.phone,
               p.address
        FROM tenant_customers c
        JOIN tenant_accounts a
          ON a.account_id = c.account_id
         AND a.tenant_id = c.tenant_id
        LEFT JOIN tenant_customer_profiles p
          ON p.customer_id = c.customer_id
         AND p.tenant_id = c.tenant_id
        WHERE ${whereClauses.join(' AND ')}
        ORDER BY c.created_at DESC, c.customer_id DESC
      `,
      params
    );

    return (Array.isArray(rows) ? rows : [])
      .map((row) => toCustomerRecordFromRow(row))
      .filter(Boolean);
  };

  const findTenantCustomerByCustomerId = async ({
    tenantId,
    customerId,
    operatorUserId = null,
    scopes = ['my']
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedCustomerId = normalizeCustomerId(customerId);
    if (!normalizedTenantId || !normalizedCustomerId) {
      return null;
    }
    const row = await loadCustomerRowByTenantAndCustomerId({
      tenantId: normalizedTenantId,
      customerId: normalizedCustomerId,
      operatorUserId,
      scopes
    });
    return toCustomerRecordFromRow(row);
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
    const normalizedWechatId = normalizeWechatId(wechatId);
    const normalizedNickname = normalizeNickname(nickname);
    const normalizedSource = normalizeSource(source);
    const normalizedStatus = normalizeStatus(status) || 'enabled';
    if (
      !normalizedTenantId
      || !normalizedAccountId
      || !normalizedWechatId
      || !normalizedNickname
      || !normalizedSource
      || !normalizedStatus
    ) {
      throw new Error('invalid customer payload');
    }

    const accountRows = await dbClient.query(
      `
        SELECT account_id, status
        FROM tenant_accounts
        WHERE tenant_id = ?
          AND account_id = ?
        LIMIT 1
      `,
      [normalizedTenantId, normalizedAccountId]
    );
    const accountRow = accountRows?.[0] || null;
    if (
      !accountRow
      || normalizeStatus(accountRow.status) !== 'enabled'
    ) {
      throw createAccountNotFoundError();
    }

    const normalizedOperationAt = resolveOperationTimestampForWrite(operationAt);
    const normalizedRealName = toNullableProfileField(normalizeOptionalProfileField({
      value: realName,
      maxLength: MAX_REAL_NAME_LENGTH
    }));
    const normalizedSchool = toNullableProfileField(normalizeOptionalProfileField({
      value: school,
      maxLength: MAX_SCHOOL_LENGTH
    }));
    const normalizedClassName = toNullableProfileField(normalizeOptionalProfileField({
      value: className,
      maxLength: MAX_CLASS_NAME_LENGTH
    }));
    const normalizedRelation = toNullableProfileField(normalizeOptionalProfileField({
      value: relation,
      maxLength: MAX_RELATION_LENGTH
    }));
    const normalizedPhone = toNullableProfileField(normalizeOptionalProfileField({
      value: phone,
      maxLength: MAX_PHONE_LENGTH
    }));
    const normalizedAddress = toNullableProfileField(normalizeOptionalProfileField({
      value: address,
      maxLength: MAX_ADDRESS_LENGTH
    }));

    for (let attempt = 0; attempt < MAX_CUSTOMER_ID_RETRY; attempt += 1) {
      const normalizedCustomerId = normalizeCustomerId(createCustomerId());
      if (!normalizedCustomerId) {
        continue;
      }
      try {
        await executeWriteWithRetry({
          operation: 'createTenantCustomer',
          execute: async () =>
            dbClient.inTransaction(async (tx) => {
              await tx.query(
                `
                  INSERT INTO tenant_customers (
                    customer_id,
                    tenant_id,
                    account_id,
                    wechat_id,
                    nickname,
                    source,
                    status,
                    created_by_user_id,
                    updated_by_user_id,
                    created_at,
                    updated_at
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                  normalizedCustomerId,
                  normalizedTenantId,
                  normalizedAccountId,
                  normalizedWechatId,
                  normalizedNickname,
                  normalizedSource,
                  normalizedStatus,
                  normalizeRequiredString(operatorUserId) || null,
                  normalizeRequiredString(operatorUserId) || null,
                  normalizedOperationAt,
                  normalizedOperationAt
                ]
              );

              await tx.query(
                `
                  UPDATE tenant_accounts
                  SET customer_count = COALESCE(customer_count, 0) + 1
                  WHERE tenant_id = ?
                    AND account_id = ?
                `,
                [
                  normalizedTenantId,
                  normalizedAccountId
                ]
              );

              await tx.query(
                `
                  INSERT INTO tenant_customer_profiles (
                    customer_id,
                    tenant_id,
                    real_name,
                    school,
                    class_name,
                    relation,
                    phone,
                    address,
                    created_at,
                    updated_at
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                  normalizedCustomerId,
                  normalizedTenantId,
                  normalizedRealName,
                  normalizedSchool,
                  normalizedClassName,
                  normalizedRelation,
                  normalizedPhone,
                  normalizedAddress,
                  normalizedOperationAt,
                  normalizedOperationAt
                ]
              );

              await insertCustomerOperationLogTx({
                txClient: tx,
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
            })
        });

        return findTenantCustomerByCustomerId({
          tenantId: normalizedTenantId,
          customerId: normalizedCustomerId,
          scopes: ['all']
        });
      } catch (error) {
        if (isWechatDuplicateError(error)) {
          throw createWechatConflictError();
        }
        if (isCustomerIdDuplicateError(error)) {
          continue;
        }
        throw error;
      }
    }

    throw new Error('tenant customer id generation exhausted');
  };

  const updateTenantCustomerBasic = async ({
    tenantId,
    customerId,
    scopes = ['all'],
    source,
    operatorUserId = null,
    operatorName = null,
    operationAt = new Date()
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedCustomerId = normalizeCustomerId(customerId);
    const normalizedSource = normalizeSource(source);
    if (!normalizedTenantId || !normalizedCustomerId || !normalizedSource) {
      throw new Error('invalid customer basic payload');
    }
    const normalizedOperationAt = resolveOperationTimestampForWrite(operationAt);
    const updated = await executeWriteWithRetry({
      operation: 'updateTenantCustomerBasic',
      execute: async () =>
        dbClient.inTransaction(async (tx) => {
          const existingCustomer = await loadCustomerRowByTenantAndCustomerId({
            tenantId: normalizedTenantId,
            customerId: normalizedCustomerId,
            operatorUserId,
            scopes,
            queryClient: tx,
            lockForUpdate: true
          });
          if (!existingCustomer) {
            return false;
          }

          await tx.query(
            `
              UPDATE tenant_customers
              SET source = ?,
                  updated_by_user_id = ?,
                  updated_at = ?
              WHERE tenant_id = ?
                AND customer_id = ?
            `,
            [
              normalizedSource,
              normalizeRequiredString(operatorUserId) || null,
              normalizedOperationAt,
              normalizedTenantId,
              normalizedCustomerId
            ]
          );

          await insertCustomerOperationLogTx({
            txClient: tx,
            tenantId: normalizedTenantId,
            customerId: normalizedCustomerId,
            operationType: 'update_basic',
            operationContent: JSON.stringify({
              source: normalizedSource
            }),
            operatorUserId,
            operatorName,
            operationAt: normalizedOperationAt
          });

          return true;
        })
    });
    if (!updated) {
      return null;
    }
    return findTenantCustomerByCustomerId({
      tenantId: normalizedTenantId,
      customerId: normalizedCustomerId,
      scopes: ['all']
    });
  };

  const updateTenantCustomerRealname = async ({
    tenantId,
    customerId,
    scopes = ['all'],
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
    const normalizedCustomerId = normalizeCustomerId(customerId);
    if (!normalizedTenantId || !normalizedCustomerId) {
      throw new Error('invalid customer realname payload');
    }
    const normalizedOperationAt = resolveOperationTimestampForWrite(operationAt);
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

    const updated = await executeWriteWithRetry({
      operation: 'updateTenantCustomerRealname',
      execute: async () =>
        dbClient.inTransaction(async (tx) => {
          const existingCustomer = await loadCustomerRowByTenantAndCustomerId({
            tenantId: normalizedTenantId,
            customerId: normalizedCustomerId,
            operatorUserId,
            scopes,
            queryClient: tx,
            lockForUpdate: true
          });
          if (!existingCustomer) {
            return false;
          }

          const profileRows = await tx.query(
            `
              SELECT customer_id,
                     real_name,
                     school,
                     class_name,
                     relation,
                     phone,
                     address,
                     created_at
              FROM tenant_customer_profiles
              WHERE tenant_id = ?
                AND customer_id = ?
              LIMIT 1
              FOR UPDATE
            `,
            [normalizedTenantId, normalizedCustomerId]
          );
          const existingProfile = profileRows?.[0] || null;
          const resolvedRealName =
            nextRealName === undefined
              ? normalizeRequiredString(existingProfile?.real_name) || null
              : nextRealName;
          const resolvedSchool =
            nextSchool === undefined
              ? normalizeRequiredString(existingProfile?.school) || null
              : nextSchool;
          const resolvedClassName =
            nextClassName === undefined
              ? normalizeRequiredString(existingProfile?.class_name) || null
              : nextClassName;
          const resolvedRelation =
            nextRelation === undefined
              ? normalizeRequiredString(existingProfile?.relation) || null
              : nextRelation;
          const resolvedPhone =
            nextPhone === undefined
              ? normalizeRequiredString(existingProfile?.phone) || null
              : nextPhone;
          const resolvedAddress =
            nextAddress === undefined
              ? normalizeRequiredString(existingProfile?.address) || null
              : nextAddress;

          if (existingProfile) {
            await tx.query(
              `
                UPDATE tenant_customer_profiles
                SET real_name = ?,
                    school = ?,
                    class_name = ?,
                    relation = ?,
                    phone = ?,
                    address = ?,
                    updated_at = ?
                WHERE tenant_id = ?
                  AND customer_id = ?
              `,
              [
                resolvedRealName,
                resolvedSchool,
                resolvedClassName,
                resolvedRelation,
                resolvedPhone,
                resolvedAddress,
                normalizedOperationAt,
                normalizedTenantId,
                normalizedCustomerId
              ]
            );
          } else {
            await tx.query(
              `
                INSERT INTO tenant_customer_profiles (
                  customer_id,
                  tenant_id,
                  real_name,
                  school,
                  class_name,
                  relation,
                  phone,
                  address,
                  created_at,
                  updated_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
              `,
              [
                normalizedCustomerId,
                normalizedTenantId,
                resolvedRealName,
                resolvedSchool,
                resolvedClassName,
                resolvedRelation,
                resolvedPhone,
                resolvedAddress,
                normalizedOperationAt,
                normalizedOperationAt
              ]
            );
          }

          await tx.query(
            `
              UPDATE tenant_customers
              SET updated_by_user_id = ?,
                  updated_at = ?
              WHERE tenant_id = ?
                AND customer_id = ?
            `,
            [
              normalizeRequiredString(operatorUserId) || null,
              normalizedOperationAt,
              normalizedTenantId,
              normalizedCustomerId
            ]
          );

          await insertCustomerOperationLogTx({
            txClient: tx,
            tenantId: normalizedTenantId,
            customerId: normalizedCustomerId,
            operationType: 'update_realname',
            operationContent: JSON.stringify({
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

          return true;
        })
    });
    if (!updated) {
      return null;
    }
    return findTenantCustomerByCustomerId({
      tenantId: normalizedTenantId,
      customerId: normalizedCustomerId,
      scopes: ['all']
    });
  };

  const listTenantCustomerOperationLogs = async ({
    tenantId,
    customerId,
    operatorUserId = null,
    scopes = ['my'],
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
    const rows = await dbClient.query(
      `
        SELECT operation_id,
               tenant_id,
               customer_id,
               operation_type,
               operation_content,
               operator_user_id,
               operator_name,
               operation_time,
               created_at
        FROM tenant_customer_operation_logs
        WHERE tenant_id = ?
          AND customer_id = ?
        ORDER BY operation_time DESC, operation_id DESC
        LIMIT ?
      `,
      [normalizedTenantId, normalizedCustomerId, normalizedLimit]
    );
    return (Array.isArray(rows) ? rows : [])
      .map((row) => toOperationLogRecordFromRow(row))
      .filter(Boolean);
  };

  return {
    listTenantCustomersByTenantId,
    createTenantCustomer,
    findTenantCustomerByCustomerId,
    updateTenantCustomerBasic,
    updateTenantCustomerRealname,
    listTenantCustomerOperationLogs
  };
};

module.exports = {
  createTenantMysqlAuthStoreCustomer
};
