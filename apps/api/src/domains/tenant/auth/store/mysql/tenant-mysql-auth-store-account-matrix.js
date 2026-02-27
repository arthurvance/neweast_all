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
const MAX_ACCOUNT_ID_RETRY = 8;

const createTenantMysqlAuthStoreAccountMatrix = ({
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

  const createWechatConflictError = () => {
    const error = new Error('tenant account wechat conflict');
    error.code = 'ERR_TENANT_ACCOUNT_WECHAT_CONFLICT';
    return error;
  };

  const createOperationId = () =>
    `op_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createAccountId = () =>
    `acc_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

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

  const parseAssistantMembershipIdsFromRow = (row = {}) => {
    const assistantMembershipIdsCsv = normalizeRequiredString(
      row.assistant_membership_ids_csv
    );
    if (!assistantMembershipIdsCsv) {
      return [];
    }
    return normalizeAssistantMembershipIds(
      assistantMembershipIdsCsv
        .split(',')
        .map((item) => String(item || '').trim())
        .filter((item) => item.length > 0)
    );
  };

  const toAccountRecordFromRow = (row = {}) => {
    const accountId = normalizeAccountId(row.account_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const wechatId = normalizeWechatId(row.wechat_id);
    const nickname = normalizeNickname(row.nickname);
    const ownerMembershipId = normalizeMembershipId(row.owner_membership_id);
    const status = normalizeAccountStatus(row.status);
    const createdAt = normalizeStoreIsoTimestamp(row.created_at);
    const updatedAt = normalizeStoreIsoTimestamp(row.updated_at);
    if (
      !accountId
      || !tenantId
      || !wechatId
      || !nickname
      || !ownerMembershipId
      || !status
      || !createdAt
      || !updatedAt
    ) {
      return null;
    }

    return {
      account_id: accountId,
      tenant_id: tenantId,
      wechat_id: wechatId,
      nickname,
      owner_membership_id: ownerMembershipId,
      assistant_membership_ids: parseAssistantMembershipIdsFromRow(row),
      customer_count: Math.max(0, Math.floor(Number(row.customer_count || 0))),
      group_chat_count: Math.max(0, Math.floor(Number(row.group_chat_count || 0))),
      status,
      avatar_url: row.avatar_url === null || row.avatar_url === undefined
        ? null
        : String(row.avatar_url),
      created_by_user_id: normalizeRequiredString(row.created_by_user_id) || null,
      updated_by_user_id: normalizeRequiredString(row.updated_by_user_id) || null,
      created_at: createdAt,
      updated_at: updatedAt
    };
  };

  const toOperationLogRecordFromRow = (row = {}) => {
    const operationId = normalizeRequiredString(row.operation_id);
    const accountId = normalizeAccountId(row.account_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const operationType = normalizeRequiredString(row.operation_type);
    const operationTime = normalizeStoreIsoTimestamp(row.operation_time || row.created_at);

    if (!operationId || !accountId || !tenantId || !operationType || !operationTime) {
      return null;
    }

    return {
      operation_id: operationId,
      account_id: accountId,
      tenant_id: tenantId,
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
    && /uk_tenant_accounts_tenant_wechat/i.test(String(error?.message || ''));

  const isAccountIdDuplicateError = (error) =>
    isDuplicateEntryError(error)
    && /for key 'PRIMARY'/i.test(String(error?.message || ''));

  const toSqlLikeContains = (keyword) => {
    const normalized = normalizeRequiredString(keyword).toLowerCase();
    if (!normalized) {
      return '';
    }
    return `%${escapeSqlLikePattern(normalized)}%`;
  };

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

  const loadAccountRowByTenantAndId = async ({ tenantId, accountId }) => {
    const rows = await dbClient.query(
      `
        SELECT a.account_id,
               a.tenant_id,
               a.wechat_id,
               a.nickname,
               a.owner_membership_id,
               a.customer_count,
               a.group_chat_count,
               a.status,
               a.avatar_url,
               a.created_by_user_id,
               a.updated_by_user_id,
               a.created_at,
               a.updated_at,
               (
                 SELECT GROUP_CONCAT(assistant_membership_id ORDER BY assistant_membership_id SEPARATOR ',')
                 FROM tenant_account_assistants
                 WHERE account_id = a.account_id
               ) AS assistant_membership_ids_csv
        FROM tenant_accounts a
        WHERE a.tenant_id = ? AND a.account_id = ?
        LIMIT 1
      `,
      [tenantId, accountId]
    );
    return rows?.[0] || null;
  };

  const insertAccountOperationLogTx = async ({
    txClient,
    accountId,
    tenantId,
    operationType,
    operationContent,
    operatorUserId = null,
    operatorName = null,
    operationAt
  }) => {
    const normalizedOperationType = normalizeRequiredString(operationType)
      .slice(0, MAX_OPERATION_TYPE_LENGTH)
      || 'update';
    const normalizedOperationContent = normalizeRequiredString(operationContent)
      .slice(0, MAX_OPERATION_CONTENT_LENGTH)
      || null;
    const normalizedOperatorName = normalizeRequiredString(operatorName)
      .slice(0, MAX_OPERATOR_NAME_LENGTH)
      || null;

    await txClient.query(
      `
        INSERT INTO tenant_account_operation_logs (
          operation_id,
          account_id,
          tenant_id,
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
        accountId,
        tenantId,
        normalizedOperationType,
        normalizedOperationContent,
        normalizeRequiredString(operatorUserId) || null,
        normalizedOperatorName,
        operationAt,
        operationAt
      ]
    );
  };

  const listTenantAccountsByTenantId = async ({
    tenantId,
    filters = {}
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      return [];
    }

    const whereClauses = ['a.tenant_id = ?'];
    const params = [normalizedTenantId];

    const normalizedWechatId = normalizeRequiredString(filters?.wechatId);
    if (normalizedWechatId) {
      whereClauses.push('a.wechat_id = ?');
      params.push(normalizedWechatId);
    }

    const nicknameLike = toSqlLikeContains(filters?.nickname);
    if (nicknameLike) {
      whereClauses.push("LOWER(a.nickname) LIKE ? ESCAPE '\\\\'");
      params.push(nicknameLike);
    }

    const status = normalizeAccountStatus(filters?.status);
    if (status) {
      whereClauses.push('a.status = ?');
      params.push(status);
    }

    const createdAtStart = toMySqlTimestamp(filters?.createdAtStart);
    if (createdAtStart) {
      whereClauses.push('a.created_at >= ?');
      params.push(createdAtStart);
    }
    const createdAtEnd = toMySqlTimestamp(filters?.createdAtEnd);
    if (createdAtEnd) {
      whereClauses.push('a.created_at <= ?');
      params.push(createdAtEnd);
    }

    const ownerKeywordLike = toSqlLikeContains(filters?.ownerKeyword);
    if (ownerKeywordLike) {
      whereClauses.push(
        `
          EXISTS (
            SELECT 1
            FROM tenant_memberships tm_owner
            WHERE tm_owner.membership_id = a.owner_membership_id
              AND tm_owner.tenant_id = a.tenant_id
              AND LOWER(
                COALESCE(
                  NULLIF(TRIM(tm_owner.display_name), ''),
                  tm_owner.user_id,
                  tm_owner.membership_id
                )
              ) LIKE ? ESCAPE '\\\\'
          )
        `
      );
      params.push(ownerKeywordLike);
    }

    const assistantKeywordLike = toSqlLikeContains(filters?.assistantKeyword);
    if (assistantKeywordLike) {
      whereClauses.push(
        `
          EXISTS (
            SELECT 1
            FROM tenant_account_assistants taa2
            JOIN tenant_memberships tm_assistant
              ON tm_assistant.membership_id = taa2.assistant_membership_id
             AND tm_assistant.tenant_id = a.tenant_id
            WHERE taa2.account_id = a.account_id
              AND LOWER(
                COALESCE(
                  NULLIF(TRIM(tm_assistant.display_name), ''),
                  tm_assistant.user_id,
                  tm_assistant.membership_id
                )
              ) LIKE ? ESCAPE '\\\\'
          )
        `
      );
      params.push(assistantKeywordLike);
    }

    const rows = await dbClient.query(
      `
        SELECT a.account_id,
               a.tenant_id,
               a.wechat_id,
               a.nickname,
               a.owner_membership_id,
               a.customer_count,
               a.group_chat_count,
               a.status,
               a.avatar_url,
               a.created_by_user_id,
               a.updated_by_user_id,
               a.created_at,
               a.updated_at,
               (
                 SELECT GROUP_CONCAT(assistant_membership_id ORDER BY assistant_membership_id SEPARATOR ',')
                 FROM tenant_account_assistants
                 WHERE account_id = a.account_id
               ) AS assistant_membership_ids_csv
        FROM tenant_accounts a
        WHERE ${whereClauses.join(' AND ')}
        ORDER BY a.created_at DESC, a.account_id DESC
      `,
      params
    );

    return (Array.isArray(rows) ? rows : [])
      .map((row) => toAccountRecordFromRow(row))
      .filter(Boolean);
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

    const row = await loadAccountRowByTenantAndId({
      tenantId: normalizedTenantId,
      accountId: normalizedAccountId
    });
    return toAccountRecordFromRow(row);
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

    const normalizedOperationAt = resolveOperationTimestampForWrite(operationAt);

    for (let attempt = 0; attempt < MAX_ACCOUNT_ID_RETRY; attempt += 1) {
      const accountId = normalizeAccountId(createAccountId());
      if (!accountId) {
        continue;
      }
      try {
        await executeWriteWithRetry({
          operation: 'createTenantAccount',
          execute: async () =>
            dbClient.inTransaction(async (tx) => {
              await tx.query(
                `
                  INSERT INTO tenant_accounts (
                    account_id,
                    tenant_id,
                    wechat_id,
                    nickname,
                    owner_membership_id,
                    customer_count,
                    group_chat_count,
                    status,
                    avatar_url,
                    created_by_user_id,
                    updated_by_user_id,
                    created_at,
                    updated_at
                  )
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `,
                [
                  accountId,
                  normalizedTenantId,
                  normalizedWechatId,
                  normalizedNickname,
                  normalizedOwnerMembershipId,
                  0,
                  0,
                  'enabled',
                  null,
                  normalizeRequiredString(operatorUserId) || null,
                  normalizeRequiredString(operatorUserId) || null,
                  normalizedOperationAt,
                  normalizedOperationAt
                ]
              );

              for (const assistantMembershipId of normalizedAssistantMembershipIds) {
                await tx.query(
                  `
                    INSERT INTO tenant_account_assistants (
                      account_id,
                      assistant_membership_id,
                      created_by_user_id,
                      updated_by_user_id
                    )
                    VALUES (?, ?, ?, ?)
                  `,
                  [
                    accountId,
                    assistantMembershipId,
                    normalizeRequiredString(operatorUserId) || null,
                    normalizeRequiredString(operatorUserId) || null
                  ]
                );
              }

              await insertAccountOperationLogTx({
                txClient: tx,
                accountId,
                tenantId: normalizedTenantId,
                operationType: 'create',
                operationContent: `新建账号：${normalizedWechatId}`,
                operatorUserId,
                operatorName,
                operationAt: normalizedOperationAt
              });
            })
        });

        return findTenantAccountByAccountId({
          tenantId: normalizedTenantId,
          accountId
        });
      } catch (error) {
        if (isWechatDuplicateError(error)) {
          throw createWechatConflictError();
        }
        if (isAccountIdDuplicateError(error)) {
          continue;
        }
        throw error;
      }
    }

    throw new Error('tenant account id generation exhausted');
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

    const normalizedOperationAt = resolveOperationTimestampForWrite(operationAt);
    try {
      const updated = await executeWriteWithRetry({
        operation: 'updateTenantAccount',
        execute: async () =>
          dbClient.inTransaction(async (tx) => {
            const existingRows = await tx.query(
              `
                SELECT account_id
                FROM tenant_accounts
                WHERE tenant_id = ?
                  AND account_id = ?
                LIMIT 1
                FOR UPDATE
              `,
              [normalizedTenantId, normalizedAccountId]
            );
            if (!existingRows?.[0]) {
              return false;
            }

            await tx.query(
              `
                UPDATE tenant_accounts
                SET wechat_id = ?,
                    nickname = ?,
                    owner_membership_id = ?,
                    updated_by_user_id = ?,
                    updated_at = ?
                WHERE tenant_id = ?
                  AND account_id = ?
              `,
              [
                normalizedWechatId,
                normalizedNickname,
                normalizedOwnerMembershipId,
                normalizeRequiredString(operatorUserId) || null,
                normalizedOperationAt,
                normalizedTenantId,
                normalizedAccountId
              ]
            );

            await tx.query(
              `
                DELETE FROM tenant_account_assistants
                WHERE account_id = ?
              `,
              [normalizedAccountId]
            );

            for (const assistantMembershipId of normalizedAssistantMembershipIds) {
              await tx.query(
                `
                  INSERT INTO tenant_account_assistants (
                    account_id,
                    assistant_membership_id,
                    created_by_user_id,
                    updated_by_user_id
                  )
                  VALUES (?, ?, ?, ?)
                `,
                [
                  normalizedAccountId,
                  assistantMembershipId,
                  normalizeRequiredString(operatorUserId) || null,
                  normalizeRequiredString(operatorUserId) || null
                ]
              );
            }

            await insertAccountOperationLogTx({
              txClient: tx,
              accountId: normalizedAccountId,
              tenantId: normalizedTenantId,
              operationType: 'update',
              operationContent: `编辑账号：${normalizedWechatId}`,
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
      return findTenantAccountByAccountId({
        tenantId: normalizedTenantId,
        accountId: normalizedAccountId
      });
    } catch (error) {
      if (isWechatDuplicateError(error)) {
        throw createWechatConflictError();
      }
      throw error;
    }
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

    const normalizedOperationAt = resolveOperationTimestampForWrite(operationAt);
    const updated = await executeWriteWithRetry({
      operation: 'updateTenantAccountStatus',
      execute: async () =>
        dbClient.inTransaction(async (tx) => {
          const existingRows = await tx.query(
            `
              SELECT account_id
              FROM tenant_accounts
              WHERE tenant_id = ?
                AND account_id = ?
              LIMIT 1
              FOR UPDATE
            `,
            [normalizedTenantId, normalizedAccountId]
          );
          if (!existingRows?.[0]) {
            return false;
          }

          await tx.query(
            `
              UPDATE tenant_accounts
              SET status = ?,
                  updated_by_user_id = ?,
                  updated_at = ?
              WHERE tenant_id = ?
                AND account_id = ?
            `,
            [
              normalizedStatus,
              normalizeRequiredString(operatorUserId) || null,
              normalizedOperationAt,
              normalizedTenantId,
              normalizedAccountId
            ]
          );

          await insertAccountOperationLogTx({
            txClient: tx,
            accountId: normalizedAccountId,
            tenantId: normalizedTenantId,
            operationType: 'status',
            operationContent: `账号状态更新为：${normalizedStatus}`,
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
    return findTenantAccountByAccountId({
      tenantId: normalizedTenantId,
      accountId: normalizedAccountId
    });
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

    const normalizedLimit = Number.isFinite(Number(limit))
      ? Math.max(1, Math.min(MAX_OPERATION_LOG_LIMIT, Math.floor(Number(limit))))
      : MAX_OPERATION_LOG_LIMIT;

    const rows = await dbClient.query(
      `
        SELECT operation_id,
               account_id,
               tenant_id,
               operation_type,
               operation_content,
               operator_user_id,
               operator_name,
               operation_time,
               created_at
        FROM tenant_account_operation_logs
        WHERE tenant_id = ?
          AND account_id = ?
        ORDER BY operation_time DESC, operation_id DESC
        LIMIT ?
      `,
      [normalizedTenantId, normalizedAccountId, normalizedLimit]
    );

    return (Array.isArray(rows) ? rows : [])
      .map((row) => toOperationLogRecordFromRow(row))
      .filter(Boolean);
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
  createTenantMysqlAuthStoreAccountMatrix
};
