'use strict';

const CONVERSATION_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const MESSAGE_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const OUTBOUND_MESSAGE_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const CLIENT_MESSAGE_ID_PATTERN = /^[^\s\u0000-\u001F\u007F]{1,64}$/;
const MAX_WECHAT_ID_LENGTH = 128;
const MAX_NICKNAME_LENGTH = 128;
const MAX_CONVERSATION_NAME_LENGTH = 128;
const MAX_MESSAGE_TYPE_LENGTH = 32;
const MAX_MESSAGE_PREVIEW_LENGTH = 512;
const MAX_SOURCE_EVENT_ID_LENGTH = 128;
const MAX_SOURCE_NAME_LENGTH = 32;
const MAX_PROVIDER_MESSAGE_ID_LENGTH = 128;
const MAX_ERROR_CODE_LENGTH = 64;
const MAX_ERROR_MESSAGE_LENGTH = 512;
const ENQUEUE_STATUS_SET = new Set([
  'pending',
  'processing',
  'retrying',
  'sent',
  'failed',
  'dead_letter',
  'cancelled'
]);

const createTenantMysqlAuthStoreSession = ({
  CONTROL_CHAR_PATTERN,
  dbClient,
  executeWithDeadlockRetry,
  formatAuditDateTimeForMySql,
  isDuplicateEntryError,
  normalizeStoreIsoTimestamp,
  randomUUID
} = {}) => {
  const normalizeRequiredString = (value) =>
    typeof value === 'string' ? value.trim() : '';

  const normalizeStrictRequiredString = (value) => {
    if (typeof value !== 'string') {
      return '';
    }
    const normalized = value.trim();
    if (!normalized || normalized !== value) {
      return '';
    }
    return normalized;
  };

  const normalizeTenantId = (tenantId) => normalizeStrictRequiredString(tenantId);

  const normalizeWechatId = (wechatId) => {
    const normalized = normalizeStrictRequiredString(wechatId);
    if (
      !normalized
      || normalized.length > MAX_WECHAT_ID_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeConversationId = (conversationId) => {
    const normalized = normalizeStrictRequiredString(conversationId);
    if (!normalized || !CONVERSATION_ID_PATTERN.test(normalized)) {
      return '';
    }
    return normalized;
  };

  const normalizeConversationType = (conversationType) => {
    const normalized = normalizeStrictRequiredString(conversationType).toLowerCase();
    if (normalized !== 'direct' && normalized !== 'group') {
      return '';
    }
    return normalized;
  };

  const normalizeConversationName = (conversationName) => {
    const normalized = normalizeStrictRequiredString(conversationName);
    if (
      !normalized
      || normalized.length > MAX_CONVERSATION_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeSourceName = (sourceName, fallbackValue) => {
    const normalized = normalizeRequiredString(sourceName).toLowerCase();
    if (
      !normalized
      || normalized.length > MAX_SOURCE_NAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return fallbackValue;
    }
    return normalized;
  };

  const normalizeNickname = (nickname) => {
    const normalized = normalizeStrictRequiredString(nickname);
    if (
      !normalized
      || normalized.length > MAX_NICKNAME_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeMessageType = (messageType) => {
    const normalized = normalizeStrictRequiredString(messageType).toLowerCase();
    if (
      !normalized
      || normalized.length > MAX_MESSAGE_TYPE_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizePreview = (preview) => {
    if (preview === null || preview === undefined) {
      return null;
    }
    const normalized = normalizeRequiredString(preview);
    if (!normalized) {
      return null;
    }
    return normalized.slice(0, MAX_MESSAGE_PREVIEW_LENGTH);
  };

  const normalizeSourceEventId = (sourceEventId) => {
    if (sourceEventId === null || sourceEventId === undefined || sourceEventId === '') {
      return '';
    }
    const normalized = normalizeStrictRequiredString(sourceEventId);
    if (
      !normalized
      || normalized.length > MAX_SOURCE_EVENT_ID_LENGTH
      || CONTROL_CHAR_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeClientMessageId = (clientMessageId) => {
    if (clientMessageId === null || clientMessageId === undefined || clientMessageId === '') {
      return '';
    }
    const normalized = normalizeStrictRequiredString(clientMessageId);
    if (
      !normalized
      || normalized.length > 64
      || !CLIENT_MESSAGE_ID_PATTERN.test(normalized)
    ) {
      return '';
    }
    return normalized;
  };

  const normalizeOutboundMessageId = (outboundMessageId) => {
    const normalized = normalizeStrictRequiredString(outboundMessageId);
    if (!normalized || !OUTBOUND_MESSAGE_ID_PATTERN.test(normalized)) {
      return '';
    }
    return normalized;
  };

  const normalizeMessageId = (messageId) => {
    const normalized = normalizeStrictRequiredString(messageId);
    if (!normalized || !MESSAGE_ID_PATTERN.test(normalized)) {
      return '';
    }
    return normalized;
  };

  const normalizeEnqueueStatus = (enqueueStatus) => {
    const normalized = normalizeRequiredString(enqueueStatus).toLowerCase();
    if (!ENQUEUE_STATUS_SET.has(normalized)) {
      return '';
    }
    return normalized;
  };

  const normalizeOptionalLimitedText = (value, maxLength) => {
    const normalized = normalizeRequiredString(value);
    if (!normalized) {
      return null;
    }
    return normalized.slice(0, maxLength);
  };

  const normalizeNameForCompare = (value) => {
    const normalized = normalizeRequiredString(value);
    if (!normalized) {
      return '';
    }
    return normalized
      .normalize('NFKC')
      .replace(/\s+/g, ' ')
      .toLowerCase();
  };

  const toIsoTimestamp = (value) => {
    if (value instanceof Date) {
      return value.toISOString();
    }
    if (value === null || value === undefined || value === '') {
      return '';
    }
    const parsed = new Date(value);
    if (Number.isNaN(parsed.getTime())) {
      return '';
    }
    return parsed.toISOString();
  };

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

  const resolveTimestampForWrite = (value) =>
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

  const createConversationDuplicateError = () => {
    const error = new Error('tenant session conversation duplicate');
    error.code = 'ERR_TENANT_SESSION_CONVERSATION_DUPLICATE';
    return error;
  };

  const createConversationNotFoundError = () => {
    const error = new Error('tenant session conversation not found');
    error.code = 'ERR_TENANT_SESSION_CONVERSATION_NOT_FOUND';
    return error;
  };

  const createOutboundMessageNotFoundError = () => {
    const error = new Error('tenant session outbound message not found');
    error.code = 'ERR_TENANT_SESSION_OUTBOUND_MESSAGE_NOT_FOUND';
    return error;
  };

  const isConversationDuplicateError = (error) =>
    isDuplicateEntryError(error)
    && /PRIMARY|uk_tenant_session_conversations/i.test(String(error?.message || ''));

  const isHistorySourceEventDuplicateError = (error) =>
    isDuplicateEntryError(error)
    && /uk_tenant_session_history_messages_source_event/i.test(String(error?.message || ''));

  const isOutboundClientDuplicateError = (error) =>
    isDuplicateEntryError(error)
    && /uk_tenant_session_outbound_messages_client/i.test(String(error?.message || ''));

  const createConversationId = () =>
    `conv_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createMessageId = () =>
    `hmsg_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createOutboundMessageId = () =>
    `som_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const toConversationRecordFromRow = (row = {}) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      return null;
    }
    const conversationId = normalizeConversationId(row.conversation_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const accountWechatId = normalizeWechatId(row.account_wechat_id);
    const conversationType = normalizeConversationType(row.conversation_type);
    const conversationName = normalizeConversationName(row.conversation_name);
    const createdAt = normalizeStoreIsoTimestamp(row.created_at);
    const updatedAt = normalizeStoreIsoTimestamp(row.updated_at);
    if (
      !conversationId
      || !tenantId
      || !accountWechatId
      || !conversationType
      || !conversationName
      || !createdAt
      || !updatedAt
    ) {
      return null;
    }
    return {
      conversation_id: conversationId,
      tenant_id: tenantId,
      account_wechat_id: accountWechatId,
      account_wechat_id_normalized: normalizeRequiredString(
        row.account_wechat_id_normalized
      ) || accountWechatId.toLowerCase(),
      conversation_type: conversationType,
      conversation_name: conversationName,
      conversation_name_normalized: normalizeRequiredString(
        row.conversation_name_normalized
      ) || normalizeNameForCompare(conversationName),
      last_message_time: normalizeStoreIsoTimestamp(row.last_message_time) || null,
      last_message_preview: normalizePreview(row.last_message_preview),
      external_updated_at: normalizeStoreIsoTimestamp(row.external_updated_at) || null,
      sync_source: normalizeSourceName(row.sync_source, 'external'),
      created_at: createdAt,
      updated_at: updatedAt
    };
  };

  const toHistoryMessageRecordFromRow = (row = {}) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      return null;
    }
    const messageId = normalizeStrictRequiredString(row.message_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const conversationId = normalizeConversationId(row.conversation_id);
    const senderName = normalizeConversationName(row.sender_name);
    const messageType = normalizeMessageType(row.message_type);
    const messageTime = normalizeStoreIsoTimestamp(row.message_time);
    if (
      !messageId
      || !tenantId
      || !conversationId
      || !senderName
      || !messageType
      || !messageTime
    ) {
      return null;
    }
    return {
      message_id: messageId,
      tenant_id: tenantId,
      conversation_id: conversationId,
      sender_name: senderName,
      sender_name_normalized: normalizeRequiredString(row.sender_name_normalized)
        || normalizeNameForCompare(senderName),
      is_self:
        row.is_self === null || row.is_self === undefined
          ? null
          : Number(row.is_self) === 1
            ? 1
            : 0,
      message_type: messageType,
      message_payload_json: row.message_payload_json,
      message_preview: normalizePreview(row.message_preview),
      message_time: messageTime,
      source_event_id: normalizeRequiredString(row.source_event_id) || null,
      ingest_source: normalizeSourceName(row.ingest_source, 'external'),
      ingested_at: normalizeStoreIsoTimestamp(row.ingested_at) || null,
      created_at: normalizeStoreIsoTimestamp(row.created_at) || null
    };
  };

  const toOutboundMessageRecordFromRow = (row = {}) => {
    if (!row || typeof row !== 'object' || Array.isArray(row)) {
      return null;
    }
    const outboundMessageId = normalizeOutboundMessageId(row.outbound_message_id);
    const tenantId = normalizeTenantId(row.tenant_id);
    const accountWechatId = normalizeWechatId(row.account_wechat_id);
    const accountNickname = normalizeNickname(row.account_nickname);
    const conversationId = normalizeConversationId(row.conversation_id);
    const conversationName = normalizeConversationName(row.conversation_name);
    const messageType = normalizeMessageType(row.message_type);
    const sendTime = normalizeStoreIsoTimestamp(row.send_time);
    const enqueueStatus = normalizeEnqueueStatus(row.enqueue_status);
    if (
      !outboundMessageId
      || !tenantId
      || !accountWechatId
      || !accountNickname
      || !conversationId
      || !conversationName
      || !messageType
      || !sendTime
      || !enqueueStatus
    ) {
      return null;
    }
    return {
      outbound_message_id: outboundMessageId,
      tenant_id: tenantId,
      account_wechat_id: accountWechatId,
      account_nickname: accountNickname,
      conversation_id: conversationId,
      conversation_name: conversationName,
      message_type: messageType,
      message_payload_json: row.message_payload_json,
      message_preview: normalizePreview(row.message_preview),
      send_time: sendTime,
      enqueue_status: enqueueStatus,
      provider_message_id: normalizeRequiredString(row.provider_message_id) || null,
      error_code: normalizeRequiredString(row.error_code) || null,
      error_message: normalizeRequiredString(row.error_message) || null,
      status_updated_at: normalizeStoreIsoTimestamp(row.status_updated_at) || null,
      client_message_id: normalizeRequiredString(row.client_message_id) || null,
      created_at: normalizeStoreIsoTimestamp(row.created_at) || null
    };
  };

  const loadConversationByTenantAndConversationId = async ({
    tenantId,
    conversationId
  }) => {
    const rows = await dbClient.query(
      `
        SELECT conversation_id,
               tenant_id,
               account_wechat_id,
               account_wechat_id_normalized,
               conversation_type,
               conversation_name,
               conversation_name_normalized,
               last_message_time,
               last_message_preview,
               external_updated_at,
               sync_source,
               created_at,
               updated_at
        FROM tenant_session_conversations
        WHERE tenant_id = ?
          AND conversation_id = ?
        LIMIT 1
      `,
      [tenantId, conversationId]
    );
    return toConversationRecordFromRow(rows?.[0] || null);
  };

  const loadHistoryMessageByTenantAndMessageId = async ({
    tenantId,
    messageId
  }) => {
    const rows = await dbClient.query(
      `
        SELECT message_id,
               tenant_id,
               conversation_id,
               sender_name,
               sender_name_normalized,
               is_self,
               message_type,
               message_payload_json,
               message_preview,
               message_time,
               source_event_id,
               ingest_source,
               ingested_at,
               created_at
        FROM tenant_session_history_messages
        WHERE tenant_id = ?
          AND message_id = ?
        LIMIT 1
      `,
      [tenantId, messageId]
    );
    return toHistoryMessageRecordFromRow(rows?.[0] || null);
  };

  const loadHistoryMessageBySourceEvent = async ({
    tenantId,
    conversationId,
    sourceEventId
  }) => {
    const rows = await dbClient.query(
      `
        SELECT message_id,
               tenant_id,
               conversation_id,
               sender_name,
               sender_name_normalized,
               is_self,
               message_type,
               message_payload_json,
               message_preview,
               message_time,
               source_event_id,
               ingest_source,
               ingested_at,
               created_at
        FROM tenant_session_history_messages
        WHERE tenant_id = ?
          AND conversation_id = ?
          AND source_event_id = ?
        LIMIT 1
      `,
      [tenantId, conversationId, sourceEventId]
    );
    return toHistoryMessageRecordFromRow(rows?.[0] || null);
  };

  const loadOutboundMessageByTenantAndOutboundId = async ({
    tenantId,
    outboundMessageId
  }) => {
    const rows = await dbClient.query(
      `
        SELECT outbound_message_id,
               tenant_id,
               account_wechat_id,
               account_nickname,
               conversation_id,
               conversation_name,
               message_type,
               message_payload_json,
               message_preview,
               send_time,
               enqueue_status,
               provider_message_id,
               error_code,
               error_message,
               status_updated_at,
               client_message_id,
               created_at
        FROM tenant_session_outbound_messages
        WHERE tenant_id = ?
          AND outbound_message_id = ?
        LIMIT 1
      `,
      [tenantId, outboundMessageId]
    );
    return toOutboundMessageRecordFromRow(rows?.[0] || null);
  };

  const loadOutboundMessageByClientMessageId = async ({
    tenantId,
    accountWechatId,
    clientMessageId
  }) => {
    const rows = await dbClient.query(
      `
        SELECT outbound_message_id,
               tenant_id,
               account_wechat_id,
               account_nickname,
               conversation_id,
               conversation_name,
               message_type,
               message_payload_json,
               message_preview,
               send_time,
               enqueue_status,
               provider_message_id,
               error_code,
               error_message,
               status_updated_at,
               client_message_id,
               created_at
        FROM tenant_session_outbound_messages
        WHERE tenant_id = ?
          AND account_wechat_id = ?
          AND client_message_id = ?
        LIMIT 1
      `,
      [tenantId, accountWechatId, clientMessageId]
    );
    return toOutboundMessageRecordFromRow(rows?.[0] || null);
  };

  const applyHistoryConversationSummaryCompensation = async ({
    tenantId,
    conversationId,
    messageTime,
    messagePreview = null
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedConversationId = normalizeConversationId(conversationId);
    const messageTimeForWrite = toMySqlTimestamp(messageTime);
    if (!normalizedTenantId || !normalizedConversationId || !messageTimeForWrite) {
      return;
    }
    const nowTimestamp = resolveTimestampForWrite(new Date());
    await executeWriteWithRetry({
      operation: 'tenantSessionHistorySummaryCompensation',
      execute: () =>
        dbClient.query(
          `
            UPDATE tenant_session_conversations
            SET last_message_preview = CASE
                  WHEN last_message_time IS NULL OR last_message_time <= ?
                    THEN ?
                  ELSE last_message_preview
                END,
                last_message_time = CASE
                  WHEN last_message_time IS NULL OR last_message_time <= ?
                    THEN ?
                  ELSE last_message_time
                END,
                updated_at = CASE
                  WHEN last_message_time IS NULL OR last_message_time <= ?
                    THEN ?
                  ELSE updated_at
                END
            WHERE tenant_id = ?
              AND conversation_id = ?
          `,
          [
            messageTimeForWrite,
            normalizePreview(messagePreview),
            messageTimeForWrite,
            messageTimeForWrite,
            messageTimeForWrite,
            nowTimestamp,
            normalizedTenantId,
            normalizedConversationId
          ]
        )
    });
  };

  const applyOutboundConversationSummaryCompensation = async ({
    tenantId,
    conversationId,
    messageTime,
    messagePreview = null
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedConversationId = normalizeConversationId(conversationId);
    const messageTimeForWrite = toMySqlTimestamp(messageTime);
    if (!normalizedTenantId || !normalizedConversationId || !messageTimeForWrite) {
      return;
    }
    const nowTimestamp = resolveTimestampForWrite(new Date());
    await executeWriteWithRetry({
      operation: 'tenantSessionOutboundSummaryCompensation',
      execute: () =>
        dbClient.query(
          `
            UPDATE tenant_session_conversations
            SET last_message_preview = ?,
                last_message_time = ?,
                updated_at = ?
            WHERE tenant_id = ?
              AND conversation_id = ?
          `,
          [
            normalizePreview(messagePreview),
            messageTimeForWrite,
            nowTimestamp,
            normalizedTenantId,
            normalizedConversationId
          ]
        )
    });
  };

  const createTenantSessionConversation = async ({
    tenantId,
    accountWechatId,
    conversationId,
    conversationType,
    conversationName,
    lastMessageTime = null,
    lastMessagePreview = null,
    externalUpdatedAt = null,
    syncSource = 'external'
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountWechatId = normalizeWechatId(accountWechatId);
    const normalizedConversationId = normalizeConversationId(conversationId || createConversationId());
    const normalizedConversationType = normalizeConversationType(conversationType);
    const normalizedConversationName = normalizeConversationName(conversationName);
    if (
      !normalizedTenantId
      || !normalizedAccountWechatId
      || !normalizedConversationId
      || !normalizedConversationType
      || !normalizedConversationName
    ) {
      throw createConversationNotFoundError();
    }

    const nowTimestamp = resolveTimestampForWrite(new Date());

    try {
      await executeWriteWithRetry({
        operation: 'tenantSessionConversationInsert',
        execute: () =>
          dbClient.query(
            `
              INSERT INTO tenant_session_conversations (
                conversation_id,
                tenant_id,
                account_wechat_id,
                account_wechat_id_normalized,
                conversation_type,
                conversation_name,
                conversation_name_normalized,
                last_message_time,
                last_message_preview,
                external_updated_at,
                sync_source,
                created_at,
                updated_at
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
              normalizedConversationId,
              normalizedTenantId,
              normalizedAccountWechatId,
              normalizedAccountWechatId.toLowerCase(),
              normalizedConversationType,
              normalizedConversationName,
              normalizeNameForCompare(normalizedConversationName),
              toMySqlTimestamp(lastMessageTime) || null,
              normalizePreview(lastMessagePreview),
              toMySqlTimestamp(externalUpdatedAt) || null,
              normalizeSourceName(syncSource, 'external'),
              nowTimestamp,
              nowTimestamp
            ]
          )
      });
    } catch (error) {
      if (isConversationDuplicateError(error)) {
        throw createConversationDuplicateError();
      }
      throw error;
    }

    const stored = await loadConversationByTenantAndConversationId({
      tenantId: normalizedTenantId,
      conversationId: normalizedConversationId
    });
    if (!stored) {
      throw createConversationNotFoundError();
    }
    return stored;
  };

  const findTenantSessionConversationByConversationId = async ({
    tenantId,
    conversationId
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedConversationId = normalizeConversationId(conversationId);
    if (!normalizedTenantId || !normalizedConversationId) {
      return null;
    }
    return loadConversationByTenantAndConversationId({
      tenantId: normalizedTenantId,
      conversationId: normalizedConversationId
    });
  };

  const listTenantSessionConversationsByAccountWechatId = async ({
    tenantId,
    accountWechatId,
    keyword = ''
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountWechatId = normalizeWechatId(accountWechatId);
    if (!normalizedTenantId || !normalizedAccountWechatId) {
      return [];
    }

    const whereClauses = [
      'tenant_id = ?',
      'account_wechat_id_normalized = ?'
    ];
    const params = [
      normalizedTenantId,
      normalizedAccountWechatId.toLowerCase()
    ];
    const keywordNormalized = normalizeNameForCompare(keyword);
    if (keywordNormalized) {
      whereClauses.push('conversation_name_normalized LIKE ?');
      params.push(`%${keywordNormalized}%`);
    }

    const rows = await dbClient.query(
      `
        SELECT conversation_id,
               tenant_id,
               account_wechat_id,
               account_wechat_id_normalized,
               conversation_type,
               conversation_name,
               conversation_name_normalized,
               last_message_time,
               last_message_preview,
               external_updated_at,
               sync_source,
               created_at,
               updated_at
        FROM tenant_session_conversations
        WHERE ${whereClauses.join(' AND ')}
        ORDER BY last_message_time DESC, updated_at DESC, conversation_id DESC
      `,
      params
    );

    return (Array.isArray(rows) ? rows : [])
      .map((row) => toConversationRecordFromRow(row))
      .filter(Boolean);
  };

  const createTenantSessionHistoryMessage = async ({
    tenantId,
    conversationId,
    senderName,
    senderNameNormalized = '',
    isSelf = null,
    messageType,
    messagePayloadJson,
    messagePreview = null,
    messageTime,
    sourceEventId = '',
    ingestSource = 'external'
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedConversationId = normalizeConversationId(conversationId);
    const normalizedSenderName = normalizeConversationName(senderName);
    const normalizedMessageType = normalizeMessageType(messageType);
    const normalizedMessageTime = toIsoTimestamp(messageTime);
    const normalizedSourceEventId = normalizeSourceEventId(sourceEventId);
    if (
      !normalizedTenantId
      || !normalizedConversationId
      || !normalizedSenderName
      || !normalizedMessageType
      || !normalizedMessageTime
    ) {
      throw createConversationNotFoundError();
    }

    const conversation = await loadConversationByTenantAndConversationId({
      tenantId: normalizedTenantId,
      conversationId: normalizedConversationId
    });
    if (!conversation) {
      throw createConversationNotFoundError();
    }

    if (normalizedSourceEventId) {
      const existingBySourceEvent = await loadHistoryMessageBySourceEvent({
        tenantId: normalizedTenantId,
        conversationId: normalizedConversationId,
        sourceEventId: normalizedSourceEventId
      });
      if (existingBySourceEvent) {
        await applyHistoryConversationSummaryCompensation({
          tenantId: normalizedTenantId,
          conversationId: normalizedConversationId,
          messageTime: existingBySourceEvent.message_time,
          messagePreview: existingBySourceEvent.message_preview
        });
        return {
          ...existingBySourceEvent,
          idempotent_replay: true
        };
      }
    }

    const messageId = createMessageId();
    const nowTimestamp = resolveTimestampForWrite(new Date());
    const messageTimeForWrite = toMySqlTimestamp(normalizedMessageTime);
    const messagePreviewNormalized = normalizePreview(messagePreview);

    try {
      await executeWriteWithRetry({
        operation: 'tenantSessionHistoryInsert',
        execute: async () => {
          await dbClient.query(
            `
              INSERT INTO tenant_session_history_messages (
                message_id,
                tenant_id,
                conversation_id,
                sender_name,
                sender_name_normalized,
                is_self,
                message_type,
                message_payload_json,
                message_preview,
                message_time,
                source_event_id,
                ingest_source,
                ingested_at,
                created_at
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
              messageId,
              normalizedTenantId,
              normalizedConversationId,
              normalizedSenderName,
              senderNameNormalized || normalizeNameForCompare(normalizedSenderName),
              isSelf === null || isSelf === undefined
                ? null
                : Number(isSelf) === 1
                  ? 1
                  : 0,
              normalizedMessageType,
              JSON.stringify(messagePayloadJson),
              messagePreviewNormalized,
              messageTimeForWrite,
              normalizedSourceEventId || null,
              normalizeSourceName(ingestSource, 'external'),
              nowTimestamp,
              nowTimestamp
            ]
          );
          await dbClient.query(
            `
              UPDATE tenant_session_conversations
              SET last_message_preview = CASE
                    WHEN last_message_time IS NULL OR last_message_time <= ?
                      THEN ?
                    ELSE last_message_preview
                  END,
                  last_message_time = CASE
                    WHEN last_message_time IS NULL OR last_message_time <= ?
                      THEN ?
                    ELSE last_message_time
                  END,
                  updated_at = CASE
                    WHEN last_message_time IS NULL OR last_message_time <= ?
                      THEN ?
                    ELSE updated_at
                  END
              WHERE tenant_id = ?
                AND conversation_id = ?
            `,
            [
              messageTimeForWrite,
              messagePreviewNormalized,
              messageTimeForWrite,
              messageTimeForWrite,
              messageTimeForWrite,
              nowTimestamp,
              normalizedTenantId,
              normalizedConversationId
            ]
          );
        }
      });
    } catch (error) {
      if (isHistorySourceEventDuplicateError(error) && normalizedSourceEventId) {
        const existingBySourceEvent = await loadHistoryMessageBySourceEvent({
          tenantId: normalizedTenantId,
          conversationId: normalizedConversationId,
          sourceEventId: normalizedSourceEventId
        });
        if (existingBySourceEvent) {
          await applyHistoryConversationSummaryCompensation({
            tenantId: normalizedTenantId,
            conversationId: normalizedConversationId,
            messageTime: existingBySourceEvent.message_time,
            messagePreview: existingBySourceEvent.message_preview
          });
          return {
            ...existingBySourceEvent,
            idempotent_replay: true
          };
        }
      }
      throw error;
    }

    const stored = await loadHistoryMessageByTenantAndMessageId({
      tenantId: normalizedTenantId,
      messageId
    });
    if (!stored) {
      throw createConversationNotFoundError();
    }

    return {
      ...stored,
      idempotent_replay: false
    };
  };

  const listTenantSessionHistoryMessagesByConversationId = async ({
    tenantId,
    conversationId,
    cursor = null,
    cursorCreatedAt = null,
    cursorMessageId = '',
    limit = 50
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedConversationId = normalizeConversationId(conversationId);
    if (!normalizedTenantId || !normalizedConversationId) {
      return [];
    }

    const normalizedLimit = Math.max(1, Math.min(200, Number(limit) || 50));
    const cursorTime = toMySqlTimestamp(cursor);
    const cursorCreatedAtTime = toMySqlTimestamp(cursorCreatedAt);
    const normalizedCursorMessageId = normalizeMessageId(cursorMessageId);
    const whereClauses = [
      'tenant_id = ?',
      'conversation_id = ?'
    ];
    const params = [normalizedTenantId, normalizedConversationId];
    if (cursorTime && cursorCreatedAtTime && normalizedCursorMessageId) {
      whereClauses.push(`(
        message_time < ?
        OR (message_time = ? AND created_at < ?)
        OR (message_time = ? AND created_at = ? AND message_id < ?)
      )`);
      params.push(
        cursorTime,
        cursorTime,
        cursorCreatedAtTime,
        cursorTime,
        cursorCreatedAtTime,
        normalizedCursorMessageId
      );
    } else if (cursorTime) {
      whereClauses.push('message_time < ?');
      params.push(cursorTime);
    }
    params.push(normalizedLimit);

    const rows = await dbClient.query(
      `
        SELECT message_id,
               tenant_id,
               conversation_id,
               sender_name,
               sender_name_normalized,
               is_self,
               message_type,
               message_payload_json,
               message_preview,
               message_time,
               source_event_id,
               ingest_source,
               ingested_at,
               created_at
        FROM tenant_session_history_messages
        WHERE ${whereClauses.join(' AND ')}
        ORDER BY message_time DESC, created_at DESC, message_id DESC
        LIMIT ?
      `,
      params
    );

    return (Array.isArray(rows) ? rows : [])
      .map((row) => toHistoryMessageRecordFromRow(row))
      .filter(Boolean);
  };

  const createTenantSessionOutboundMessage = async ({
    tenantId,
    accountWechatId,
    accountNickname,
    conversationId,
    conversationName,
    messageType,
    messagePayloadJson,
    messagePreview = null,
    clientMessageId = ''
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedAccountWechatId = normalizeWechatId(accountWechatId);
    const normalizedAccountNickname = normalizeNickname(accountNickname);
    const normalizedConversationId = normalizeConversationId(conversationId);
    const normalizedConversationName = normalizeConversationName(conversationName);
    const normalizedMessageType = normalizeMessageType(messageType);
    const normalizedClientMessageId = normalizeClientMessageId(clientMessageId);
    if (
      !normalizedTenantId
      || !normalizedAccountWechatId
      || !normalizedAccountNickname
      || !normalizedConversationId
      || !normalizedConversationName
      || !normalizedMessageType
    ) {
      throw createConversationNotFoundError();
    }

    const conversation = await loadConversationByTenantAndConversationId({
      tenantId: normalizedTenantId,
      conversationId: normalizedConversationId
    });
    if (!conversation) {
      throw createConversationNotFoundError();
    }

    if (normalizedClientMessageId) {
      const existingByClientMessageId = await loadOutboundMessageByClientMessageId({
        tenantId: normalizedTenantId,
        accountWechatId: normalizedAccountWechatId,
        clientMessageId: normalizedClientMessageId
      });
      if (existingByClientMessageId) {
        await applyOutboundConversationSummaryCompensation({
          tenantId: normalizedTenantId,
          conversationId: normalizedConversationId,
          messageTime: existingByClientMessageId.send_time,
          messagePreview: existingByClientMessageId.message_preview
        });
        return {
          ...existingByClientMessageId,
          idempotent_replay: true
        };
      }
    }

    const outboundMessageId = createOutboundMessageId();
    const nowTimestamp = resolveTimestampForWrite(new Date());
    const messagePreviewNormalized = normalizePreview(messagePreview);

    try {
      await executeWriteWithRetry({
        operation: 'tenantSessionOutboundInsert',
        execute: async () => {
          await dbClient.query(
            `
              INSERT INTO tenant_session_outbound_messages (
                outbound_message_id,
                tenant_id,
                account_wechat_id,
                account_nickname,
                conversation_id,
                conversation_name,
                message_type,
                message_payload_json,
                message_preview,
                send_time,
                enqueue_status,
                provider_message_id,
                error_code,
                error_message,
                status_updated_at,
                client_message_id,
                created_at
              )
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `,
            [
              outboundMessageId,
              normalizedTenantId,
              normalizedAccountWechatId,
              normalizedAccountNickname,
              normalizedConversationId,
              normalizedConversationName,
              normalizedMessageType,
              JSON.stringify(messagePayloadJson),
              messagePreviewNormalized,
              nowTimestamp,
              'pending',
              null,
              null,
              null,
              null,
              normalizedClientMessageId || null,
              nowTimestamp
            ]
          );

          await dbClient.query(
            `
              UPDATE tenant_session_conversations
              SET last_message_preview = ?,
                  last_message_time = ?,
                  updated_at = ?
              WHERE tenant_id = ?
                AND conversation_id = ?
            `,
            [
              messagePreviewNormalized,
              nowTimestamp,
              nowTimestamp,
              normalizedTenantId,
              normalizedConversationId
            ]
          );
        }
      });
    } catch (error) {
      if (isOutboundClientDuplicateError(error) && normalizedClientMessageId) {
        const existingByClientMessageId = await loadOutboundMessageByClientMessageId({
          tenantId: normalizedTenantId,
          accountWechatId: normalizedAccountWechatId,
          clientMessageId: normalizedClientMessageId
        });
        if (existingByClientMessageId) {
          await applyOutboundConversationSummaryCompensation({
            tenantId: normalizedTenantId,
            conversationId: normalizedConversationId,
            messageTime: existingByClientMessageId.send_time,
            messagePreview: existingByClientMessageId.message_preview
          });
          return {
            ...existingByClientMessageId,
            idempotent_replay: true
          };
        }
      }
      throw error;
    }

    const stored = await loadOutboundMessageByTenantAndOutboundId({
      tenantId: normalizedTenantId,
      outboundMessageId
    });
    if (!stored) {
      throw createOutboundMessageNotFoundError();
    }
    return {
      ...stored,
      idempotent_replay: false
    };
  };

  const listTenantSessionOutboundMessagesForPull = async ({
    tenantId,
    statuses = [],
    limit = 100,
    accountWechatIds = []
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    if (!normalizedTenantId) {
      return [];
    }

    const normalizedStatuses = [...new Set(
      (Array.isArray(statuses) ? statuses : [])
        .map((status) => normalizeEnqueueStatus(status))
        .filter(Boolean)
    )];
    const normalizedAccountWechatIds = [...new Set(
      (Array.isArray(accountWechatIds) ? accountWechatIds : [])
        .map((wechatId) => normalizeWechatId(wechatId))
        .filter(Boolean)
    )];
    if (normalizedStatuses.length < 1 || normalizedAccountWechatIds.length < 1) {
      return [];
    }
    const normalizedLimit = Math.max(1, Math.min(200, Number(limit) || 100));

    const statusPlaceholders = normalizedStatuses.map(() => '?').join(', ');
    const accountPlaceholders = normalizedAccountWechatIds.map(() => '?').join(', ');
    const params = [
      normalizedTenantId,
      ...normalizedStatuses,
      ...normalizedAccountWechatIds,
      normalizedLimit
    ];

    const rows = await dbClient.query(
      `
        SELECT outbound_message_id,
               tenant_id,
               account_wechat_id,
               account_nickname,
               conversation_id,
               conversation_name,
               message_type,
               message_payload_json,
               message_preview,
               send_time,
               enqueue_status,
               provider_message_id,
               error_code,
               error_message,
               status_updated_at,
               client_message_id,
               created_at
        FROM tenant_session_outbound_messages
        WHERE tenant_id = ?
          AND enqueue_status IN (${statusPlaceholders})
          AND account_wechat_id IN (${accountPlaceholders})
        ORDER BY send_time ASC, outbound_message_id ASC
        LIMIT ?
      `,
      params
    );

    return (Array.isArray(rows) ? rows : [])
      .map((row) => toOutboundMessageRecordFromRow(row))
      .filter(Boolean);
  };

  const updateTenantSessionOutboundMessageStatus = async ({
    tenantId,
    outboundMessageId,
    enqueueStatus,
    providerMessageId = null,
    errorCode = null,
    errorMessage = null,
    statusUpdatedAt = null
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedOutboundMessageId = normalizeOutboundMessageId(outboundMessageId);
    const normalizedEnqueueStatus = normalizeEnqueueStatus(enqueueStatus);
    if (
      !normalizedTenantId
      || !normalizedOutboundMessageId
      || !normalizedEnqueueStatus
    ) {
      throw createOutboundMessageNotFoundError();
    }

    const statusUpdatedAtForWrite = resolveTimestampForWrite(statusUpdatedAt || new Date());

    await executeWriteWithRetry({
      operation: 'tenantSessionOutboundStatusUpdate',
      execute: () =>
        dbClient.query(
          `
            UPDATE tenant_session_outbound_messages
            SET enqueue_status = ?,
                provider_message_id = ?,
                error_code = ?,
                error_message = ?,
                status_updated_at = ?
            WHERE tenant_id = ?
              AND outbound_message_id = ?
            LIMIT 1
          `,
          [
            normalizedEnqueueStatus,
            normalizeOptionalLimitedText(providerMessageId, MAX_PROVIDER_MESSAGE_ID_LENGTH),
            normalizeOptionalLimitedText(errorCode, MAX_ERROR_CODE_LENGTH),
            normalizeOptionalLimitedText(errorMessage, MAX_ERROR_MESSAGE_LENGTH),
            statusUpdatedAtForWrite,
            normalizedTenantId,
            normalizedOutboundMessageId
          ]
        )
    });

    return loadOutboundMessageByTenantAndOutboundId({
      tenantId: normalizedTenantId,
      outboundMessageId: normalizedOutboundMessageId
    });
  };

  const findTenantSessionOutboundMessageByOutboundMessageId = async ({
    tenantId,
    outboundMessageId
  } = {}) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedOutboundMessageId = normalizeOutboundMessageId(outboundMessageId);
    if (!normalizedTenantId || !normalizedOutboundMessageId) {
      return null;
    }
    return loadOutboundMessageByTenantAndOutboundId({
      tenantId: normalizedTenantId,
      outboundMessageId: normalizedOutboundMessageId
    });
  };

  return {
    createTenantSessionConversation,
    findTenantSessionConversationByConversationId,
    listTenantSessionConversationsByAccountWechatId,
    createTenantSessionHistoryMessage,
    listTenantSessionHistoryMessagesByConversationId,
    createTenantSessionOutboundMessage,
    listTenantSessionOutboundMessagesForPull,
    findTenantSessionOutboundMessageByOutboundMessageId,
    updateTenantSessionOutboundMessageStatus
  };
};

module.exports = {
  createTenantMysqlAuthStoreSession
};
