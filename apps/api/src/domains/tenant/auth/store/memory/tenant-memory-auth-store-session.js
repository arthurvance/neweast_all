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

const createTenantMemoryAuthStoreSession = ({
  randomUUID,
  CONTROL_CHAR_PATTERN,
  tenantAccountsByAccountId,
  tenantAccountIdsByTenantId,
  tenantSessionConversationsByConversationId,
  tenantSessionConversationIdsByTenantWechatKey,
  tenantSessionConversationUniqueIndex,
  tenantSessionHistoryMessagesByMessageId,
  tenantSessionHistoryMessageIdsByConversationId,
  tenantSessionHistoryMessageSourceEventIndex,
  tenantSessionOutboundMessagesByOutboundMessageId,
  tenantSessionOutboundMessageIdsByTenantId,
  tenantSessionOutboundMessageClientIndex,
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

  const createConversationId = () =>
    `conv_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createMessageId = () =>
    `hmsg_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const createOutboundMessageId = () =>
    `som_${Date.now().toString(36)}_${String(randomUUID()).replace(/-/g, '').slice(0, 10)}`;

  const toTenantWechatKey = ({ tenantId, accountWechatId }) =>
    `${normalizeTenantId(tenantId)}::${normalizeWechatId(accountWechatId).toLowerCase()}`;

  const toConversationSourceEventKey = ({
    tenantId,
    conversationId,
    sourceEventId
  }) =>
    `${normalizeTenantId(tenantId)}::${normalizeConversationId(conversationId)}::${normalizeSourceEventId(sourceEventId)}`;

  const toOutboundClientKey = ({
    tenantId,
    accountWechatId,
    clientMessageId
  }) =>
    `${normalizeTenantId(tenantId)}::${normalizeWechatId(accountWechatId).toLowerCase()}::${normalizeClientMessageId(clientMessageId)}`;

  const toConversationUniqueKey = ({
    tenantId,
    accountWechatId,
    conversationType,
    conversationName
  }) =>
    [
      normalizeTenantId(tenantId),
      normalizeWechatId(accountWechatId).toLowerCase(),
      normalizeConversationType(conversationType),
      normalizeNameForCompare(conversationName)
    ].join('::');

  const conversationUniqueIndex =
    tenantSessionConversationUniqueIndex instanceof Map
      ? tenantSessionConversationUniqueIndex
      : new Map();

  const toConversationIdSetByTenantWechatKey = ({
    tenantId,
    accountWechatId
  }) => {
    const key = toTenantWechatKey({ tenantId, accountWechatId });
    const existing = tenantSessionConversationIdsByTenantWechatKey.get(key);
    if (existing instanceof Set) {
      return existing;
    }
    const next = new Set();
    tenantSessionConversationIdsByTenantWechatKey.set(key, next);
    return next;
  };

  const toHistoryMessageIdListByConversationId = ({ conversationId }) => {
    const normalizedConversationId = normalizeConversationId(conversationId);
    const existing = tenantSessionHistoryMessageIdsByConversationId.get(normalizedConversationId);
    if (Array.isArray(existing)) {
      return existing;
    }
    const next = [];
    tenantSessionHistoryMessageIdsByConversationId.set(normalizedConversationId, next);
    return next;
  };

  const toOutboundMessageIdSetByTenantId = ({ tenantId }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const existing = tenantSessionOutboundMessageIdsByTenantId.get(normalizedTenantId);
    if (existing instanceof Set) {
      return existing;
    }
    const next = new Set();
    tenantSessionOutboundMessageIdsByTenantId.set(normalizedTenantId, next);
    return next;
  };

  const findTenantAccountByWechatId = ({ tenantId, accountWechatId }) => {
    const normalizedTenantId = normalizeTenantId(tenantId);
    const normalizedWechatId = normalizeWechatId(accountWechatId);
    if (!normalizedTenantId || !normalizedWechatId) {
      return null;
    }
    const accountIds = tenantAccountIdsByTenantId.get(normalizedTenantId);
    if (!(accountIds instanceof Set) || accountIds.size < 1) {
      return null;
    }
    const targetWechatId = normalizedWechatId.toLowerCase();
    for (const accountId of accountIds) {
      const account = tenantAccountsByAccountId.get(String(accountId || '').toLowerCase());
      if (!account || typeof account !== 'object') {
        continue;
      }
      const status = normalizeRequiredString(account.status).toLowerCase();
      if (status && status !== 'enabled' && status !== 'active') {
        continue;
      }
      const accountWechatIdRaw = normalizeWechatId(account.wechat_id || account.wechatId);
      if (!accountWechatIdRaw) {
        continue;
      }
      if (accountWechatIdRaw.toLowerCase() === targetWechatId) {
        return {
          ...cloneValue(account),
          wechat_id: accountWechatIdRaw
        };
      }
    }
    return null;
  };

  const cloneConversationRecord = (record = null) => {
    if (!record || typeof record !== 'object') {
      return null;
    }
    const normalizedConversationId = normalizeConversationId(record.conversation_id);
    if (!normalizedConversationId) {
      return null;
    }
    return cloneValue(record);
  };

  const cloneHistoryMessageRecord = (record = null) => {
    if (!record || typeof record !== 'object') {
      return null;
    }
    const normalizedMessageId = normalizeStrictRequiredString(record.message_id);
    if (!normalizedMessageId) {
      return null;
    }
    return cloneValue(record);
  };

  const cloneOutboundMessageRecord = (record = null) => {
    if (!record || typeof record !== 'object') {
      return null;
    }
    const normalizedOutboundMessageId = normalizeOutboundMessageId(record.outbound_message_id);
    if (!normalizedOutboundMessageId) {
      return null;
    }
    return cloneValue(record);
  };

  const patchConversationSummary = ({
    tenantId,
    conversationId,
    messageTime,
    messagePreview,
    nowIso
  }) => {
    const conversation = tenantSessionConversationsByConversationId.get(
      normalizeConversationId(conversationId)
    );
    if (!conversation || conversation.tenant_id !== tenantId) {
      return;
    }
    const currentLastMessageTime = toIsoTimestamp(conversation.last_message_time) || '';
    const incomingMessageTime = toIsoTimestamp(messageTime) || '';
    if (
      !incomingMessageTime
      || !currentLastMessageTime
      || incomingMessageTime >= currentLastMessageTime
    ) {
      conversation.last_message_time = incomingMessageTime || currentLastMessageTime || null;
      conversation.last_message_preview = normalizePreview(messagePreview);
      conversation.updated_at = nowIso;
    }
  };

  const compareIsoDesc = (leftValue, rightValue) => {
    const normalizedLeft = toIsoTimestamp(leftValue) || '';
    const normalizedRight = toIsoTimestamp(rightValue) || '';
    if (normalizedLeft === normalizedRight) {
      return 0;
    }
    return normalizedRight.localeCompare(normalizedLeft);
  };

  const sortConversationByRecentDesc = (left, right) => {
    const byLastMessageTime = compareIsoDesc(
      left?.last_message_time,
      right?.last_message_time
    );
    if (byLastMessageTime !== 0) {
      return byLastMessageTime;
    }
    const byUpdatedAt = compareIsoDesc(left?.updated_at, right?.updated_at);
    if (byUpdatedAt !== 0) {
      return byUpdatedAt;
    }
    return String(right?.conversation_id || '').localeCompare(
      String(left?.conversation_id || '')
    );
  };

  const sortHistoryByTimelineDesc = (left, right) => {
    const byMessageTime = compareIsoDesc(left?.message_time, right?.message_time);
    if (byMessageTime !== 0) {
      return byMessageTime;
    }
    const byCreatedAt = compareIsoDesc(
      left?.created_at || left?.ingested_at || left?.message_time,
      right?.created_at || right?.ingested_at || right?.message_time
    );
    if (byCreatedAt !== 0) {
      return byCreatedAt;
    }
    return String(right?.message_id || '').localeCompare(String(left?.message_id || ''));
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

    const existing = tenantSessionConversationsByConversationId.get(normalizedConversationId);
    if (existing) {
      throw createConversationDuplicateError();
    }

    const account = findTenantAccountByWechatId({
      tenantId: normalizedTenantId,
      accountWechatId: normalizedAccountWechatId
    });
    if (!account) {
      throw createConversationNotFoundError();
    }

    const conversationNameNormalized = normalizeNameForCompare(normalizedConversationName);
    const conversationUniqueKey = toConversationUniqueKey({
      tenantId: normalizedTenantId,
      accountWechatId: account.wechat_id,
      conversationType: normalizedConversationType,
      conversationName: normalizedConversationName
    });
    const existingConversationId = normalizeConversationId(
      conversationUniqueIndex.get(conversationUniqueKey)
    );
    if (existingConversationId) {
      const existingConversation = tenantSessionConversationsByConversationId.get(
        existingConversationId
      );
      if (
        existingConversation
        && normalizeTenantId(existingConversation.tenant_id) === normalizedTenantId
      ) {
        throw createConversationDuplicateError();
      }
      conversationUniqueIndex.delete(conversationUniqueKey);
    }

    const nowIso = new Date().toISOString();
    const nextRecord = {
      conversation_id: normalizedConversationId,
      tenant_id: normalizedTenantId,
      account_wechat_id: account.wechat_id,
      account_wechat_id_normalized: normalizeWechatId(account.wechat_id).toLowerCase(),
      conversation_type: normalizedConversationType,
      conversation_name: normalizedConversationName,
      conversation_name_normalized: conversationNameNormalized,
      last_message_time: toIsoTimestamp(lastMessageTime) || null,
      last_message_preview: normalizePreview(lastMessagePreview),
      external_updated_at: toIsoTimestamp(externalUpdatedAt) || null,
      sync_source: normalizeSourceName(syncSource, 'external'),
      created_at: nowIso,
      updated_at: nowIso
    };

    tenantSessionConversationsByConversationId.set(
      normalizedConversationId,
      nextRecord
    );
    toConversationIdSetByTenantWechatKey({
      tenantId: normalizedTenantId,
      accountWechatId: account.wechat_id
    }).add(normalizedConversationId);
    conversationUniqueIndex.set(conversationUniqueKey, normalizedConversationId);

    return cloneConversationRecord(nextRecord);
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
    const record = tenantSessionConversationsByConversationId.get(normalizedConversationId);
    if (!record || record.tenant_id !== normalizedTenantId) {
      return null;
    }
    return cloneConversationRecord(record);
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
    const conversationIdSet = toConversationIdSetByTenantWechatKey({
      tenantId: normalizedTenantId,
      accountWechatId: normalizedAccountWechatId
    });
    const keywordNormalized = normalizeNameForCompare(keyword);

    return [...conversationIdSet]
      .map((conversationId) =>
        cloneConversationRecord(tenantSessionConversationsByConversationId.get(conversationId))
      )
      .filter(Boolean)
      .filter((record) => record.tenant_id === normalizedTenantId)
      .filter((record) => {
        if (!keywordNormalized) {
          return true;
        }
        return normalizeNameForCompare(record.conversation_name).includes(keywordNormalized);
      })
      .sort((left, right) => sortConversationByRecentDesc(left, right));
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

    const conversation = tenantSessionConversationsByConversationId.get(normalizedConversationId);
    if (!conversation || conversation.tenant_id !== normalizedTenantId) {
      throw createConversationNotFoundError();
    }

    if (normalizedSourceEventId) {
      const sourceEventKey = toConversationSourceEventKey({
        tenantId: normalizedTenantId,
        conversationId: normalizedConversationId,
        sourceEventId: normalizedSourceEventId
      });
      const existingMessageId = tenantSessionHistoryMessageSourceEventIndex.get(sourceEventKey);
      if (existingMessageId) {
        const existingMessage = cloneHistoryMessageRecord(
          tenantSessionHistoryMessagesByMessageId.get(existingMessageId)
        );
        if (existingMessage) {
          return {
            ...existingMessage,
            idempotent_replay: true
          };
        }
      }
    }

    const nowIso = new Date().toISOString();
    const messageId = createMessageId();
    const nextRecord = {
      message_id: messageId,
      tenant_id: normalizedTenantId,
      conversation_id: normalizedConversationId,
      sender_name: normalizedSenderName,
      sender_name_normalized: senderNameNormalized || normalizeNameForCompare(senderName),
      is_self:
        isSelf === null || isSelf === undefined
          ? null
          : Number(isSelf) === 1
            ? 1
            : 0,
      message_type: normalizedMessageType,
      message_payload_json: cloneValue(messagePayloadJson),
      message_preview: normalizePreview(messagePreview),
      message_time: normalizedMessageTime,
      source_event_id: normalizedSourceEventId || null,
      ingest_source: normalizeSourceName(ingestSource, 'external'),
      ingested_at: nowIso,
      created_at: nowIso
    };

    tenantSessionHistoryMessagesByMessageId.set(messageId, nextRecord);
    toHistoryMessageIdListByConversationId({
      conversationId: normalizedConversationId
    }).push(messageId);
    if (normalizedSourceEventId) {
      tenantSessionHistoryMessageSourceEventIndex.set(
        toConversationSourceEventKey({
          tenantId: normalizedTenantId,
          conversationId: normalizedConversationId,
          sourceEventId: normalizedSourceEventId
        }),
        messageId
      );
    }

    patchConversationSummary({
      tenantId: normalizedTenantId,
      conversationId: normalizedConversationId,
      messageTime: normalizedMessageTime,
      messagePreview: nextRecord.message_preview,
      nowIso
    });

    return {
      ...cloneHistoryMessageRecord(nextRecord),
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
    const normalizedCursor = toIsoTimestamp(cursor);
    const normalizedCursorCreatedAt = toIsoTimestamp(cursorCreatedAt);
    const normalizedCursorMessageId = normalizeMessageId(cursorMessageId);
    const normalizedLimit = Math.max(1, Math.min(200, Number(limit) || 50));
    const messageIds = toHistoryMessageIdListByConversationId({
      conversationId: normalizedConversationId
    });

    return messageIds
      .map((messageId) =>
        cloneHistoryMessageRecord(tenantSessionHistoryMessagesByMessageId.get(messageId))
      )
      .filter(Boolean)
      .filter((record) => record.tenant_id === normalizedTenantId)
      .filter((record) => {
        if (!normalizedCursor) {
          return true;
        }
        const recordMessageTime = toIsoTimestamp(record.message_time);
        if (recordMessageTime < normalizedCursor) {
          return true;
        }
        if (recordMessageTime > normalizedCursor) {
          return false;
        }
        if (normalizedCursorCreatedAt) {
          const recordCreatedAt = toIsoTimestamp(
            record.created_at || record.ingested_at || record.message_time
          );
          if (recordCreatedAt < normalizedCursorCreatedAt) {
            return true;
          }
          if (recordCreatedAt > normalizedCursorCreatedAt) {
            return false;
          }
        }
        if (normalizedCursorMessageId) {
          return String(record.message_id || '') < normalizedCursorMessageId;
        }
        return false;
      })
      .sort((left, right) => sortHistoryByTimelineDesc(left, right))
      .slice(0, normalizedLimit);
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

    const conversation = tenantSessionConversationsByConversationId.get(normalizedConversationId);
    if (
      !conversation
      || conversation.tenant_id !== normalizedTenantId
      || normalizeWechatId(conversation.account_wechat_id).toLowerCase()
        !== normalizedAccountWechatId.toLowerCase()
    ) {
      throw createConversationNotFoundError();
    }

    if (normalizedClientMessageId) {
      const existingOutboundMessageId = tenantSessionOutboundMessageClientIndex.get(
        toOutboundClientKey({
          tenantId: normalizedTenantId,
          accountWechatId: normalizedAccountWechatId,
          clientMessageId: normalizedClientMessageId
        })
      );
      if (existingOutboundMessageId) {
        const existingRecord = cloneOutboundMessageRecord(
          tenantSessionOutboundMessagesByOutboundMessageId.get(existingOutboundMessageId)
        );
        if (existingRecord) {
          return {
            ...existingRecord,
            idempotent_replay: true
          };
        }
      }
    }

    const nowIso = new Date().toISOString();
    const outboundMessageId = createOutboundMessageId();
    const nextRecord = {
      outbound_message_id: outboundMessageId,
      tenant_id: normalizedTenantId,
      account_wechat_id: normalizedAccountWechatId,
      account_nickname: normalizedAccountNickname,
      conversation_id: normalizedConversationId,
      conversation_name: normalizedConversationName,
      message_type: normalizedMessageType,
      message_payload_json: cloneValue(messagePayloadJson),
      message_preview: normalizePreview(messagePreview),
      send_time: nowIso,
      enqueue_status: 'pending',
      provider_message_id: null,
      error_code: null,
      error_message: null,
      status_updated_at: null,
      client_message_id: normalizedClientMessageId || null,
      created_at: nowIso
    };

    tenantSessionOutboundMessagesByOutboundMessageId.set(
      outboundMessageId,
      nextRecord
    );
    toOutboundMessageIdSetByTenantId({ tenantId: normalizedTenantId }).add(outboundMessageId);
    if (normalizedClientMessageId) {
      tenantSessionOutboundMessageClientIndex.set(
        toOutboundClientKey({
          tenantId: normalizedTenantId,
          accountWechatId: normalizedAccountWechatId,
          clientMessageId: normalizedClientMessageId
        }),
        outboundMessageId
      );
    }

    patchConversationSummary({
      tenantId: normalizedTenantId,
      conversationId: normalizedConversationId,
      messageTime: nowIso,
      messagePreview: nextRecord.message_preview,
      nowIso
    });

    return {
      ...cloneOutboundMessageRecord(nextRecord),
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
    const normalizedStatuses = new Set(
      (Array.isArray(statuses) ? statuses : [])
        .map((status) => normalizeEnqueueStatus(status))
        .filter(Boolean)
    );
    const normalizedLimit = Math.max(1, Math.min(200, Number(limit) || 100));
    const normalizedAccountWechatIdSet = new Set(
      (Array.isArray(accountWechatIds) ? accountWechatIds : [])
        .map((wechatId) => normalizeWechatId(wechatId).toLowerCase())
        .filter(Boolean)
    );
    const outboundMessageIdSet = toOutboundMessageIdSetByTenantId({
      tenantId: normalizedTenantId
    });

    return [...outboundMessageIdSet]
      .map((outboundMessageId) =>
        cloneOutboundMessageRecord(
          tenantSessionOutboundMessagesByOutboundMessageId.get(outboundMessageId)
        )
      )
      .filter(Boolean)
      .filter((record) => record.tenant_id === normalizedTenantId)
      .filter((record) => {
        if (normalizedStatuses.size < 1) {
          return true;
        }
        return normalizedStatuses.has(normalizeEnqueueStatus(record.enqueue_status));
      })
      .filter((record) => {
        if (normalizedAccountWechatIdSet.size < 1) {
          return true;
        }
        return normalizedAccountWechatIdSet.has(
          normalizeWechatId(record.account_wechat_id).toLowerCase()
        );
      })
      .sort((left, right) => {
        const leftSendTime = toIsoTimestamp(left.send_time);
        const rightSendTime = toIsoTimestamp(right.send_time);
        if (leftSendTime !== rightSendTime) {
          return leftSendTime.localeCompare(rightSendTime);
        }
        return String(left.outbound_message_id || '').localeCompare(
          String(right.outbound_message_id || '')
        );
      })
      .slice(0, normalizedLimit);
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

    const current = tenantSessionOutboundMessagesByOutboundMessageId.get(
      normalizedOutboundMessageId
    );
    if (!current || current.tenant_id !== normalizedTenantId) {
      return null;
    }

    const nextRecord = {
      ...current,
      enqueue_status: normalizedEnqueueStatus,
      provider_message_id: normalizeOptionalLimitedText(
        providerMessageId,
        MAX_PROVIDER_MESSAGE_ID_LENGTH
      ),
      error_code: normalizeOptionalLimitedText(errorCode, MAX_ERROR_CODE_LENGTH),
      error_message: normalizeOptionalLimitedText(errorMessage, MAX_ERROR_MESSAGE_LENGTH),
      status_updated_at: toIsoTimestamp(statusUpdatedAt) || new Date().toISOString()
    };

    tenantSessionOutboundMessagesByOutboundMessageId.set(
      normalizedOutboundMessageId,
      nextRecord
    );
    return cloneOutboundMessageRecord(nextRecord);
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
    const current = tenantSessionOutboundMessagesByOutboundMessageId.get(
      normalizedOutboundMessageId
    );
    if (!current || current.tenant_id !== normalizedTenantId) {
      return null;
    }
    return cloneOutboundMessageRecord(current);
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
  createTenantMemoryAuthStoreSession
};
