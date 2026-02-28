'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createTenantMysqlAuthStoreSession
} = require('../src/domains/tenant/auth/store/mysql/tenant-mysql-auth-store-session');

const MYSQL_TIMESTAMP_PATTERN = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}$/;

const normalizeStoreIsoTimestamp = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const parsed = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return '';
  }
  return parsed.toISOString();
};

const formatAuditDateTimeForMySql = (value) => {
  const normalizedIsoTimestamp = normalizeStoreIsoTimestamp(value);
  if (!normalizedIsoTimestamp) {
    return '';
  }
  return `${normalizedIsoTimestamp.slice(0, 19).replace('T', ' ')}.${normalizedIsoTimestamp.slice(20, 23)}`;
};

const createStore = ({ dbClient, isDuplicateEntryError = () => false }) =>
  createTenantMysqlAuthStoreSession({
    CONTROL_CHAR_PATTERN: /[\u0000-\u001F\u007F]/,
    dbClient,
    executeWithDeadlockRetry: ({ execute }) => execute(),
    formatAuditDateTimeForMySql,
    isDuplicateEntryError,
    normalizeStoreIsoTimestamp,
    randomUUID: () => '12345678-1234-1234-1234-1234567890ab'
  });

test('mysql tenant session store creates conversation and history records with timestamp precision', async () => {
  let insertedConversationParams = null;
  let insertedHistoryParams = null;
  let updatedConversationSummaryParams = null;

  const store = createStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();

        if (normalizedSql.includes('INSERT INTO tenant_session_conversations')) {
          insertedConversationParams = params;
          return { affectedRows: 1 };
        }

        if (
          normalizedSql.includes('FROM tenant_session_conversations')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND conversation_id = ?')
          && !normalizedSql.includes('UPDATE tenant_session_conversations')
        ) {
          return [
            {
              conversation_id: params[1],
              tenant_id: params[0],
              account_wechat_id: 'wx_session_mysql_1',
              account_wechat_id_normalized: 'wx_session_mysql_1',
              conversation_type: 'direct',
              conversation_name: '李老师',
              conversation_name_normalized: '李老师',
              last_message_time: '2026-02-27T09:00:00.000Z',
              last_message_preview: '会话同步摘要',
              external_updated_at: '2026-02-27T09:00:00.000Z',
              sync_source: 'external',
              created_at: '2026-02-27T09:00:00.000Z',
              updated_at: '2026-02-27T09:00:00.000Z'
            }
          ];
        }

        if (
          normalizedSql.includes('FROM tenant_session_history_messages')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND conversation_id = ?')
          && normalizedSql.includes('AND source_event_id = ?')
        ) {
          return [];
        }

        if (normalizedSql.includes('INSERT INTO tenant_session_history_messages')) {
          insertedHistoryParams = params;
          return { affectedRows: 1 };
        }

        if (normalizedSql.startsWith('UPDATE tenant_session_conversations')) {
          updatedConversationSummaryParams = params;
          return { affectedRows: 1 };
        }

        if (
          normalizedSql.includes('FROM tenant_session_history_messages')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND message_id = ?')
        ) {
          return [
            {
              message_id: params[1],
              tenant_id: params[0],
              conversation_id: 'conv_mysql_001',
              sender_name: '李老师',
              sender_name_normalized: '李老师',
              is_self: 0,
              message_type: 'text',
              message_payload_json: { text: '历史消息A' },
              message_preview: '历史消息A',
              message_time: '2026-02-27T09:10:00.000Z',
              source_event_id: 'source_event_mysql_001',
              ingest_source: 'external',
              ingested_at: '2026-02-27T09:10:00.000Z',
              created_at: '2026-02-27T09:10:00.000Z'
            }
          ];
        }

        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      }
    }
  });

  const conversation = await store.createTenantSessionConversation({
    tenantId: 'tenant_mysql_a',
    accountWechatId: 'wx_session_mysql_1',
    conversationId: 'conv_mysql_001',
    conversationType: 'direct',
    conversationName: '李老师',
    lastMessageTime: '2026-02-27T09:00:00.000Z',
    lastMessagePreview: '会话同步摘要',
    externalUpdatedAt: '2026-02-27T09:00:00.000Z',
    syncSource: 'external'
  });

  assert.equal(conversation.conversation_id, 'conv_mysql_001');
  assert.ok(Array.isArray(insertedConversationParams));
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(insertedConversationParams[11]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(insertedConversationParams[12]), true);

  const history = await store.createTenantSessionHistoryMessage({
    tenantId: 'tenant_mysql_a',
    conversationId: 'conv_mysql_001',
    senderName: '李老师',
    senderNameNormalized: '李老师',
    isSelf: 0,
    messageType: 'text',
    messagePayloadJson: {
      text: '历史消息A'
    },
    messagePreview: '历史消息A',
    messageTime: '2026-02-27T09:10:00.000Z',
    sourceEventId: 'source_event_mysql_001',
    ingestSource: 'external'
  });

  assert.equal(history.idempotent_replay, false);
  assert.equal(history.message_type, 'text');
  assert.ok(Array.isArray(insertedHistoryParams));
  assert.equal(insertedHistoryParams[0].startsWith('hmsg_'), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(insertedHistoryParams[12]), true);
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(insertedHistoryParams[13]), true);
  assert.ok(Array.isArray(updatedConversationSummaryParams));
  assert.equal(updatedConversationSummaryParams[0], '2026-02-27 09:10:00.000');
});

test('mysql tenant session store replays outbound message on duplicate client_message_id', async () => {
  const duplicateError = new Error("Duplicate entry 'dup' for key 'uk_tenant_session_outbound_messages_client'");
  duplicateError.code = 'ER_DUP_ENTRY';

  const store = createStore({
    isDuplicateEntryError: (error) => error && error.code === 'ER_DUP_ENTRY',
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();

        if (
          normalizedSql.includes('FROM tenant_session_conversations')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND conversation_id = ?')
        ) {
          return [
            {
              conversation_id: 'conv_mysql_002',
              tenant_id: 'tenant_mysql_a',
              account_wechat_id: 'wx_session_mysql_2',
              account_wechat_id_normalized: 'wx_session_mysql_2',
              conversation_type: 'direct',
              conversation_name: '王老师',
              conversation_name_normalized: '王老师',
              last_message_time: null,
              last_message_preview: null,
              external_updated_at: null,
              sync_source: 'external',
              created_at: '2026-02-27T09:00:00.000Z',
              updated_at: '2026-02-27T09:00:00.000Z'
            }
          ];
        }

        if (
          normalizedSql.includes('FROM tenant_session_outbound_messages')
          && normalizedSql.includes('client_message_id = ?')
        ) {
          return [
            {
              outbound_message_id: 'som_existing_001',
              tenant_id: 'tenant_mysql_a',
              account_wechat_id: 'wx_session_mysql_2',
              account_nickname: '会话账号B',
              conversation_id: 'conv_mysql_002',
              conversation_name: '王老师',
              message_type: 'text',
              message_payload_json: { text: '外发消息B' },
              message_preview: '外发消息B',
              send_time: '2026-02-27T09:20:00.000Z',
              enqueue_status: 'pending',
              provider_message_id: null,
              error_code: null,
              error_message: null,
              status_updated_at: null,
              client_message_id: 'client_msg_mysql_001',
              created_at: '2026-02-27T09:20:00.000Z'
            }
          ];
        }

        if (normalizedSql.includes('INSERT INTO tenant_session_outbound_messages')) {
          throw duplicateError;
        }

        if (normalizedSql.startsWith('UPDATE tenant_session_conversations')) {
          return { affectedRows: 1 };
        }

        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      }
    }
  });

  const replayed = await store.createTenantSessionOutboundMessage({
    tenantId: 'tenant_mysql_a',
    accountWechatId: 'wx_session_mysql_2',
    accountNickname: '会话账号B',
    conversationId: 'conv_mysql_002',
    conversationName: '王老师',
    messageType: 'text',
    messagePayloadJson: {
      text: '外发消息B'
    },
    messagePreview: '外发消息B',
    clientMessageId: 'client_msg_mysql_001'
  });

  assert.equal(replayed.idempotent_replay, true);
  assert.equal(replayed.outbound_message_id, 'som_existing_001');
});

test('mysql tenant session store lists outbound pull candidates and updates status', async () => {
  let updateStatusParams = null;

  const store = createStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();

        if (
          normalizedSql.includes('FROM tenant_session_outbound_messages')
          && normalizedSql.includes('enqueue_status IN')
          && normalizedSql.includes('account_wechat_id IN')
        ) {
          return [
            {
              outbound_message_id: 'som_pull_001',
              tenant_id: 'tenant_mysql_a',
              account_wechat_id: 'wx_session_mysql_3',
              account_nickname: '会话账号C',
              conversation_id: 'conv_mysql_003',
              conversation_name: '赵老师',
              message_type: 'text',
              message_payload_json: { text: '待外发' },
              message_preview: '待外发',
              send_time: '2026-02-27T09:30:00.000Z',
              enqueue_status: 'pending',
              provider_message_id: null,
              error_code: null,
              error_message: null,
              status_updated_at: null,
              client_message_id: 'client_msg_mysql_003',
              created_at: '2026-02-27T09:30:00.000Z'
            }
          ];
        }

        if (normalizedSql.startsWith('UPDATE tenant_session_outbound_messages')) {
          updateStatusParams = params;
          return { affectedRows: 1 };
        }

        if (
          normalizedSql.includes('FROM tenant_session_outbound_messages')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND outbound_message_id = ?')
          && !normalizedSql.includes('enqueue_status IN')
        ) {
          return [
            {
              outbound_message_id: 'som_pull_001',
              tenant_id: 'tenant_mysql_a',
              account_wechat_id: 'wx_session_mysql_3',
              account_nickname: '会话账号C',
              conversation_id: 'conv_mysql_003',
              conversation_name: '赵老师',
              message_type: 'text',
              message_payload_json: { text: '待外发' },
              message_preview: '待外发',
              send_time: '2026-02-27T09:30:00.000Z',
              enqueue_status: 'sent',
              provider_message_id: 'provider_msg_003',
              error_code: null,
              error_message: null,
              status_updated_at: '2026-02-27T09:40:00.000Z',
              client_message_id: 'client_msg_mysql_003',
              created_at: '2026-02-27T09:30:00.000Z'
            }
          ];
        }

        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      }
    }
  });

  const pulled = await store.listTenantSessionOutboundMessagesForPull({
    tenantId: 'tenant_mysql_a',
    statuses: ['pending'],
    limit: 20,
    accountWechatIds: ['wx_session_mysql_3']
  });

  assert.equal(pulled.length, 1);
  assert.equal(pulled[0].outbound_message_id, 'som_pull_001');

  const updated = await store.updateTenantSessionOutboundMessageStatus({
    tenantId: 'tenant_mysql_a',
    outboundMessageId: 'som_pull_001',
    enqueueStatus: 'sent',
    providerMessageId: 'provider_msg_003',
    errorCode: null,
    errorMessage: null,
    statusUpdatedAt: '2026-02-27T09:40:00.000Z'
  });

  assert.equal(updated.enqueue_status, 'sent');
  assert.equal(updated.provider_message_id, 'provider_msg_003');
  assert.ok(Array.isArray(updateStatusParams));
  assert.equal(updateStatusParams[0], 'sent');
  assert.equal(MYSQL_TIMESTAMP_PATTERN.test(updateStatusParams[4]), true);
});

test('mysql tenant session history ingest retries conversation summary compensation on source_event replay', async () => {
  let storedHistoryMessage = null;
  let summaryUpdateAttempts = 0;

  const store = createStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();

        if (
          normalizedSql.includes('FROM tenant_session_conversations')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND conversation_id = ?')
          && !normalizedSql.includes('UPDATE tenant_session_conversations')
        ) {
          return [
            {
              conversation_id: 'conv_mysql_compensate_001',
              tenant_id: 'tenant_mysql_a',
              account_wechat_id: 'wx_session_mysql_compensate_1',
              account_wechat_id_normalized: 'wx_session_mysql_compensate_1',
              conversation_type: 'direct',
              conversation_name: '补偿老师',
              conversation_name_normalized: '补偿老师',
              last_message_time: null,
              last_message_preview: null,
              external_updated_at: null,
              sync_source: 'external',
              created_at: '2026-02-27T09:00:00.000Z',
              updated_at: '2026-02-27T09:00:00.000Z'
            }
          ];
        }

        if (
          normalizedSql.includes('FROM tenant_session_history_messages')
          && normalizedSql.includes('AND source_event_id = ?')
        ) {
          return storedHistoryMessage ? [storedHistoryMessage] : [];
        }

        if (normalizedSql.includes('INSERT INTO tenant_session_history_messages')) {
          storedHistoryMessage = {
            message_id: params[0],
            tenant_id: params[1],
            conversation_id: params[2],
            sender_name: params[3],
            sender_name_normalized: params[4],
            is_self: params[5],
            message_type: params[6],
            message_payload_json: JSON.parse(params[7]),
            message_preview: params[8],
            message_time: '2026-02-27T09:10:00.000Z',
            source_event_id: params[10],
            ingest_source: params[11],
            ingested_at: '2026-02-27T09:10:00.000Z',
            created_at: '2026-02-27T09:10:00.000Z'
          };
          return { affectedRows: 1 };
        }

        if (normalizedSql.startsWith('UPDATE tenant_session_conversations')) {
          summaryUpdateAttempts += 1;
          if (summaryUpdateAttempts === 1) {
            throw new Error('summary update failed once');
          }
          return { affectedRows: 1 };
        }

        if (
          normalizedSql.includes('FROM tenant_session_history_messages')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND message_id = ?')
        ) {
          if (storedHistoryMessage && params[1] === storedHistoryMessage.message_id) {
            return [storedHistoryMessage];
          }
          return [];
        }

        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      }
    }
  });

  await assert.rejects(
    () =>
      store.createTenantSessionHistoryMessage({
        tenantId: 'tenant_mysql_a',
        conversationId: 'conv_mysql_compensate_001',
        senderName: '补偿老师',
        senderNameNormalized: '补偿老师',
        isSelf: 0,
        messageType: 'text',
        messagePayloadJson: {
          text: '补偿消息'
        },
        messagePreview: '补偿消息',
        messageTime: '2026-02-27T09:10:00.000Z',
        sourceEventId: 'source_event_compensate_001',
        ingestSource: 'external'
      }),
    /summary update failed once/
  );

  const replayed = await store.createTenantSessionHistoryMessage({
    tenantId: 'tenant_mysql_a',
    conversationId: 'conv_mysql_compensate_001',
    senderName: '补偿老师',
    senderNameNormalized: '补偿老师',
    isSelf: 0,
    messageType: 'text',
    messagePayloadJson: {
      text: '补偿消息'
    },
    messagePreview: '补偿消息',
    messageTime: '2026-02-27T09:10:00.000Z',
    sourceEventId: 'source_event_compensate_001',
    ingestSource: 'external'
  });

  assert.equal(replayed.idempotent_replay, true);
  assert.equal(replayed.source_event_id, 'source_event_compensate_001');
  assert.equal(summaryUpdateAttempts, 2);
});

test('mysql tenant session outbound create retries conversation summary compensation on client_message replay', async () => {
  let storedOutboundMessage = null;
  let summaryUpdateAttempts = 0;

  const store = createStore({
    dbClient: {
      query: async (sql, params = []) => {
        const normalizedSql = String(sql).replace(/\s+/g, ' ').trim();

        if (
          normalizedSql.includes('FROM tenant_session_conversations')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND conversation_id = ?')
          && !normalizedSql.includes('UPDATE tenant_session_conversations')
        ) {
          return [
            {
              conversation_id: 'conv_mysql_compensate_002',
              tenant_id: 'tenant_mysql_a',
              account_wechat_id: 'wx_session_mysql_compensate_2',
              account_wechat_id_normalized: 'wx_session_mysql_compensate_2',
              conversation_type: 'direct',
              conversation_name: '补偿发送老师',
              conversation_name_normalized: '补偿发送老师',
              last_message_time: null,
              last_message_preview: null,
              external_updated_at: null,
              sync_source: 'external',
              created_at: '2026-02-27T09:00:00.000Z',
              updated_at: '2026-02-27T09:00:00.000Z'
            }
          ];
        }

        if (
          normalizedSql.includes('FROM tenant_session_outbound_messages')
          && normalizedSql.includes('client_message_id = ?')
        ) {
          return storedOutboundMessage ? [storedOutboundMessage] : [];
        }

        if (normalizedSql.includes('INSERT INTO tenant_session_outbound_messages')) {
          storedOutboundMessage = {
            outbound_message_id: params[0],
            tenant_id: params[1],
            account_wechat_id: params[2],
            account_nickname: params[3],
            conversation_id: params[4],
            conversation_name: params[5],
            message_type: params[6],
            message_payload_json: JSON.parse(params[7]),
            message_preview: params[8],
            send_time: '2026-02-27T09:20:00.000Z',
            enqueue_status: params[10],
            provider_message_id: params[11],
            error_code: params[12],
            error_message: params[13],
            status_updated_at: params[14],
            client_message_id: params[15],
            created_at: '2026-02-27T09:20:00.000Z'
          };
          return { affectedRows: 1 };
        }

        if (normalizedSql.startsWith('UPDATE tenant_session_conversations')) {
          summaryUpdateAttempts += 1;
          if (summaryUpdateAttempts === 1) {
            throw new Error('summary update failed once');
          }
          return { affectedRows: 1 };
        }

        if (
          normalizedSql.includes('FROM tenant_session_outbound_messages')
          && normalizedSql.includes('WHERE tenant_id = ?')
          && normalizedSql.includes('AND outbound_message_id = ?')
          && !normalizedSql.includes('client_message_id = ?')
        ) {
          if (storedOutboundMessage && params[1] === storedOutboundMessage.outbound_message_id) {
            return [storedOutboundMessage];
          }
          return [];
        }

        assert.fail(`unexpected dbClient.query SQL: ${normalizedSql}`);
        return [];
      }
    }
  });

  await assert.rejects(
    () =>
      store.createTenantSessionOutboundMessage({
        tenantId: 'tenant_mysql_a',
        accountWechatId: 'wx_session_mysql_compensate_2',
        accountNickname: '会话账号补偿',
        conversationId: 'conv_mysql_compensate_002',
        conversationName: '补偿发送老师',
        messageType: 'text',
        messagePayloadJson: {
          text: '补偿外发消息'
        },
        messagePreview: '补偿外发消息',
        clientMessageId: 'client_msg_compensate_001'
      }),
    /summary update failed once/
  );

  const replayed = await store.createTenantSessionOutboundMessage({
    tenantId: 'tenant_mysql_a',
    accountWechatId: 'wx_session_mysql_compensate_2',
    accountNickname: '会话账号补偿',
    conversationId: 'conv_mysql_compensate_002',
    conversationName: '补偿发送老师',
    messageType: 'text',
    messagePayloadJson: {
      text: '补偿外发消息'
    },
    messagePreview: '补偿外发消息',
    clientMessageId: 'client_msg_compensate_001'
  });

  assert.equal(replayed.idempotent_replay, true);
  assert.equal(replayed.client_message_id, 'client_msg_compensate_001');
  assert.equal(summaryUpdateAttempts, 2);
});
