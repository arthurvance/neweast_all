'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
  createInMemoryAuthStore
} = require('../src/shared-kernel/auth/store/create-in-memory-auth-store');

const createStore = () =>
  createInMemoryAuthStore({
    seedUsers: [
      {
        id: 'tenant-session-user-owner',
        phone: '13800003001',
        passwordHash: 'seed-password-hash-tenant-session-user-owner',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-session-a',
            tenantName: 'Tenant Session A',
            membershipId: 'membership-session-owner-1',
            status: 'active',
            displayName: '会话负责人A'
          }
        ]
      },
      {
        id: 'tenant-session-user-assist',
        phone: '13800003002',
        passwordHash: 'seed-password-hash-tenant-session-user-assist',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-session-a',
            tenantName: 'Tenant Session A',
            membershipId: 'membership-session-assist-1',
            status: 'active',
            displayName: '会话协管A'
          }
        ]
      }
    ]
  });

test('memory tenant session store supports conversation/history/outbound lifecycle and idempotency', async () => {
  const store = createStore();

  const account = await store.createTenantAccount({
    tenantId: 'tenant-session-a',
    wechatId: 'wx_session_account_1',
    nickname: '会话账号A',
    ownerMembershipId: 'membership-session-owner-1',
    assistantMembershipIds: ['membership-session-assist-1'],
    operatorUserId: 'tenant-session-user-owner',
    operatorName: '会话负责人A'
  });

  const conversation = await store.createTenantSessionConversation({
    tenantId: 'tenant-session-a',
    accountWechatId: account.wechat_id,
    conversationId: 'conv_session_001',
    conversationType: 'direct',
    conversationName: '张老师',
    syncSource: 'external'
  });

  assert.equal(conversation.conversation_id, 'conv_session_001');
  assert.equal(conversation.account_wechat_id, account.wechat_id);

  await assert.rejects(
    () =>
      store.createTenantSessionConversation({
        tenantId: 'tenant-session-a',
        accountWechatId: account.wechat_id,
        conversationId: 'conv_session_001',
        conversationType: 'direct',
        conversationName: '张老师'
      }),
    (error) => error && error.code === 'ERR_TENANT_SESSION_CONVERSATION_DUPLICATE'
  );

  const historyCreated = await store.createTenantSessionHistoryMessage({
    tenantId: 'tenant-session-a',
    conversationId: 'conv_session_001',
    senderName: '会话账号A',
    senderNameNormalized: '会话账号a',
    isSelf: 1,
    messageType: 'text',
    messagePayloadJson: {
      text: '第一条历史消息'
    },
    messagePreview: '第一条历史消息',
    messageTime: '2026-02-27T08:00:00.000Z',
    sourceEventId: 'src_event_001',
    ingestSource: 'external'
  });

  assert.equal(historyCreated.idempotent_replay, false);
  assert.equal(historyCreated.is_self, 1);

  const historyReplay = await store.createTenantSessionHistoryMessage({
    tenantId: 'tenant-session-a',
    conversationId: 'conv_session_001',
    senderName: '会话账号A',
    senderNameNormalized: '会话账号a',
    isSelf: 1,
    messageType: 'text',
    messagePayloadJson: {
      text: '第一条历史消息'
    },
    messagePreview: '第一条历史消息',
    messageTime: '2026-02-27T08:00:00.000Z',
    sourceEventId: 'src_event_001',
    ingestSource: 'external'
  });

  assert.equal(historyReplay.idempotent_replay, true);
  assert.equal(historyReplay.message_id, historyCreated.message_id);

  const conversationList = await store.listTenantSessionConversationsByAccountWechatId({
    tenantId: 'tenant-session-a',
    accountWechatId: account.wechat_id,
    keyword: '张'
  });

  assert.equal(conversationList.length, 1);
  assert.equal(conversationList[0].conversation_id, 'conv_session_001');
  assert.equal(conversationList[0].last_message_preview, '第一条历史消息');

  const historyList = await store.listTenantSessionHistoryMessagesByConversationId({
    tenantId: 'tenant-session-a',
    conversationId: 'conv_session_001',
    limit: 20
  });

  assert.equal(historyList.length, 1);
  assert.equal(historyList[0].message_id, historyCreated.message_id);
  assert.equal(historyList[0].is_self, 1);

  const outboundCreated = await store.createTenantSessionOutboundMessage({
    tenantId: 'tenant-session-a',
    accountWechatId: account.wechat_id,
    accountNickname: account.nickname,
    conversationId: 'conv_session_001',
    conversationName: '张老师',
    messageType: 'text',
    messagePayloadJson: {
      text: '外发消息A'
    },
    messagePreview: '外发消息A',
    clientMessageId: 'client_msg_001'
  });

  assert.equal(outboundCreated.enqueue_status, 'pending');
  assert.equal(outboundCreated.idempotent_replay, false);

  const outboundReplay = await store.createTenantSessionOutboundMessage({
    tenantId: 'tenant-session-a',
    accountWechatId: account.wechat_id,
    accountNickname: account.nickname,
    conversationId: 'conv_session_001',
    conversationName: '张老师',
    messageType: 'text',
    messagePayloadJson: {
      text: '外发消息A'
    },
    messagePreview: '外发消息A',
    clientMessageId: 'client_msg_001'
  });

  assert.equal(outboundReplay.idempotent_replay, true);
  assert.equal(outboundReplay.outbound_message_id, outboundCreated.outbound_message_id);

  const pendingForPull = await store.listTenantSessionOutboundMessagesForPull({
    tenantId: 'tenant-session-a',
    statuses: ['pending'],
    limit: 50,
    accountWechatIds: [account.wechat_id]
  });

  assert.equal(pendingForPull.length, 1);
  assert.equal(pendingForPull[0].outbound_message_id, outboundCreated.outbound_message_id);

  const outboundUpdated = await store.updateTenantSessionOutboundMessageStatus({
    tenantId: 'tenant-session-a',
    outboundMessageId: outboundCreated.outbound_message_id,
    enqueueStatus: 'sent',
    providerMessageId: 'provider_msg_001',
    errorCode: null,
    errorMessage: null,
    statusUpdatedAt: '2026-02-27T08:10:00.000Z'
  });

  assert.equal(outboundUpdated.enqueue_status, 'sent');
  assert.equal(outboundUpdated.provider_message_id, 'provider_msg_001');

  const pendingAfterSent = await store.listTenantSessionOutboundMessagesForPull({
    tenantId: 'tenant-session-a',
    statuses: ['pending'],
    limit: 50,
    accountWechatIds: [account.wechat_id]
  });

  assert.deepEqual(pendingAfterSent, []);
});

test('memory tenant session store enforces unique conversation identity per tenant/account/type/name', async () => {
  const store = createStore();

  const account = await store.createTenantAccount({
    tenantId: 'tenant-session-a',
    wechatId: 'wx_session_account_unique_1',
    nickname: '会话账号Unique',
    ownerMembershipId: 'membership-session-owner-1',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-session-user-owner',
    operatorName: '会话负责人A'
  });

  await store.createTenantSessionConversation({
    tenantId: 'tenant-session-a',
    accountWechatId: account.wechat_id,
    conversationId: 'conv_session_unique_001',
    conversationType: 'direct',
    conversationName: 'TutorA',
    syncSource: 'external'
  });

  await assert.rejects(
    () =>
      store.createTenantSessionConversation({
        tenantId: 'tenant-session-a',
        accountWechatId: account.wechat_id,
        conversationId: 'conv_session_unique_002',
        conversationType: 'direct',
        conversationName: 'tutora',
        syncSource: 'external'
      }),
    (error) => error && error.code === 'ERR_TENANT_SESSION_CONVERSATION_DUPLICATE'
  );

  const groupConversation = await store.createTenantSessionConversation({
    tenantId: 'tenant-session-a',
    accountWechatId: account.wechat_id,
    conversationId: 'conv_session_unique_003',
    conversationType: 'group',
    conversationName: 'TutorA',
    syncSource: 'external'
  });

  assert.equal(groupConversation.conversation_id, 'conv_session_unique_003');
});
