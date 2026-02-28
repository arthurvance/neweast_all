'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { createRouteHandlers } = require('../src/http-routes');
const { dispatchApiRoute } = require('../src/server');
const { readConfig } = require('../src/config/env');
const {
  createInMemoryAuthStore
} = require('../src/shared-kernel/auth/store/create-in-memory-auth-store');

const config = readConfig({ ALLOW_MOCK_BACKENDS: 'true' });
const dependencyProbe = async () => ({
  db: { ok: true },
  redis: { ok: true }
});

const defaultTenantPermissionContext = Object.freeze({
  can_view_session_management: true,
  can_operate_session_management: true,
  can_view_session_scope_my: true,
  can_view_session_scope_assist: true,
  can_view_session_scope_all: true
});

const createAuthStore = () =>
  createInMemoryAuthStore({
    seedUsers: [
      {
        id: 'tenant-session-operator',
        phone: '13800003101',
        passwordHash: 'seed-password-hash-tenant-session-operator',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-session-a',
            tenantName: 'Tenant Session A',
            membershipId: 'membership-session-owner',
            status: 'active',
            displayName: '会话负责人'
          }
        ]
      },
      {
        id: 'tenant-session-assistant',
        phone: '13800003102',
        passwordHash: 'seed-password-hash-tenant-session-assistant',
        status: 'active',
        domains: ['tenant'],
        tenants: [
          {
            tenantId: 'tenant-session-a',
            tenantName: 'Tenant Session A',
            membershipId: 'membership-session-assistant',
            status: 'active',
            displayName: '会话协管'
          }
        ]
      }
    ]
  });

const createHarness = async ({
  permissionContext = defaultTenantPermissionContext
} = {}) => {
  const authorizeCalls = [];
  const authStore = createAuthStore();

  const account = await authStore.createTenantAccount({
    tenantId: 'tenant-session-a',
    wechatId: 'wx_session_api_1',
    nickname: '会话账号API',
    ownerMembershipId: 'membership-session-owner',
    assistantMembershipIds: ['membership-session-assistant'],
    operatorUserId: 'tenant-session-operator',
    operatorName: '会话负责人'
  });

  const authService = {
    authorizeRoute: async (payload) => {
      authorizeCalls.push(payload);
      return {
        user_id: 'tenant-session-operator',
        session_id: 'tenant-session-token',
        entry_domain: 'tenant',
        active_tenant_id: 'tenant-session-a',
        tenant_permission_context: {
          ...permissionContext
        }
      };
    },
    recordIdempotencyEvent: async () => {},
    _internals: {
      authStore,
      auditTrail: []
    }
  };

  const handlers = createRouteHandlers(config, {
    dependencyProbe,
    authService
  });

  return {
    handlers,
    authStore,
    authorizeCalls,
    account
  };
};

const seedConversation = async ({
  authStore,
  accountWechatId,
  conversationId = 'conv_api_001',
  conversationName = '王老师'
}) =>
  authStore.createTenantSessionConversation({
    tenantId: 'tenant-session-a',
    accountWechatId,
    conversationId,
    conversationType: 'direct',
    conversationName,
    syncSource: 'external'
  });

test('POST /tenant/sessions/conversations/ingest and GET /tenant/sessions/chats work with tenant scope checks', async () => {
  const harness = await createHarness();

  const ingestRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/conversations/ingest',
    method: 'POST',
    requestId: 'req-tenant-session-conversation-ingest',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_wechat_id: harness.account.wechat_id,
      conversation_id: 'conv_api_001',
      conversation_type: 'direct',
      conversation_name: '王老师'
    },
    handlers: harness.handlers
  });

  assert.equal(ingestRoute.status, 200);
  const ingestPayload = JSON.parse(ingestRoute.body);
  assert.equal(ingestPayload.conversation_id, 'conv_api_001');
  assert.equal(ingestPayload.account_wechat_id, harness.account.wechat_id);
  assert.equal(
    harness.authorizeCalls.at(-1).permissionCode,
    'tenant.session_management.operate'
  );

  const listRoute = await dispatchApiRoute({
    pathname: `/tenant/sessions/chats?scope=my&account_wechat_id=${encodeURIComponent(harness.account.wechat_id)}`,
    method: 'GET',
    requestId: 'req-tenant-session-chat-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(listRoute.status, 200);
  const listPayload = JSON.parse(listRoute.body);
  assert.equal(listPayload.total, 1);
  assert.equal(listPayload.chats[0].conversation_id, 'conv_api_001');
  assert.equal(
    harness.authorizeCalls.at(-1).permissionCode,
    'tenant.session_management.view'
  );
});

test('POST /tenant/sessions/history/ingest computes is_self and supports source_event_id idempotency', async () => {
  const harness = await createHarness();
  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: harness.account.wechat_id,
    conversationId: 'conv_api_002',
    conversationName: '李老师'
  });

  const ingestHistoryRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/history/ingest',
    method: 'POST',
    requestId: 'req-tenant-session-history-ingest-1',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      conversation_id: 'conv_api_002',
      sender_name: harness.account.nickname,
      message_type: 'text',
      message_payload_json: {
        text: '历史消息测试'
      },
      message_time: '2026-02-27T10:00:00.000Z',
      source_event_id: 'source_event_api_001'
    },
    handlers: harness.handlers
  });

  assert.equal(ingestHistoryRoute.status, 200);
  const historyPayload = JSON.parse(ingestHistoryRoute.body);
  assert.equal(historyPayload.is_self, 1);
  assert.equal(historyPayload.idempotent_replay, false);

  const replayRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/history/ingest',
    method: 'POST',
    requestId: 'req-tenant-session-history-ingest-2',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      conversation_id: 'conv_api_002',
      sender_name: harness.account.nickname,
      message_type: 'text',
      message_payload_json: {
        text: '历史消息测试'
      },
      message_time: '2026-02-27T10:00:00.000Z',
      source_event_id: 'source_event_api_001'
    },
    handlers: harness.handlers
  });

  assert.equal(replayRoute.status, 200);
  const replayPayload = JSON.parse(replayRoute.body);
  assert.equal(replayPayload.idempotent_replay, true);
  assert.equal(replayPayload.message_id, historyPayload.message_id);

  const listMessagesRoute = await dispatchApiRoute({
    pathname: `/tenant/sessions/chats/conv_api_002/messages?scope=my&account_wechat_id=${encodeURIComponent(harness.account.wechat_id)}&limit=20`,
    method: 'GET',
    requestId: 'req-tenant-session-message-list',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(listMessagesRoute.status, 200);
  const messageListPayload = JSON.parse(listMessagesRoute.body);
  assert.equal(messageListPayload.messages.length, 1);
  assert.equal(messageListPayload.messages[0].is_self, 1);
});

test('GET /tenant/sessions/chats/:conversation_id/messages paginates same-second messages without gaps', async () => {
  const harness = await createHarness();
  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: harness.account.wechat_id,
    conversationId: 'conv_api_cursor_001',
    conversationName: '同秒分页测试'
  });

  const sameMessageTime = '2026-02-27T11:00:00.000Z';
  for (const suffix of ['001', '002', '003']) {
    await harness.authStore.createTenantSessionHistoryMessage({
      tenantId: 'tenant-session-a',
      conversationId: 'conv_api_cursor_001',
      senderName: `客户${suffix}`,
      senderNameNormalized: `客户${suffix}`,
      isSelf: 0,
      messageType: 'text',
      messagePayloadJson: {
        text: `同秒消息-${suffix}`
      },
      messagePreview: `同秒消息-${suffix}`,
      messageTime: sameMessageTime,
      sourceEventId: `source_event_cursor_${suffix}`,
      ingestSource: 'external'
    });
    await new Promise((resolve) => setTimeout(resolve, 2));
  }

  const firstPageRoute = await dispatchApiRoute({
    pathname: `/tenant/sessions/chats/conv_api_cursor_001/messages?scope=my&account_wechat_id=${encodeURIComponent(harness.account.wechat_id)}&limit=2`,
    method: 'GET',
    requestId: 'req-tenant-session-message-list-page-1',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(firstPageRoute.status, 200);
  const firstPagePayload = JSON.parse(firstPageRoute.body);
  assert.equal(firstPagePayload.messages.length, 2);
  assert.equal(String(firstPagePayload.next_cursor || '').startsWith('msg_v1.'), true);

  const secondPageRoute = await dispatchApiRoute({
    pathname: `/tenant/sessions/chats/conv_api_cursor_001/messages?scope=my&account_wechat_id=${encodeURIComponent(harness.account.wechat_id)}&limit=2&cursor=${encodeURIComponent(firstPagePayload.next_cursor)}`,
    method: 'GET',
    requestId: 'req-tenant-session-message-list-page-2',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(secondPageRoute.status, 200);
  const secondPagePayload = JSON.parse(secondPageRoute.body);
  assert.equal(secondPagePayload.messages.length, 1);

  const allMessageIds = [
    ...firstPagePayload.messages,
    ...secondPagePayload.messages
  ].map((item) => item.message_id);
  assert.equal(new Set(allMessageIds).size, 3);
});

test('POST /tenant/sessions/messages supports client_message_id idempotency and outbound pull/status flow', async () => {
  const harness = await createHarness();
  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: harness.account.wechat_id,
    conversationId: 'conv_api_003',
    conversationName: '赵老师'
  });

  const createMessageRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/messages',
    method: 'POST',
    requestId: 'req-tenant-session-message-create-1',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_wechat_id: harness.account.wechat_id,
      account_nickname: harness.account.nickname,
      conversation_id: 'conv_api_003',
      conversation_name: '赵老师',
      message_type: 'text',
      message_payload_json: {
        text: '外发消息测试'
      },
      client_message_id: 'client_message_api_001'
    },
    handlers: harness.handlers
  });

  assert.equal(createMessageRoute.status, 200);
  const createdPayload = JSON.parse(createMessageRoute.body);
  assert.equal(createdPayload.enqueue_status, 'pending');
  assert.equal(createdPayload.idempotent_replay, false);

  const replayRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/messages',
    method: 'POST',
    requestId: 'req-tenant-session-message-create-2',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_wechat_id: harness.account.wechat_id,
      account_nickname: harness.account.nickname,
      conversation_id: 'conv_api_003',
      conversation_name: '赵老师',
      message_type: 'text',
      message_payload_json: {
        text: '外发消息测试'
      },
      client_message_id: 'client_message_api_001'
    },
    handlers: harness.handlers
  });

  assert.equal(replayRoute.status, 200);
  const replayPayload = JSON.parse(replayRoute.body);
  assert.equal(replayPayload.idempotent_replay, true);
  assert.equal(replayPayload.outbound_message_id, createdPayload.outbound_message_id);

  const pullRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/outbound-messages/pull?status=pending&limit=20',
    method: 'GET',
    requestId: 'req-tenant-session-outbound-pull',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(pullRoute.status, 200);
  const pullPayload = JSON.parse(pullRoute.body);
  assert.equal(pullPayload.messages.length, 1);
  assert.equal(pullPayload.messages[0].outbound_message_id, createdPayload.outbound_message_id);

  const statusRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/outbound-messages/status',
    method: 'POST',
    requestId: 'req-tenant-session-outbound-status',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      outbound_message_id: createdPayload.outbound_message_id,
      enqueue_status: 'sent',
      provider_message_id: 'provider_message_api_001'
    },
    handlers: harness.handlers
  });

  assert.equal(statusRoute.status, 200);
  const statusPayload = JSON.parse(statusRoute.body);
  assert.equal(statusPayload.enqueue_status, 'sent');
  assert.equal(statusPayload.provider_message_id, 'provider_message_api_001');
});

test('POST /tenant/sessions/outbound-messages/status denies updates for outbound messages outside operator scope', async () => {
  const harness = await createHarness({
    permissionContext: {
      can_view_session_management: true,
      can_operate_session_management: true,
      can_view_session_scope_my: true,
      can_view_session_scope_assist: false,
      can_view_session_scope_all: false
    }
  });

  const foreignAccount = await harness.authStore.createTenantAccount({
    tenantId: 'tenant-session-a',
    wechatId: 'wx_session_api_foreign_1',
    nickname: '会话账号Foreign',
    ownerMembershipId: 'membership-session-assistant',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-session-assistant',
    operatorName: '会话协管'
  });

  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: foreignAccount.wechat_id,
    conversationId: 'conv_api_scope_001',
    conversationName: 'Scope老师'
  });

  const foreignOutbound = await harness.authStore.createTenantSessionOutboundMessage({
    tenantId: 'tenant-session-a',
    accountWechatId: foreignAccount.wechat_id,
    accountNickname: foreignAccount.nickname,
    conversationId: 'conv_api_scope_001',
    conversationName: 'Scope老师',
    messageType: 'text',
    messagePayloadJson: {
      text: '仅用于权限校验'
    },
    messagePreview: '仅用于权限校验',
    clientMessageId: 'client_message_scope_001'
  });

  const statusRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/outbound-messages/status',
    method: 'POST',
    requestId: 'req-tenant-session-outbound-status-scope-denied',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      outbound_message_id: foreignOutbound.outbound_message_id,
      enqueue_status: 'sent'
    },
    handlers: harness.handlers
  });

  assert.equal(statusRoute.status, 403);
  const deniedPayload = JSON.parse(statusRoute.body);
  assert.equal(deniedPayload.error_code, 'AUTH-403-FORBIDDEN');
});

test('POST /tenant/sessions/messages denies create for conversations outside operator scope', async () => {
  const harness = await createHarness({
    permissionContext: {
      can_view_session_management: true,
      can_operate_session_management: true,
      can_view_session_scope_my: true,
      can_view_session_scope_assist: false,
      can_view_session_scope_all: false
    }
  });

  const foreignAccount = await harness.authStore.createTenantAccount({
    tenantId: 'tenant-session-a',
    wechatId: 'wx_session_api_foreign_2',
    nickname: '会话账号Foreign-Create',
    ownerMembershipId: 'membership-session-assistant',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-session-assistant',
    operatorName: '会话协管'
  });

  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: foreignAccount.wechat_id,
    conversationId: 'conv_api_scope_002',
    conversationName: 'CreateScope老师'
  });

  const deniedRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/messages',
    method: 'POST',
    requestId: 'req-tenant-session-message-create-scope-denied',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    body: {
      account_wechat_id: foreignAccount.wechat_id,
      account_nickname: foreignAccount.nickname,
      conversation_id: 'conv_api_scope_002',
      conversation_name: 'CreateScope老师',
      message_type: 'text',
      message_payload_json: {
        text: '越权发送应被拒绝'
      },
      client_message_id: 'client_message_scope_002'
    },
    handlers: harness.handlers
  });

  assert.equal(deniedRoute.status, 403);
  const deniedPayload = JSON.parse(deniedRoute.body);
  assert.equal(deniedPayload.error_code, 'AUTH-403-FORBIDDEN');
});

test('GET /tenant/sessions/chats rejects scope=all without scope permission', async () => {
  const harness = await createHarness({
    permissionContext: {
      can_view_session_management: true,
      can_operate_session_management: true,
      can_view_session_scope_my: true,
      can_view_session_scope_assist: true,
      can_view_session_scope_all: false
    }
  });

  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: harness.account.wechat_id,
    conversationId: 'conv_api_004',
    conversationName: '周老师'
  });

  const deniedRoute = await dispatchApiRoute({
    pathname: `/tenant/sessions/chats?scope=all&account_wechat_id=${encodeURIComponent(harness.account.wechat_id)}`,
    method: 'GET',
    requestId: 'req-tenant-session-scope-denied',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(deniedRoute.status, 403);
  const deniedPayload = JSON.parse(deniedRoute.body);
  assert.equal(deniedPayload.error_code, 'AUTH-403-FORBIDDEN');
});

test('GET /tenant/sessions/chats can omit account_wechat_id and auto-select first scoped account', async () => {
  const harness = await createHarness();
  await seedConversation({
    authStore: harness.authStore,
    accountWechatId: harness.account.wechat_id,
    conversationId: 'conv_api_auto_pick_001',
    conversationName: '自动选号会话'
  });

  const route = await dispatchApiRoute({
    pathname: '/tenant/sessions/chats?scope=my',
    method: 'GET',
    requestId: 'req-tenant-session-chat-list-auto-pick',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.account_wechat_id, harness.account.wechat_id);
  assert.equal(payload.total, 1);
  assert.equal(payload.chats[0].conversation_id, 'conv_api_auto_pick_001');
});

test('GET /tenant/sessions/chats omitting account_wechat_id returns empty list when scoped account set is empty', async () => {
  const harness = await createHarness();

  const route = await dispatchApiRoute({
    pathname: '/tenant/sessions/chats?scope=assist',
    method: 'GET',
    requestId: 'req-tenant-session-chat-list-empty-assist',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(route.status, 200);
  const payload = JSON.parse(route.body);
  assert.equal(payload.account_wechat_id, null);
  assert.equal(payload.total, 0);
  assert.deepEqual(payload.chats, []);
});

test('GET /tenant/sessions/account-options returns all enabled accounts under scope=all', async () => {
  const harness = await createHarness();
  const secondAccount = await harness.authStore.createTenantAccount({
    tenantId: 'tenant-session-a',
    wechatId: 'wx_session_api_all_scope_2',
    nickname: '会话账号ALL-2',
    ownerMembershipId: 'membership-session-assistant',
    assistantMembershipIds: [],
    operatorUserId: 'tenant-session-assistant',
    operatorName: '会话协管'
  });

  const listAllRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/account-options?scope=all',
    method: 'GET',
    requestId: 'req-tenant-session-account-options-all',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(listAllRoute.status, 200);
  const listAllPayload = JSON.parse(listAllRoute.body);
  const accountWechatIds = new Set(
    (Array.isArray(listAllPayload.accounts) ? listAllPayload.accounts : [])
      .map((item) => String(item.account_wechat_id || '').trim())
      .filter(Boolean)
  );
  assert.equal(accountWechatIds.has(harness.account.wechat_id), true);
  assert.equal(accountWechatIds.has(secondAccount.wechat_id), true);
});

test('GET /tenant/sessions/account-options keeps legacy active account status compatible', async () => {
  const harness = await createHarness();
  const originalListTenantAccountsByTenantId =
    harness.authStore.listTenantAccountsByTenantId.bind(harness.authStore);
  harness.authStore.listTenantAccountsByTenantId = async (...args) => {
    const accounts = await originalListTenantAccountsByTenantId(...args);
    return (Array.isArray(accounts) ? accounts : []).map((account, index) =>
      index === 0
        ? {
          ...account,
          status: 'active'
        }
        : account
    );
  };

  const listAllRoute = await dispatchApiRoute({
    pathname: '/tenant/sessions/account-options?scope=all',
    method: 'GET',
    requestId: 'req-tenant-session-account-options-active-compatible',
    headers: {
      authorization: 'Bearer fake-access-token'
    },
    handlers: harness.handlers
  });

  assert.equal(listAllRoute.status, 200);
  const listAllPayload = JSON.parse(listAllRoute.body);
  const accountWechatIds = new Set(
    (Array.isArray(listAllPayload.accounts) ? listAllPayload.accounts : [])
      .map((item) => String(item.account_wechat_id || '').trim())
      .filter(Boolean)
  );
  assert.equal(accountWechatIds.has(harness.account.wechat_id), true);
});
