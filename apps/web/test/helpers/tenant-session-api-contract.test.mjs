import test from 'node:test';
import assert from 'node:assert/strict';
import { createTenantManagementApi } from '../../src/api/tenant-management.mjs';

const createJsonResponse = (payload = {}) => ({
  ok: true,
  headers: {
    get: () => 'application/json'
  },
  json: async () => payload,
  text: async () => ''
});

const withMockFetch = async (handler, callback) => {
  const originalFetch = globalThis.fetch;
  globalThis.fetch = handler;
  try {
    await callback();
  } finally {
    globalThis.fetch = originalFetch;
  }
};

test('tenant session list request keeps API path and scope query semantics', async () => {
  const calls = [];
  await withMockFetch(async (url, options) => {
    calls.push({ url, options });
    return createJsonResponse({ chats: [] });
  }, async () => {
    const api = createTenantManagementApi({ accessToken: 'tenant-token' });
    await api.listSessions({
      page: 2,
      pageSize: 50,
      scope: 'assist',
      account_wechat_id: 'wx_tenant_101_sales',
      keyword: '会话关键词'
    });
  });

  assert.equal(calls.length, 1);
  const requestUrl = new URL(String(calls[0].url), 'http://localhost');
  assert.equal(requestUrl.pathname, '/api/tenant/sessions/chats');
  assert.equal(requestUrl.searchParams.get('page'), '2');
  assert.equal(requestUrl.searchParams.get('page_size'), '50');
  assert.equal(requestUrl.searchParams.get('scope'), 'assist');
  assert.equal(requestUrl.searchParams.get('account_wechat_id'), 'wx_tenant_101_sales');
  assert.equal(requestUrl.searchParams.get('keyword'), '会话关键词');
  assert.equal(calls[0].options.method, 'GET');
  assert.equal(calls[0].options.headers.Authorization, 'Bearer tenant-token');
});

test('tenant session account-options request uses canonical endpoint', async () => {
  const calls = [];
  await withMockFetch(async (url, options) => {
    calls.push({ url, options });
    return createJsonResponse({ accounts: [] });
  }, async () => {
    const api = createTenantManagementApi({ accessToken: 'tenant-token' });
    await api.listSessionAccounts({ scope: 'my' });
  });

  assert.equal(calls.length, 1);
  const requestUrl = new URL(String(calls[0].url), 'http://localhost');
  assert.equal(requestUrl.pathname, '/api/tenant/sessions/account-options');
  assert.equal(requestUrl.searchParams.get('scope'), 'my');
  assert.equal(calls[0].options.method, 'GET');
});

test('tenant session message list request encodes conversation id and keeps cursor+limit semantics', async () => {
  const calls = [];
  await withMockFetch(async (url, options) => {
    calls.push({ url, options });
    return createJsonResponse({ messages: [] });
  }, async () => {
    const api = createTenantManagementApi({ accessToken: 'tenant-token' });
    await api.getSessionMessages({
      conversationId: 'conversation/tenant-101?alpha=1',
      scope: 'assist',
      account_wechat_id: 'wx_tenant_101_sales',
      cursor: '2026-01-01T00:00:00.000Z',
      limit: 30
    });
  });

  assert.equal(calls.length, 1);
  const requestUrl = new URL(String(calls[0].url), 'http://localhost');
  assert.equal(
    requestUrl.pathname,
    '/api/tenant/sessions/chats/conversation%2Ftenant-101%3Falpha%3D1/messages'
  );
  assert.equal(requestUrl.searchParams.get('scope'), 'assist');
  assert.equal(requestUrl.searchParams.get('account_wechat_id'), 'wx_tenant_101_sales');
  assert.equal(requestUrl.searchParams.get('cursor'), '2026-01-01T00:00:00.000Z');
  assert.equal(requestUrl.searchParams.get('limit'), '30');
  assert.equal(calls[0].options.method, 'GET');
});

test('tenant session send request uses outbound message endpoint and includes idempotency key header', async () => {
  const calls = [];
  await withMockFetch(async (url, options) => {
    calls.push({ url, options });
    return createJsonResponse({ request_id: 'req-1' });
  }, async () => {
    const api = createTenantManagementApi({ accessToken: 'tenant-token' });
    await api.sendSessionMessage({
      payload: {
        account_wechat_id: 'wx_tenant_101_sales',
        account_nickname: '销售号',
        conversation_id: 'session-tenant-101-2',
        conversation_name: '客户乙',
        message_type: 'text',
        message_payload_json: {
          text: '会话中心联动消息'
        }
      }
    });
  });

  assert.equal(calls.length, 1);
  const requestUrl = new URL(String(calls[0].url), 'http://localhost');
  assert.equal(requestUrl.pathname, '/api/tenant/sessions/messages');
  assert.equal(calls[0].options.method, 'POST');
  assert.deepEqual(JSON.parse(String(calls[0].options.body)), {
    account_wechat_id: 'wx_tenant_101_sales',
    account_nickname: '销售号',
    conversation_id: 'session-tenant-101-2',
    conversation_name: '客户乙',
    message_type: 'text',
    message_payload_json: {
      text: '会话中心联动消息'
    }
  });
  assert.equal(calls[0].options.headers.Authorization, 'Bearer tenant-token');
  assert.match(
    String(calls[0].options.headers['Idempotency-Key'] || ''),
    /^ui-tenant-sessions-send-message-\d+-[a-f0-9]+$/i
  );
});
