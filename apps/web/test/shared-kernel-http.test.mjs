import test from 'node:test';
import assert from 'node:assert/strict';
import {
  configureAuthRequestHooks,
  createApiRequest,
  toProblemMessage,
  toSearch
} from '../src/shared-kernel/http/request-json.mjs';
import { buildIdempotencyKey } from '../src/shared-kernel/http/idempotency-key.mjs';

test('toSearch omits empty values and keeps stable query keys', () => {
  const search = toSearch({
    page: 1,
    page_size: 20,
    status: '',
    owner: null,
    keyword: 'alice'
  });
  assert.equal(search, '?page=1&page_size=20&keyword=alice');
});

test('createApiRequest sends auth + idempotency headers and parses json body', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({
      url,
      options
    });
    return {
      ok: true,
      headers: {
        get: () => 'application/json'
      },
      json: async () => ({ ok: true }),
      text: async () => ''
    };
  };

  try {
    const request = createApiRequest({
      accessToken: 'token-123',
      apiBaseUrl: 'http://localhost:3000/api'
    });

    const payload = await request({
      path: '/platform/users',
      method: 'POST',
      payload: { name: 'Alice' },
      idempotencyKey: 'idem-123'
    });

    assert.deepEqual(payload, { ok: true });
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, 'http://localhost:3000/api/platform/users');
    assert.equal(calls[0].options.headers.Authorization, 'Bearer token-123');
    assert.equal(calls[0].options.headers['Idempotency-Key'], 'idem-123');
    assert.equal(calls[0].options.headers['Content-Type'], 'application/json');
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('createApiRequest supports request-level access token override', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (url, options) => {
    calls.push({
      url,
      options
    });
    return {
      ok: true,
      headers: {
        get: () => 'application/json'
      },
      json: async () => ({ ok: true }),
      text: async () => ''
    };
  };

  try {
    const request = createApiRequest({
      apiBaseUrl: 'http://localhost:3000/api'
    });
    await request({
      path: '/auth/platform/options',
      method: 'GET',
      accessToken: 'runtime-token'
    });

    assert.equal(calls.length, 1);
    assert.equal(
      calls[0].options.headers.Authorization,
      'Bearer runtime-token'
    );
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('createApiRequest auto refreshes invalid access token and retries once', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  const refreshCalls = [];
  let currentAccessToken = 'token-before-refresh';

  globalThis.fetch = async (url, options) => {
    calls.push({
      url,
      options
    });
    if (calls.length === 1) {
      return {
        ok: false,
        status: 401,
        headers: {
          get: () => 'application/problem+json'
        },
        json: async () => ({
          error_code: 'AUTH-401-INVALID-ACCESS',
          detail: '当前会话无效，请重新登录'
        }),
        text: async () => ''
      };
    }
    return {
      ok: true,
      status: 200,
      headers: {
        get: () => 'application/json'
      },
      json: async () => ({ ok: true, token: currentAccessToken }),
      text: async () => ''
    };
  };

  configureAuthRequestHooks({
    getAccessToken: () => currentAccessToken,
    refreshAccessToken: async (context) => {
      refreshCalls.push(context);
      currentAccessToken = 'token-after-refresh';
      return currentAccessToken;
    }
  });

  try {
    const request = createApiRequest({
      apiBaseUrl: 'http://localhost:3000/api'
    });
    const payload = await request({
      path: '/tenant/customers',
      method: 'GET'
    });

    assert.deepEqual(payload, {
      ok: true,
      token: 'token-after-refresh'
    });
    assert.equal(calls.length, 2);
    assert.equal(
      calls[0].options.headers.Authorization,
      'Bearer token-before-refresh'
    );
    assert.equal(
      calls[1].options.headers.Authorization,
      'Bearer token-after-refresh'
    );
    assert.equal(refreshCalls.length, 1);
    assert.deepEqual(refreshCalls[0], {
      reason: 'invalid-access',
      path: '/tenant/customers',
      method: 'GET',
      previousAccessToken: 'token-before-refresh'
    });
  } finally {
    configureAuthRequestHooks();
    globalThis.fetch = originalFetch;
  }
});

test('createApiRequest does not auto refresh excluded auth endpoints', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  let refreshCallCount = 0;

  globalThis.fetch = async (url, options) => {
    calls.push({
      url,
      options
    });
    return {
      ok: false,
      status: 401,
      headers: {
        get: () => 'application/problem+json'
      },
      json: async () => ({
        error_code: 'AUTH-401-INVALID-ACCESS',
        detail: '当前会话无效，请重新登录'
      }),
      text: async () => ''
    };
  };

  configureAuthRequestHooks({
    getAccessToken: () => 'token-before-refresh',
    refreshAccessToken: async () => {
      refreshCallCount += 1;
      return 'token-after-refresh';
    }
  });

  try {
    const request = createApiRequest({
      apiBaseUrl: 'http://localhost:3000/api'
    });

    await assert.rejects(
      request({
        path: '/auth/refresh',
        method: 'POST'
      }),
      (error) => Number(error?.status) === 401
    );

    assert.equal(calls.length, 1);
    assert.equal(refreshCallCount, 0);
  } finally {
    configureAuthRequestHooks();
    globalThis.fetch = originalFetch;
  }
});

test('createApiRequest retries once when refresh returns unchanged access token', async () => {
  const originalFetch = globalThis.fetch;
  const calls = [];
  let refreshCallCount = 0;

  globalThis.fetch = async (url, options) => {
    calls.push({
      url,
      options
    });
    if (calls.length === 1) {
      return {
        ok: false,
        status: 401,
        headers: {
          get: () => 'application/problem+json'
        },
        json: async () => ({
          error_code: 'AUTH-401-INVALID-ACCESS',
          detail: '当前会话无效，请重新登录'
        }),
        text: async () => ''
      };
    }
    return {
      ok: true,
      status: 200,
      headers: {
        get: () => 'application/json'
      },
      json: async () => ({ ok: true }),
      text: async () => ''
    };
  };

  configureAuthRequestHooks({
    getAccessToken: () => 'token-same',
    refreshAccessToken: async () => {
      refreshCallCount += 1;
      return 'token-same';
    }
  });

  try {
    const request = createApiRequest({
      apiBaseUrl: 'http://localhost:3000/api'
    });
    const payload = await request({
      path: '/tenant/customers',
      method: 'GET'
    });

    assert.deepEqual(payload, { ok: true });
    assert.equal(refreshCallCount, 1);
    assert.equal(calls.length, 2);
    assert.equal(
      calls[0].options.headers.Authorization,
      'Bearer token-same'
    );
    assert.equal(
      calls[1].options.headers.Authorization,
      'Bearer token-same'
    );
  } finally {
    configureAuthRequestHooks();
    globalThis.fetch = originalFetch;
  }
});

test('toProblemMessage appends retry hint only once', () => {
  assert.equal(
    toProblemMessage(new Error('网络异常'), '操作失败'),
    '网络异常，请稍后重试'
  );
  assert.equal(
    toProblemMessage({ message: '网络异常，请稍后重试' }, '操作失败'),
    '网络异常，请稍后重试'
  );
});

test('buildIdempotencyKey includes prefix and entropy segment', () => {
  const key = buildIdempotencyKey('ui-test');
  assert.match(key, /^ui-test-\d+-[a-f0-9]+$/i);
});
