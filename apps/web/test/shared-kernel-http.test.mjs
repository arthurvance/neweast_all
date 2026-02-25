import test from 'node:test';
import assert from 'node:assert/strict';
import {
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
