const test = require('node:test');
const assert = require('node:assert/strict');
const {
  TRACEPARENT_PATTERN,
  normalizeTraceparent,
  createTraceparent,
  extract,
  inject,
  mergeReplayTraceContext
} = require('../src/common/trace-context');

test('normalizeTraceparent enforces W3C-style shape and fail-closed invalid values', () => {
  assert.equal(
    normalizeTraceparent('00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'),
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(
    normalizeTraceparent('FF-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'),
    null
  );
  assert.equal(
    normalizeTraceparent('00-00000000000000000000000000000000-00f067aa0ba902b7-01'),
    null
  );
  assert.equal(normalizeTraceparent('invalid'), null);
});

test('extract http trace context supports generated traceparent fallback', () => {
  const extractedWithHeader = extract({
    source: {
      'X-Request-Id': 'req-trace-extract',
      Traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    }
  });
  assert.equal(extractedWithHeader.requestId, 'req-trace-extract');
  assert.equal(
    extractedWithHeader.traceparent,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );

  const extractedWithoutHeader = extract({
    source: {},
    fallbackRequestId: 'fallback-request-id',
    generateTraceparentOnMissing: true
  });
  assert.equal(extractedWithoutHeader.requestId, 'fallback-request-id');
  assert.match(extractedWithoutHeader.traceparent, TRACEPARENT_PATTERN);

  const extractedWithInvalidHeader = extract({
    source: {
      'x-request-id': 'req-trace-invalid',
      traceparent: 'invalid'
    },
    generateTraceparentOnMissing: true
  });
  assert.equal(extractedWithInvalidHeader.requestId, 'req-trace-invalid');
  assert.equal(extractedWithInvalidHeader.traceparent, null);
});

test('extract fail-closes ambiguous multi-value http headers', () => {
  const extracted = extract({
    source: {
      'x-request-id': ['req-a', 'req-b'],
      traceparent: [
        '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
        '00-11111111111111111111111111111111-2222222222222222-01'
      ]
    },
    fallbackRequestId: 'fallback-request-id',
    generateTraceparentOnMissing: true
  });

  assert.equal(extracted.requestId, 'fallback-request-id');
  assert.equal(extracted.traceparent, null);
});

test('inject supports both http headers and async envelope minimum fields', () => {
  const traceparent = createTraceparent();
  const injectedHttp = inject({
    channel: 'http',
    traceContext: {
      requestId: 'req-inject-http',
      traceparent
    }
  });
  assert.equal(injectedHttp['x-request-id'], 'req-inject-http');
  assert.equal(injectedHttp.traceparent, traceparent);

  const injectedMessage = inject({
    channel: 'queue',
    traceContext: {
      requestId: 'req-inject-msg',
      traceparent
    },
    target: {
      data: {
        ok: true
      }
    },
    schemaVersion: '2026-02-21'
  });
  assert.ok(injectedMessage.event_id);
  assert.equal(injectedMessage.request_id, 'req-inject-msg');
  assert.equal(injectedMessage.traceparent, traceparent);
  assert.ok(injectedMessage.occurred_at);
  assert.equal(injectedMessage.schema_version, '2026-02-21');
});

test('inject http fail-closes stale target trace headers on invalid traceparent', () => {
  const injectedHttp = inject({
    channel: 'http',
    traceContext: {
      requestId: 'req-inject-http-invalid-trace',
      traceparent: 'not-a-valid-traceparent'
    },
    target: {
      foo: 'bar',
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
      Traceparent: '00-11111111111111111111111111111111-2222222222222222-01',
      'X-Request-Id': 'old-request-id'
    }
  });

  assert.equal(injectedHttp.foo, 'bar');
  assert.equal(injectedHttp['x-request-id'], 'req-inject-http-invalid-trace');
  assert.equal(
    Object.keys(injectedHttp).some(
      (key) => String(key).toLowerCase() === 'traceparent'
    ),
    false
  );
  assert.equal(
    Object.keys(injectedHttp).some(
      (key) => key !== 'x-request-id' && String(key).toLowerCase() === 'x-request-id'
    ),
    false
  );
});

test('mergeReplayTraceContext preserves original trace fields and stores replay ids separately', () => {
  const originalTraceparent = createTraceparent();
  const replayTraceparent = createTraceparent();
  const merged = mergeReplayTraceContext({
    original: {
      request_id: 'req-original',
      traceparent: originalTraceparent
    },
    replay: {
      request_id: 'req-replay',
      traceparent: replayTraceparent
    }
  });

  assert.equal(merged.request_id, 'req-original');
  assert.equal(merged.traceparent, originalTraceparent);
  assert.equal(merged.replay_request_id, 'req-replay');
  assert.equal(merged.replay_traceparent, replayTraceparent);
});
