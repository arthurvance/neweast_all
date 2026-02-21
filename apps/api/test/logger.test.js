const test = require('node:test');
const assert = require('node:assert/strict');
const { log } = require('../src/common/logger');

test('log normalizes traceparent and resists traceparent override via extra payload', () => {
  const originalWrite = process.stdout.write;
  const chunks = [];
  process.stdout.write = (chunk) => {
    chunks.push(String(chunk));
    return true;
  };

  try {
    log('info', 'trace log', {
      request_id: 'req-log',
      traceparent: '  00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01  '
    });
    log('info', 'invalid trace log', {
      request_id: 'req-log-2',
      traceparent: { invalid: true }
    });
    log('info', 'invalid trace string', {
      request_id: 'req-log-3',
      traceparent: 'not-a-valid-traceparent'
    });
    log('info', 'non-string request id', {
      request_id: { bad: true },
      traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
    });
  } finally {
    process.stdout.write = originalWrite;
  }

  const first = JSON.parse(chunks[0]);
  assert.equal(first.request_id, 'req-log');
  assert.equal(
    first.traceparent,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );

  const second = JSON.parse(chunks[1]);
  assert.equal(second.request_id, 'req-log-2');
  assert.equal(second.traceparent, null);

  const third = JSON.parse(chunks[2]);
  assert.equal(third.request_id, 'req-log-3');
  assert.equal(third.traceparent, null);

  const fourth = JSON.parse(chunks[3]);
  assert.equal(fourth.request_id, 'request_id_unset');
  assert.equal(
    fourth.traceparent,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
});
