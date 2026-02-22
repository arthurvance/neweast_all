const test = require('node:test');
const assert = require('node:assert/strict');
const {
  runIntegrationReleaseWindowCheck,
  _internals
} = require('../scripts/check-integration-freeze-gate');

test('resolveRouteRequestId falls back to response payload request_id for freeze gate script', () => {
  const route = {
    status: 200,
    body: JSON.stringify({
      request_id: 'req-freeze-gate-script-fallback'
    })
  };
  const payload = _internals.parseJsonBodySafely(route);
  assert.deepEqual(payload, {
    request_id: 'req-freeze-gate-script-fallback'
  });
  assert.equal(
    _internals.resolveRouteRequestId(route, payload),
    'req-freeze-gate-script-fallback'
  );
});

test('parseJsonBodySafely returns null for malformed JSON in freeze gate script', () => {
  assert.equal(
    _internals.parseJsonBodySafely({
      status: 500,
      body: '{"broken":'
    }),
    null
  );
});

test('assertRoute captures validator exceptions for freeze gate script checks', () => {
  const checks = [];
  assert.doesNotThrow(() => {
    _internals.assertRoute(checks, {
      status: 200,
      requestId: 'req-freeze-gate-script-validator-exception',
      body: '{"ok": true}'
    }, {
      id: 'validator.exception',
      expectedStatus: 200,
      validate: () => {
        throw new Error('validator crash');
      }
    });
  });
  assert.equal(checks.length, 1);
  assert.equal(checks[0].id, 'validator.exception');
  assert.equal(checks[0].passed, false);
  assert.equal(checks[0].status, 200);
  assert.equal(checks[0].request_id, 'req-freeze-gate-script-validator-exception');
  assert.match(checks[0].detail, /validation exception: validator crash/);
});

test('runIntegrationReleaseWindowCheck captures non-empty request_id for every check', async () => {
  const report = await runIntegrationReleaseWindowCheck();
  assert.equal(report.passed, true);
  assert.ok(Array.isArray(report.checks));
  assert.equal(report.checks.length > 0, true);
  for (const check of report.checks) {
    assert.equal(typeof check.request_id, 'string');
    assert.equal(check.request_id.length > 0, true);
  }
});
