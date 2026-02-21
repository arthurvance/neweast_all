const test = require('node:test');
const assert = require('node:assert/strict');
const { buildProblemDetails } = require('../src/common/problem-details');

test('buildProblemDetails includes request_id placeholder', () => {
  const problem = buildProblemDetails({
    title: 'Bad Request',
    status: 400,
    detail: 'Invalid payload'
  });

  assert.equal(problem.status, 400);
  assert.equal(problem.title, 'Bad Request');
  assert.equal(problem.request_id, 'request_id_unset');
});

test('buildProblemDetails includes retryable flag with default false and explicit override', () => {
  const defaultProblem = buildProblemDetails({
    title: 'Unauthorized',
    status: 401,
    detail: 'invalid access token'
  });
  assert.equal(defaultProblem.retryable, false);

  const retryableProblem = buildProblemDetails({
    title: 'Service Unavailable',
    status: 503,
    detail: 'temporary degraded',
    extensions: {
      retryable: true,
      degradation_reason: 'db-deadlock'
    }
  });
  assert.equal(retryableProblem.retryable, true);
  assert.equal(retryableProblem.degradation_reason, 'db-deadlock');
});

test('buildProblemDetails does not allow extensions to override request_id and traceparent', () => {
  const problem = buildProblemDetails({
    title: 'Bad Request',
    status: 400,
    detail: 'invalid',
    requestId: 'req-problem',
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01',
    extensions: {
      request_id: 'spoofed-request-id',
      traceparent: 'invalid-traceparent',
      retryable: true
    }
  });

  assert.equal(problem.request_id, 'req-problem');
  assert.equal(
    problem.traceparent,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
  assert.equal(problem.retryable, true);
});

test('buildProblemDetails fail-closes invalid traceparent values', () => {
  const problem = buildProblemDetails({
    title: 'Bad Request',
    status: 400,
    detail: 'invalid',
    requestId: 'req-problem-invalid-trace',
    traceparent: 'not-a-valid-traceparent'
  });

  assert.equal(problem.request_id, 'req-problem-invalid-trace');
  assert.equal(problem.traceparent, null);
});

test('buildProblemDetails keeps request_id as string contract', () => {
  const problem = buildProblemDetails({
    title: 'Bad Request',
    status: 400,
    detail: 'invalid',
    requestId: { unexpected: true },
    traceparent: '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  });

  assert.equal(problem.request_id, 'request_id_unset');
  assert.equal(
    problem.traceparent,
    '00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'
  );
});
