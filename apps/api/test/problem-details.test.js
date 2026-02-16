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
