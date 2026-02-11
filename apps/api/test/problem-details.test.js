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
