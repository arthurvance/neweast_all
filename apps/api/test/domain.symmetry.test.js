const test = require('node:test');
const assert = require('node:assert/strict');
const { runDomainSymmetryCheck } = require('../scripts/check-domain-symmetry');

test('API domain symmetry contract check passes for baseline contract', () => {
  const report = runDomainSymmetryCheck();
  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.equal(report.checked_capabilities > 0, true);
});
