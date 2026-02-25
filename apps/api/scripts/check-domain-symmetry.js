#!/usr/bin/env node
'use strict';

const path = require('node:path');
const {
  runDomainSymmetryCheck: runSharedDomainSymmetryCheck
} = require('../../../tools/domain-contract/check-domain-symmetry');

function runDomainSymmetryCheck(options = {}) {
  const repoRoot = options.repoRoot || path.resolve(__dirname, '../../..');
  return runSharedDomainSymmetryCheck({
    ...options,
    app: 'api',
    repoRoot
  });
}

function main() {
  const report = runDomainSymmetryCheck();

  if (!report.ok) {
    console.error('[check-domain-symmetry] API domain symmetry check failed.');
    for (const issue of report.errors) {
      console.error(` - ${issue}`);
    }
    process.exit(1);
  }

  console.log(
    `[check-domain-symmetry] API domain symmetry check passed (${report.checked_capabilities} capabilities checked).`
  );
}

if (require.main === module) {
  main();
}

module.exports = {
  runDomainSymmetryCheck
};
