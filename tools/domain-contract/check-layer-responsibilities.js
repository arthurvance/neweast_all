#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function walk(directoryPath, output) {
  let entries = [];
  try {
    entries = fs.readdirSync(directoryPath, { withFileTypes: true });
  } catch (_error) {
    return;
  }

  for (const entry of entries) {
    const absolutePath = path.join(directoryPath, entry.name);
    if (entry.isDirectory()) {
      walk(absolutePath, output);
      continue;
    }
    if (entry.isFile() && /\.(?:[mc]?js|ts|tsx|jsx)$/.test(entry.name)) {
      output.push(absolutePath);
    }
  }
}

function runLayerResponsibilityCheck(options = {}) {
  const repoRoot = options.repoRoot || path.resolve(__dirname, '..', '..');
  const files = [];
  walk(path.join(repoRoot, 'apps/api/src/modules/auth'), files);
  walk(path.join(repoRoot, 'apps/api/src/domains'), files);
  walk(path.join(repoRoot, 'apps/api/src/shared-kernel/auth'), files);

  const errors = [];

  const routeSqlPattern = /\b(SELECT|INSERT|UPDATE|DELETE)\b|dbClient\s*\.\s*query\s*\(/;
  const routeBusinessPattern = /inTransaction\s*\(|CREATE\s+TABLE|DROP\s+TABLE/i;
  const storeAuthzPattern = /authorizeRoute\s*\(|permissionContextBuilder|createEntryPolicyService/;

  for (const filePath of files) {
    const relativePath = toPosix(path.relative(repoRoot, filePath));
    const content = fs.readFileSync(filePath, 'utf8');

    if (/\.routes\.[mc]?js$/.test(relativePath) || relativePath.endsWith('/auth.routes.js')) {
      if (routeSqlPattern.test(content) || routeBusinessPattern.test(content)) {
        errors.push(`route layer contains persistence/business logic: ${relativePath}`);
      }
    }

    if (/\.store\.(memory|mysql)\.[mc]?js$/.test(relativePath) || /create-(in-memory|mysql)-auth-store\.[mc]?js$/.test(relativePath)) {
      if (storeAuthzPattern.test(content)) {
        errors.push(`store layer contains authz orchestration logic: ${relativePath}`);
      }
    }
  }

  return {
    ok: errors.length === 0,
    checked_files: files.length,
    errors
  };
}

if (require.main === module) {
  const result = runLayerResponsibilityCheck();
  if (!result.ok) {
    process.stderr.write(`${result.errors.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(`OK: layer responsibility checks passed (${result.checked_files} files).\n`);
}

module.exports = {
  runLayerResponsibilityCheck
};
