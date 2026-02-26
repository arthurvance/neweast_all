#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function joinPath(...segments) {
  return segments.join('/');
}

function readJson(filePath, errors) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (error) {
    errors.push(`failed to read JSON ${toPosix(filePath)}: ${error.message}`);
    return null;
  }
}

function isFile(filePath) {
  try {
    return fs.statSync(filePath).isFile();
  } catch (_error) {
    return false;
  }
}

function walkFiles(directoryPath, files) {
  let entries = [];
  try {
    entries = fs.readdirSync(directoryPath, { withFileTypes: true });
  } catch (_error) {
    return;
  }

  for (const entry of entries) {
    const absolutePath = path.join(directoryPath, entry.name);
    if (entry.isDirectory()) {
      walkFiles(absolutePath, files);
      continue;
    }
    if (entry.isFile()) {
      files.push(absolutePath);
    }
  }
}

function hasAtLeastTwoTrueCriteria(criteria = {}) {
  const keys = [
    'independent_permission_set',
    'independent_transaction_boundary',
    'independent_audit_event_model',
    'independent_state_machine'
  ];
  let score = 0;
  for (const key of keys) {
    if (criteria[key] === true) {
      score += 1;
    }
  }
  return score >= 2;
}

function runCapabilityBoundaryCheck(options = {}) {
  const repoRoot = options.repoRoot || path.resolve(__dirname, '..', '..');
  const errors = [];
  const warnings = [];

  const capabilityMap = readJson(
    path.join(repoRoot, 'tools/domain-contract/capability-map.json'),
    errors
  );
  const decisionLog = readJson(
    path.join(repoRoot, 'tools/domain-contract/capability-decision-log.json'),
    errors
  );
  const rules = readJson(
    path.join(repoRoot, 'tools/domain-contract/capability-boundary-rules.json'),
    errors
  );

  if (!capabilityMap || !decisionLog || !rules) {
    return { ok: false, errors, warnings };
  }

  const authCapabilities = (capabilityMap.capabilities || []).filter(
    (capability) => capability.module === 'auth' && (capability.applications || []).includes('api')
  );

  const decisionEntries = new Map(
    (decisionLog.entries || []).map((entry) => [entry.capability_id, entry])
  );

  for (const capability of authCapabilities) {
    const decision = decisionEntries.get(capability.capability_id);
    if (!decision) {
      errors.push(`missing capability decision log entry: ${capability.capability_id}`);
      continue;
    }

    if (!hasAtLeastTwoTrueCriteria(decision.criteria || {})) {
      errors.push(
        `capability decision requires at least two criteria=true: ${capability.capability_id}`
      );
    }

    if (
      capability.symmetry === 'extension'
      && rules.constraints.platform_only_capabilities_require_exception
      && (!capability.domain_scoped_exception || capability.domain_scoped_exception.enabled !== true)
    ) {
      errors.push(
        `platform-only capability must declare domain_scoped_exception: ${capability.capability_id}`
      );
    }

    if (rules.constraints.require_domain_structure) {
      const capabilityDirectory = path.join(
        repoRoot,
        'apps/api/src/domains',
        capability.domain,
        capability.module,
        capability.capability
      );
      if (!fs.existsSync(capabilityDirectory)) {
        errors.push(
          `missing capability directory: ${toPosix(path.relative(repoRoot, capabilityDirectory))}`
        );
        continue;
      }

      if (rules.constraints.require_colocated_service_store) {
        const leafName = capability.capability.split('/').pop();
        const requiredFiles = [
          'index.js',
          `${leafName}.service.js`,
          `${leafName}.store.memory.js`,
          `${leafName}.store.mysql.js`
        ];
        for (const fileName of requiredFiles) {
          const targetPath = path.join(capabilityDirectory, fileName);
          if (!isFile(targetPath)) {
            errors.push(`missing colocated file: ${toPosix(path.relative(repoRoot, targetPath))}`);
          }
        }
      }
    }
  }

  const forbiddenPatterns = (rules.constraints.forbidden_file_name_patterns || []).map(
    (pattern) => String(pattern)
  );
  if (forbiddenPatterns.length > 0) {
    const files = [];
    walkFiles(path.join(repoRoot, 'apps/api/src/domains'), files);
    walkFiles(path.join(repoRoot, 'apps/api/src/shared-kernel/auth'), files);

    for (const filePath of files) {
      const relativePath = toPosix(path.relative(repoRoot, filePath));
      const basename = path.basename(relativePath);
      for (const pattern of forbiddenPatterns) {
        if (basename.endsWith(pattern)) {
          errors.push(`forbidden filename pattern (${pattern}): ${relativePath}`);
        }
      }
    }
  }

  const defaultLegacyPaths = [
    joinPath('apps', 'api', 'src', 'modules', 'auth', 'auth.service.js'),
    joinPath('apps', 'api', 'src', 'modules', 'auth', 'auth.store.memory.js'),
    joinPath('apps', 'api', 'src', 'modules', 'auth', 'auth.store.mysql.js'),
    joinPath(
      'apps',
      'api',
      'src',
      'modules',
      'auth',
      'store-methods',
      'auth-store-memory-capabilities.js'
    ),
    joinPath(
      'apps',
      'api',
      'src',
      'modules',
      'auth',
      'store-methods',
      'auth-store-mysql-capabilities.js'
    )
  ];
  const configuredLegacyPaths = Array.isArray(rules.constraints.legacy_paths)
    ? rules.constraints.legacy_paths
    : [];
  const legacyPaths = [...new Set([...defaultLegacyPaths, ...configuredLegacyPaths])];
  for (const legacyPath of legacyPaths) {
    const targetPath = path.join(repoRoot, legacyPath);
    if (fs.existsSync(targetPath)) {
      errors.push(`legacy path still exists: ${toPosix(path.relative(repoRoot, targetPath))}`);
    }
  }

  return {
    ok: errors.length === 0,
    checked_capabilities: authCapabilities.length,
    errors,
    warnings
  };
}

if (require.main === module) {
  const result = runCapabilityBoundaryCheck();
  if (!result.ok) {
    process.stderr.write(`${result.errors.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(`OK: capability boundary checks passed (${result.checked_capabilities} capabilities).\n`);
}

module.exports = {
  runCapabilityBoundaryCheck
};
