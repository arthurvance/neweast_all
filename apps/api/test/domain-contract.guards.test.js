const test = require('node:test');
const assert = require('node:assert/strict');
const {
  mkdtempSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync
} = require('node:fs');
const { tmpdir } = require('node:os');
const { join, resolve } = require('node:path');
const domainSymmetryContract = require('../../../tools/domain-contract/check-domain-symmetry');
const {
  runDomainSymmetryCheck
} = domainSymmetryContract;
const refactorGovernanceContract = require(
  '../../../tools/domain-contract/check-refactor-governance'
);
const {
  runRefactorGovernanceCheck
} = refactorGovernanceContract;
const crossDomainRule = require('../../../tools/lint-rules/no-cross-domain-imports');
const domainDeepImportRule = require('../../../tools/lint-rules/no-domain-deep-imports');
const domainModuleConstantsImportRule = require(
  '../../../tools/lint-rules/no-domain-module-constants-imports'
);
const domainApiClientImportRule = require(
  '../../../tools/lint-rules/no-domain-api-client-direct-imports'
);
const fileGranularityRule = require(
  '../../../tools/lint-rules/file-granularity-thresholds'
);

const REPO_ROOT = resolve(__dirname, '../../..');
const CAPABILITY_MAP = JSON.parse(
  readFileSync(resolve(REPO_ROOT, 'tools/domain-contract/capability-map.json'), 'utf8')
);
const CAPABILITY_SCHEMA = JSON.parse(
  readFileSync(resolve(REPO_ROOT, 'tools/domain-contract/capability-map.schema.json'), 'utf8')
);
const EXTENSION_REGISTRY = JSON.parse(
  readFileSync(resolve(REPO_ROOT, 'tools/domain-contract/domain-extension-registry.json'), 'utf8')
);
const NAMING_RULES = JSON.parse(
  readFileSync(resolve(REPO_ROOT, 'tools/domain-contract/naming-rules.json'), 'utf8')
);

test('domain symmetry check rejects duplicate capability_id', () => {
  const duplicateMap = JSON.parse(JSON.stringify(CAPABILITY_MAP));
  duplicateMap.capabilities.push({
    ...duplicateMap.capabilities[0]
  });

  const report = runDomainSymmetryCheck({
    app: 'api',
    repoRoot: REPO_ROOT,
    capabilityMap: duplicateMap
  });

  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /duplicate capability_id detected/);
});

test('domain symmetry check rejects unknown extension capability references', () => {
  const invalidExtensionRegistry = JSON.parse(JSON.stringify(EXTENSION_REGISTRY));
  invalidExtensionRegistry.extensions.push({
    capability_id: 'platform.config.ghost',
    domain: 'platform',
    module: 'config',
    capability: 'ghost',
    owner: 'platform-core',
    reason: 'invalid test fixture',
    exit_condition: 'never',
    review_at: '2026-06-30'
  });

  const report = runDomainSymmetryCheck({
    app: 'api',
    repoRoot: REPO_ROOT,
    extensionRegistry: invalidExtensionRegistry
  });

  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /references unknown capability_id/);
});

test('domain symmetry check internals reject domains/{domain}/{capability} top-level directory', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'domain-top-level-shape-'));
  try {
    const domainsRoot = resolve(sandboxRoot, 'apps/api/src/domains');
    mkdirSync(resolve(domainsRoot, 'platform/settings/user'), { recursive: true });
    mkdirSync(resolve(domainsRoot, 'platform/user-management'), { recursive: true });
    mkdirSync(resolve(domainsRoot, 'tenant/settings/user'), { recursive: true });

    const errors = [];
    domainSymmetryContract._internals.validateDomainTopLevelDirectoryShape({
      app: 'api',
      domainsRoot,
      repoRoot: sandboxRoot,
      errors
    });

    assert.equal(errors.length, 1);
    assert.match(errors[0], /invalid domain top-level directory/);
    assert.match(errors[0], /platform\/user-management/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('domain symmetry check supports onboarding inventory module when declared in capability map', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'domain-module-onboarding-'));
  try {
    const domainsRoot = resolve(sandboxRoot, 'apps/api/src/domains');
    mkdirSync(resolve(domainsRoot, 'platform/inventory/stock'), { recursive: true });
    mkdirSync(resolve(domainsRoot, 'tenant/inventory/stock'), { recursive: true });
    writeFileSync(resolve(domainsRoot, 'platform/index.js'), 'module.exports = {};\n', 'utf8');
    writeFileSync(resolve(domainsRoot, 'tenant/index.js'), 'module.exports = {};\n', 'utf8');
    writeFileSync(
      resolve(domainsRoot, 'platform/inventory/stock/index.js'),
      'module.exports = {};\n',
      'utf8'
    );
    writeFileSync(
      resolve(domainsRoot, 'tenant/inventory/stock/index.js'),
      'module.exports = {};\n',
      'utf8'
    );

    const onboardingCapabilityMap = {
      schema_version: '2.0.0',
      capabilities: [
        {
          capability_id: 'platform.inventory.stock',
          canonical_term: 'stock',
          module: 'inventory',
          domain: 'platform',
          capability: 'stock',
          owner: 'platform-core',
          review_at: '2026-06-30',
          parity_key: 'inventory.stock',
          symmetry: 'required',
          applications: ['api']
        },
        {
          capability_id: 'tenant.inventory.stock',
          canonical_term: 'stock',
          module: 'inventory',
          domain: 'tenant',
          capability: 'stock',
          owner: 'tenant-core',
          review_at: '2026-06-30',
          parity_key: 'inventory.stock',
          symmetry: 'required',
          applications: ['api']
        }
      ]
    };
    const onboardingNamingRules = {
      ...NAMING_RULES,
      modules: [...NAMING_RULES.modules, 'inventory'],
      module_semantics: {
        ...(NAMING_RULES.module_semantics || {}),
        inventory: ['stock']
      }
    };

    const report = runDomainSymmetryCheck({
      app: 'api',
      repoRoot: sandboxRoot,
      capabilityMap: onboardingCapabilityMap,
      capabilitySchema: CAPABILITY_SCHEMA,
      extensionRegistry: { extensions: [] },
      namingRules: onboardingNamingRules
    });

    assert.equal(report.ok, true, report.errors.join('\n'));
    assert.deepEqual(report.errors, []);
    assert.equal(report.checked_capabilities, 2);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('domain symmetry check internals reject legacy namespace residue references', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'domain-legacy-residue-'));
  try {
    const apiSrcRoot = resolve(sandboxRoot, 'apps/api/src');
    mkdirSync(apiSrcRoot, { recursive: true });
    writeFileSync(
      resolve(apiSrcRoot, 'http-routes.js'),
      "const legacy = require('./modules/platform/org.routes');\n",
      'utf8'
    );

    const errors = [];
    domainSymmetryContract._internals.validateLegacyNamespaceResidue({
      app: 'api',
      repoRoot: sandboxRoot,
      errors
    });

    assert.equal(errors.length, 1);
    assert.match(errors[0], /legacy namespace reference found/);
    assert.match(errors[0], /modules\/platform\//);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('domain symmetry check internals allow tenant config placeholder canonical layout', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'tenant-config-placeholder-ok-'));
  try {
    const domainsRoot = resolve(sandboxRoot, 'apps/web/src/domains');
    mkdirSync(resolve(domainsRoot, 'tenant/config/domain-extension/registry'), { recursive: true });
    writeFileSync(
      resolve(domainsRoot, 'tenant/config/domain-extension/registry/.gitkeep'),
      '',
      'utf8'
    );
    mkdirSync(resolve(sandboxRoot, 'apps/web/src/domains/tenant/settings/workbench'), {
      recursive: true
    });
    writeFileSync(
      resolve(
        sandboxRoot,
        'apps/web/src/domains/tenant/settings/workbench/tenant-management.config.jsx'
      ),
      "export const TENANT_NAV_ITEMS = [{ key: 'settings', children: [{ key: 'settings/users' }] }];\n",
      'utf8'
    );

    const errors = [];
    domainSymmetryContract._internals.validateTenantConfigPlaceholderMode({
      app: 'web',
      repoRoot: sandboxRoot,
      domainsRoot,
      capabilityMap: CAPABILITY_MAP,
      errors
    });

    assert.deepEqual(errors, []);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('domain symmetry check internals reject tenant config placeholder violations', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'tenant-config-placeholder-bad-'));
  try {
    const domainsRoot = resolve(sandboxRoot, 'apps/web/src/domains');
    mkdirSync(resolve(domainsRoot, 'tenant/config/domain-extension/registry'), { recursive: true });
    writeFileSync(
      resolve(domainsRoot, 'tenant/config/domain-extension/registry/.gitkeep'),
      '',
      'utf8'
    );
    mkdirSync(resolve(domainsRoot, 'tenant/config/experimental'), { recursive: true });
    writeFileSync(
      resolve(domainsRoot, 'tenant/config/experimental/feature.js'),
      'export default true;\n',
      'utf8'
    );
    mkdirSync(resolve(sandboxRoot, 'apps/web/src/domains/tenant/settings/workbench'), {
      recursive: true
    });
    writeFileSync(
      resolve(
        sandboxRoot,
        'apps/web/src/domains/tenant/settings/workbench/tenant-management.config.jsx'
      ),
      "const CONFIG_MENU_KEY = 'config';\nexport const TENANT_NAV_ITEMS = [{ key: CONFIG_MENU_KEY }];\n",
      'utf8'
    );

    const errors = [];
    domainSymmetryContract._internals.validateTenantConfigPlaceholderMode({
      app: 'web',
      repoRoot: sandboxRoot,
      domainsRoot,
      capabilityMap: CAPABILITY_MAP,
      errors
    });

    assert.ok(errors.length >= 2);
    assert.match(errors.join('\n'), /placeholder mode allows only domain-extension\/registry/);
    assert.match(errors.join('\n'), /forbids tenant config menu key declaration/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('domain symmetry check internals enforce capability module ownership rules', () => {
  const invalidMap = JSON.parse(JSON.stringify(CAPABILITY_MAP));
  const targetCapability = invalidMap.capabilities.find((capability) =>
    capability.canonical_term === 'user' && capability.module === 'settings'
  );
  assert.ok(targetCapability);
  targetCapability.module = 'auth';

  const errors = [];
  domainSymmetryContract._internals.validateCapabilityModuleOwnership({
    capabilityMap: invalidMap,
    app: 'api',
    errors
  });

  assert.ok(errors.length >= 1);
  assert.match(errors.join('\n'), /violates module ownership/);
  assert.match(errors.join('\n'), /canonical_term=user expects module=settings/);
});

test('domain symmetry check consumes naming-rules forbidden_terms', () => {
  const invalidMap = JSON.parse(JSON.stringify(CAPABILITY_MAP));
  invalidMap.capabilities[0] = {
    ...invalidMap.capabilities[0],
    canonical_term: 'member',
    capability_id: 'platform.settings.member'
  };
  const report = runDomainSymmetryCheck({
    app: 'api',
    repoRoot: REPO_ROOT,
    capabilityMap: invalidMap
  });

  assert.equal(report.ok, false);
  assert.match(report.errors.join('\n'), /uses forbidden term \"member\" in canonical_term/);
});

test('domain symmetry check internals enforce switch-org placement under auth/session', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'switch-org-placement-'));
  try {
    const domainsRoot = resolve(sandboxRoot, 'apps/web/src/domains');
    mkdirSync(resolve(domainsRoot, 'tenant/settings/org-switch'), { recursive: true });
    mkdirSync(resolve(domainsRoot, 'tenant/auth/session/switch-org'), { recursive: true });

    const errors = [];
    domainSymmetryContract._internals.validateSwitchOrgPlacement({
      domainsRoot,
      repoRoot: sandboxRoot,
      errors
    });

    assert.equal(errors.length, 1);
    assert.match(errors[0], /switch-org must be nested under auth\/session/);
    assert.match(errors[0], /tenant\/settings\/org-switch/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('refactor governance check passes for current repository baseline', () => {
  const report = runRefactorGovernanceCheck({
    repoRoot: REPO_ROOT,
    changedFiles: []
  });

  assert.equal(report.ok, true, report.errors.join('\n'));
  assert.deepEqual(report.errors, []);
});

test('refactor governance check blocks milestone progression when previous stage is unfinished', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'refactor-governance-milestone-'));
  try {
    const artifactsRoot = resolve(sandboxRoot, '_bmad-output/implementation-artifacts');
    mkdirSync(artifactsRoot, { recursive: true });
    const specPath = resolve(artifactsRoot, 'tech-spec.md');
    const milestonesPath = resolve(artifactsRoot, 'refactor-milestones.yaml');
    const diffRegisterPath = resolve(artifactsRoot, 'spec-diff-register.json');
    const reviewRecordPath = resolve(artifactsRoot, 'refactor-review-record.json');

    writeFileSync(
      specPath,
      '- [x] Task 1: sample task\n- [ ] Task 2: sample task\n- [x] AC 1: sample acceptance criterion\n',
      'utf8'
    );
    writeFileSync(
      milestonesPath,
      [
        'scope_freeze:',
        '  enabled: true',
        'milestones:',
        '  - id: M1',
        '    tasks:',
        '      - 1',
        '    status: pending',
        '  - id: M2',
        '    tasks:',
        '      - 2',
        '    status: in-progress',
        ''
      ].join('\n'),
      'utf8'
    );
    writeFileSync(diffRegisterPath, JSON.stringify({ entries: [] }, null, 2), 'utf8');
    writeFileSync(
      reviewRecordPath,
      JSON.stringify(
        {
          reviews: [
            {
              task_id: 1,
              best_practice_status: 'pass',
              minimal_change_fallback: false,
              reviewer: 'reviewer-a',
              reviewed_at: '2026-02-25',
              related_ac: [1]
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );

    const report = runRefactorGovernanceCheck({
      repoRoot: sandboxRoot,
      specPath,
      milestonesPath,
      diffRegisterPath,
      reviewRecordPath
    });

    assert.equal(report.ok, false);
    assert.match(report.errors.join('\n'), /cannot start before M1 is completed/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('refactor governance check blocks accepted diff without signed justification record', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'refactor-governance-diff-'));
  try {
    const artifactsRoot = resolve(sandboxRoot, '_bmad-output/implementation-artifacts');
    mkdirSync(artifactsRoot, { recursive: true });
    const specPath = resolve(artifactsRoot, 'tech-spec.md');
    const milestonesPath = resolve(artifactsRoot, 'refactor-milestones.yaml');
    const diffRegisterPath = resolve(artifactsRoot, 'spec-diff-register.json');
    const reviewRecordPath = resolve(artifactsRoot, 'refactor-review-record.json');

    writeFileSync(
      specPath,
      '- [x] Task 1: sample task\n- [x] AC 1: sample acceptance criterion\n',
      'utf8'
    );
    writeFileSync(
      milestonesPath,
      [
        'scope_freeze:',
        '  enabled: true',
        'milestones:',
        '  - id: M1',
        '    tasks:',
        '      - 1',
        '    status: completed',
        ''
      ].join('\n'),
      'utf8'
    );
    writeFileSync(
      diffRegisterPath,
      JSON.stringify(
        {
          entries: [
            {
              change_id: '20260225-001',
              status: 'accepted',
              justification_file: 'docs/spec-diff-justifications/20260225-001.md',
              affected_files: ['apps/api/test/contracts/platform.route-manifest.snapshot.json'],
              responsible_engineer: 'platform-tenant-refactor',
              reviewer: 'architecture-reviewer',
              signed_at: '2026-02-25'
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );
    writeFileSync(
      reviewRecordPath,
      JSON.stringify(
        {
          reviews: [
            {
              task_id: 1,
              best_practice_status: 'pass',
              minimal_change_fallback: false,
              reviewer: 'reviewer-a',
              reviewed_at: '2026-02-25',
              related_ac: [1]
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );

    const report = runRefactorGovernanceCheck({
      repoRoot: sandboxRoot,
      specPath,
      milestonesPath,
      diffRegisterPath,
      reviewRecordPath
    });

    assert.equal(report.ok, false);
    assert.match(report.errors.join('\n'), /missing spec diff justification file/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('refactor governance check blocks checked task with minimal-change fallback review', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'refactor-governance-review-'));
  try {
    const artifactsRoot = resolve(sandboxRoot, '_bmad-output/implementation-artifacts');
    mkdirSync(artifactsRoot, { recursive: true });
    const specPath = resolve(artifactsRoot, 'tech-spec.md');
    const milestonesPath = resolve(artifactsRoot, 'refactor-milestones.yaml');
    const diffRegisterPath = resolve(artifactsRoot, 'spec-diff-register.json');
    const reviewRecordPath = resolve(artifactsRoot, 'refactor-review-record.json');

    writeFileSync(
      specPath,
      '- [x] Task 1: sample task\n- [x] AC 1: sample acceptance criterion\n',
      'utf8'
    );
    writeFileSync(
      milestonesPath,
      [
        'scope_freeze:',
        '  enabled: true',
        'milestones:',
        '  - id: M1',
        '    tasks:',
        '      - 1',
        '    status: completed',
        ''
      ].join('\n'),
      'utf8'
    );
    writeFileSync(diffRegisterPath, JSON.stringify({ entries: [] }, null, 2), 'utf8');
    writeFileSync(
      reviewRecordPath,
      JSON.stringify(
        {
          reviews: [
            {
              task_id: 1,
              best_practice_status: 'pass',
              minimal_change_fallback: true,
              reviewer: 'reviewer-a',
              reviewed_at: '2026-02-25',
              related_ac: [1]
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );

    const report = runRefactorGovernanceCheck({
      repoRoot: sandboxRoot,
      specPath,
      milestonesPath,
      diffRegisterPath,
      reviewRecordPath
    });

    assert.equal(report.ok, false);
    assert.match(report.errors.join('\n'), /cannot use minimal_change_fallback/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('refactor governance check blocks checked task without AC traceability mapping', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'refactor-governance-traceability-'));
  try {
    const artifactsRoot = resolve(sandboxRoot, '_bmad-output/implementation-artifacts');
    mkdirSync(artifactsRoot, { recursive: true });
    const specPath = resolve(artifactsRoot, 'tech-spec.md');
    const milestonesPath = resolve(artifactsRoot, 'refactor-milestones.yaml');
    const diffRegisterPath = resolve(artifactsRoot, 'spec-diff-register.json');
    const reviewRecordPath = resolve(artifactsRoot, 'refactor-review-record.json');

    writeFileSync(
      specPath,
      '- [x] Task 1: sample task\n- [x] AC 1: sample acceptance criterion\n',
      'utf8'
    );
    writeFileSync(
      milestonesPath,
      [
        'scope_freeze:',
        '  enabled: true',
        'milestones:',
        '  - id: M1',
        '    tasks:',
        '      - 1',
        '    status: completed',
        ''
      ].join('\n'),
      'utf8'
    );
    writeFileSync(diffRegisterPath, JSON.stringify({ entries: [] }, null, 2), 'utf8');
    writeFileSync(
      reviewRecordPath,
      JSON.stringify(
        {
          reviews: [
            {
              task_id: 1,
              best_practice_status: 'pass',
              minimal_change_fallback: false,
              reviewer: 'reviewer-a',
              reviewed_at: '2026-02-25'
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );

    const report = runRefactorGovernanceCheck({
      repoRoot: sandboxRoot,
      specPath,
      milestonesPath,
      diffRegisterPath,
      reviewRecordPath
    });

    assert.equal(report.ok, false);
    assert.match(report.errors.join('\n'), /must map to at least one AC/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('refactor governance check blocks changed governed baseline without accepted diff coverage', () => {
  const sandboxRoot = mkdtempSync(join(tmpdir(), 'refactor-governance-baseline-trigger-'));
  try {
    const artifactsRoot = resolve(sandboxRoot, '_bmad-output/implementation-artifacts');
    mkdirSync(artifactsRoot, { recursive: true });
    const specPath = resolve(artifactsRoot, 'tech-spec.md');
    const milestonesPath = resolve(artifactsRoot, 'refactor-milestones.yaml');
    const diffRegisterPath = resolve(artifactsRoot, 'spec-diff-register.json');
    const reviewRecordPath = resolve(artifactsRoot, 'refactor-review-record.json');

    writeFileSync(
      specPath,
      '- [x] Task 1: sample task\n- [x] AC 1: sample acceptance criterion\n',
      'utf8'
    );
    writeFileSync(
      milestonesPath,
      [
        'scope_freeze:',
        '  enabled: true',
        'milestones:',
        '  - id: M1',
        '    tasks:',
        '      - 1',
        '    status: completed',
        ''
      ].join('\n'),
      'utf8'
    );
    writeFileSync(diffRegisterPath, JSON.stringify({ entries: [] }, null, 2), 'utf8');
    writeFileSync(
      reviewRecordPath,
      JSON.stringify(
        {
          reviews: [
            {
              task_id: 1,
              best_practice_status: 'pass',
              minimal_change_fallback: false,
              reviewer: 'reviewer-a',
              reviewed_at: '2026-02-25',
              related_ac: [1]
            }
          ]
        },
        null,
        2
      ),
      'utf8'
    );

    const report = runRefactorGovernanceCheck({
      repoRoot: sandboxRoot,
      specPath,
      milestonesPath,
      diffRegisterPath,
      reviewRecordPath,
      changedFiles: ['apps/api/test/contracts/platform.route-manifest.snapshot.json']
    });

    assert.equal(report.ok, false);
    assert.match(report.errors.join('\n'), /governed snapshot\/baseline files changed without accepted diff record/);
  } finally {
    rmSync(sandboxRoot, { recursive: true, force: true });
  }
});

test('no-cross-domain-imports blocks platform to tenant direct import', () => {
  const issues = crossDomainRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/index.js',
    content: "const tenantUser = require('../../../tenant/settings/user');"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /cross-domain import is not allowed/);
});

test('no-cross-domain-imports supports explicit allowlist entries', () => {
  const issues = crossDomainRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/index.js',
    content: "const tenantUser = require('../../../tenant/settings/user');",
    crossDomainAllowlist: [
      {
        from_domain: 'platform',
        to_domain: 'tenant',
        specifier_regex: '^\\.\\.\\/\\.\\.\\/\\.\\.\\/tenant\\/settings\\/user$'
      }
    ]
  });

  assert.deepEqual(issues, []);
});

test('no-domain-deep-imports blocks external deep domain path usage', () => {
  const issues = domainDeepImportRule.checkFile({
    filePath: '/repo/apps/api/src/http-routes.js',
    content: "const userCapability = require('./domains/platform/settings/user');"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /domain deep import is blocked/);
});

test('no-domain-deep-imports blocks deep domain re-export usage', () => {
  const issues = domainDeepImportRule.checkFile({
    filePath: '/repo/apps/api/src/http-routes.js',
    content: "export * from './domains/platform/settings/user';"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /domain deep import is blocked/);
});

test('no-domain-deep-imports allows domain public API imports', () => {
  const issues = domainDeepImportRule.checkFile({
    filePath: '/repo/apps/api/src/http-routes.js',
    content: "const platformDomain = require('./domains/platform');"
  });

  assert.deepEqual(issues, []);
});

test('AST-based domain import rule ignores plain strings that look like imports', () => {
  const issues = domainDeepImportRule.checkFile({
    filePath: '/repo/apps/api/src/http-routes.js',
    content: "const sample = \"require('./domains/platform/settings/user')\";"
  });

  assert.deepEqual(issues, []);
});

test('no-domain-deep-imports ignores external package imports with domains segment', () => {
  const issues = domainDeepImportRule.checkFile({
    filePath: '/repo/apps/api/src/http-routes.js',
    content: "const sdk = require('@vendor/domains/platform/settings/user');"
  });

  assert.deepEqual(issues, []);
});

test('no-domain-deep-imports blocks src alias deep domain imports', () => {
  const issues = domainDeepImportRule.checkFile({
    filePath: '/repo/apps/api/src/http-routes.js',
    content: "import userCapability from 'src/domains/platform/settings/user';"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /domain deep import is blocked/);
});

test('no-domain-module-constants-imports blocks src direct module constants imports', () => {
  const issues = domainModuleConstantsImportRule.checkFile({
    filePath: '/repo/apps/api/src/server.js',
    content: "const { PLATFORM_ORG_LIST_PATH } = require('./modules/platform/org.constants');"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /modules\/platform\/\*\.constants is blocked/);
});

test('no-domain-module-constants-imports allows domain internal constants bridge', () => {
  const issues = domainModuleConstantsImportRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/index.js',
    content: "const orgConstants = require('../../modules/platform/org.constants');"
  });

  assert.deepEqual(issues, []);
});

test('no-domain-module-constants-imports allows modules internal constants usage', () => {
  const issues = domainModuleConstantsImportRule.checkFile({
    filePath: '/repo/apps/api/src/modules/platform/org.routes.js',
    content: "const orgConstants = require('./org.constants');"
  });

  assert.deepEqual(issues, []);
});

test('no-domain-api-client-direct-imports blocks web feature direct client import', () => {
  const issues = domainApiClientImportRule.checkFile({
    filePath: '/repo/apps/web/src/features/platform-management/pages/PlatformUserManagementPage.jsx',
    content:
      "import { createPlatformManagementApi } from '../../../api/platform-management.mjs';"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /direct api client import is blocked/);
});

test('no-domain-api-client-direct-imports allows domain index import in web features', () => {
  const issues = domainApiClientImportRule.checkFile({
    filePath: '/repo/apps/web/src/features/platform-management/pages/PlatformUserManagementPage.jsx',
    content:
      "import { createPlatformManagementApi } from '../../../domains/platform/index.mjs';"
  });

  assert.deepEqual(issues, []);
});

test('file-granularity-thresholds blocks oversized domain capability files', () => {
  const issues = fileGranularityRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/service.js',
    content: `${'const x = 1;\n'.repeat(820)}module.exports = { x };`
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /file too large/);
});

test('file-granularity-thresholds blocks over-fragmented domain capability files', () => {
  const issues = fileGranularityRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/settings/user/service.js',
    content: "const value = 1;\nmodule.exports = { value };"
  });

  assert.equal(issues.length, 1);
  assert.match(issues[0], /over-fragmented/);
});

test('file-granularity-thresholds ignores domain route adapter files', () => {
  const issues = fileGranularityRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/config/system-config/system-config.routes.js',
    content: "const value = 1;\nmodule.exports = { value };"
  });

  assert.deepEqual(issues, []);
});

test('file-granularity-thresholds ignores domain runtime composition files', () => {
  const issues = fileGranularityRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/runtime/platform.runtime.js',
    content: "const value = 1;\nmodule.exports = { value };"
  });

  assert.deepEqual(issues, []);
});

test('file-granularity-thresholds ignores domain index files', () => {
  const issues = fileGranularityRule.checkFile({
    filePath: '/repo/apps/api/src/domains/platform/index.js',
    content: "module.exports = { platform: true };"
  });

  assert.deepEqual(issues, []);
});

test('domain contract guard runs capability-boundary checker', () => {
  const { runCapabilityBoundaryCheck } = require('../../../tools/domain-contract/check-capability-boundaries');
  const result = runCapabilityBoundaryCheck({ repoRoot: REPO_ROOT });
  assert.equal(result.ok, true, result.errors.join('\n'));
});

test('domain contract guard runs layer-responsibility checker', () => {
  const { runLayerResponsibilityCheck } = require('../../../tools/domain-contract/check-layer-responsibilities');
  const result = runLayerResponsibilityCheck({ repoRoot: REPO_ROOT });
  assert.equal(result.ok, true, result.errors.join('\n'));
});
