#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

const DOMAIN_SET = new Set(['platform', 'tenant']);
const DEFAULT_MODULE_SET = new Set(['settings', 'config', 'auth']);
const MODULE_NAME_RE = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const APP_SET = new Set(['api', 'web']);
const SYMMETRY_SET = new Set(['required', 'extension', 'placeholder']);
const SOURCE_EXTENSION_SET = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);
const IGNORED_SCAN_DIRECTORIES = new Set([
  'node_modules',
  'dist',
  '.next',
  'coverage'
]);
const LEGACY_NAMESPACE_PATTERNS_BY_APP = Object.freeze({
  api: ['modules/platform/', 'modules/tenant/'],
  web: ['features/platform-management/', 'features/tenant-management/']
});
const LEGACY_NAMESPACE_DIRECTORIES_BY_APP = Object.freeze({
  api: ['apps/api/src/modules/platform', 'apps/api/src/modules/tenant'],
  web: ['apps/web/src/features/platform-management', 'apps/web/src/features/tenant-management']
});
const DOMAIN_TOP_LEVEL_BUILTIN_DIRECTORIES_BY_APP = Object.freeze({
  api: new Set(['runtime']),
  web: new Set([])
});
const TENANT_CONFIG_PLACEHOLDER_ALLOWED_DIRECTORIES = new Set([
  '',
  'domain-extension',
  'domain-extension/registry'
]);
const TENANT_CONFIG_PLACEHOLDER_ALLOWED_FILES = new Set([
  '.gitkeep',
  '.gitignore'
]);
const TENANT_CONFIG_FORBIDDEN_FRONTEND_PATTERNS = [
  '/tenant/config',
  'tenant-menu-config',
  'tenant-tab-config'
];
const DEFAULT_MODULE_SEMANTICS = Object.freeze({
  settings: ['user', 'role', 'org'],
  config: ['password-policy', 'system-config', 'integration', 'domain-extension-registry'],
  auth: ['session', 'context', 'provisioning']
});
const DEFAULT_CAPABILITY_ID_TEMPLATE = '{domain}.{module}.{canonical_term}';
const PUBLIC_API_FILES = [
  'index.js',
  'index.mjs',
  'index.cjs',
  'index.ts',
  'index.tsx',
  'index.jsx'
];

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function readJson(filePath, errors) {
  try {
    const raw = fs.readFileSync(filePath, 'utf8');
    return JSON.parse(raw);
  } catch (error) {
    errors.push(`failed to read JSON ${filePath}: ${error.message}`);
    return null;
  }
}

function isDirectory(targetPath) {
  try {
    return fs.statSync(targetPath).isDirectory();
  } catch (_error) {
    return false;
  }
}

function isFile(targetPath) {
  try {
    return fs.statSync(targetPath).isFile();
  } catch (_error) {
    return false;
  }
}

function toRelativePath(repoRoot, targetPath) {
  return toPosix(path.relative(repoRoot, targetPath));
}

function isValidModuleName(value) {
  return MODULE_NAME_RE.test(String(value || '').trim());
}

function toNonEmptyLowerCase(value) {
  const normalized = String(value || '').trim().toLowerCase();
  return normalized.length > 0 ? normalized : '';
}

function normalizeNamingRules(namingRules, errors) {
  const normalized = {
    modules: new Set(DEFAULT_MODULE_SET),
    forbiddenTerms: new Set(),
    canonicalTermRegex: /^[a-z0-9]+(?:-[a-z0-9]+)*$/,
    capabilityPathRegex: /^[a-z0-9-]+(?:\/[a-z0-9-]+)*$/,
    capabilityIdTemplate: DEFAULT_CAPABILITY_ID_TEMPLATE,
    moduleSemantics: new Map()
  };

  if (!namingRules || typeof namingRules !== 'object') {
    errors.push('naming rules must be a JSON object');
    return normalized;
  }

  if (Array.isArray(namingRules.modules) && namingRules.modules.length > 0) {
    const modules = new Set();
    for (const moduleName of namingRules.modules) {
      if (!isValidModuleName(moduleName)) {
        errors.push(`naming rules modules contains invalid module name: ${moduleName}`);
        continue;
      }
      modules.add(String(moduleName).trim());
    }
    if (modules.size > 0) {
      normalized.modules = modules;
    }
  }

  const rules = namingRules.rules && typeof namingRules.rules === 'object'
    ? namingRules.rules
    : {};

  if (typeof rules.canonical_term_regex === 'string' && rules.canonical_term_regex.trim()) {
    try {
      normalized.canonicalTermRegex = new RegExp(rules.canonical_term_regex);
    } catch (error) {
      errors.push(`invalid canonical_term_regex in naming rules: ${error.message}`);
    }
  }

  if (typeof rules.capability_path_regex === 'string' && rules.capability_path_regex.trim()) {
    try {
      normalized.capabilityPathRegex = new RegExp(rules.capability_path_regex);
    } catch (error) {
      errors.push(`invalid capability_path_regex in naming rules: ${error.message}`);
    }
  }

  if (typeof rules.capability_id === 'string' && rules.capability_id.trim()) {
    normalized.capabilityIdTemplate = rules.capability_id.trim();
  }

  if (Array.isArray(rules.forbidden_terms)) {
    for (const term of rules.forbidden_terms) {
      const normalizedTerm = toNonEmptyLowerCase(term);
      if (normalizedTerm) {
        normalized.forbiddenTerms.add(normalizedTerm);
      }
    }
  }

  if (namingRules.module_semantics && typeof namingRules.module_semantics === 'object') {
    for (const [moduleName, terms] of Object.entries(namingRules.module_semantics)) {
      if (!isValidModuleName(moduleName)) {
        errors.push(`module_semantics contains invalid module key: ${moduleName}`);
        continue;
      }
      if (!Array.isArray(terms)) {
        errors.push(`module_semantics.${moduleName} must be an array`);
        continue;
      }
      const normalizedTerms = new Set();
      for (const term of terms) {
        const normalizedTerm = toNonEmptyLowerCase(term);
        if (!normalizedTerm) {
          continue;
        }
        if (!normalized.canonicalTermRegex.test(normalizedTerm)) {
          errors.push(
            `module_semantics.${moduleName} contains invalid canonical term: ${term}`
          );
          continue;
        }
        normalizedTerms.add(normalizedTerm);
      }
      normalized.moduleSemantics.set(moduleName, normalizedTerms);
    }
  }

  return normalized;
}

function collectConfiguredModules(capabilityMap, app, namingRulesConfig) {
  const modules = new Set(
    namingRulesConfig && namingRulesConfig.modules
      ? namingRulesConfig.modules
      : DEFAULT_MODULE_SET
  );
  if (!capabilityMap || !Array.isArray(capabilityMap.capabilities)) {
    return modules;
  }

  for (const capability of capabilityMap.capabilities) {
    if (!isCapabilityEnabledForApp(capability, app)) {
      continue;
    }
    const moduleName = String(capability.module || '').trim();
    if (!isValidModuleName(moduleName)) {
      continue;
    }
    modules.add(moduleName);
  }
  return modules;
}

function resolveAllowedTopLevelDirectories({ app, capabilityMap, namingRulesConfig }) {
  const allowedDirectories = collectConfiguredModules(capabilityMap, app, namingRulesConfig);
  const builtinDirectories = DOMAIN_TOP_LEVEL_BUILTIN_DIRECTORIES_BY_APP[app] || new Set();
  for (const directoryName of builtinDirectories) {
    allowedDirectories.add(directoryName);
  }
  return allowedDirectories;
}

function formatCapabilityIdFromTemplate(template, capability) {
  const rawTemplate = String(template || DEFAULT_CAPABILITY_ID_TEMPLATE);
  return rawTemplate
    .replaceAll('{domain}', String(capability.domain || '').trim())
    .replaceAll('{module}', String(capability.module || '').trim())
    .replaceAll('{canonical_term}', String(capability.canonical_term || '').trim());
}

function tokenizeName(value) {
  return String(value || '')
    .toLowerCase()
    .split(/[./\-_]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function validateForbiddenTerm({
  value,
  fieldName,
  capabilityId,
  forbiddenTerms,
  errors
}) {
  if (!forbiddenTerms || forbiddenTerms.size === 0) {
    return;
  }
  const tokens = tokenizeName(value);
  for (const token of tokens) {
    if (!forbiddenTerms.has(token)) {
      continue;
    }
    errors.push(
      `capability ${capabilityId || '(unknown)'} uses forbidden term "${token}" in ${fieldName}`
    );
  }
}

function validateForbiddenTermsInDomainPaths({
  domainsRoot,
  repoRoot,
  forbiddenTerms,
  errors
}) {
  if (!forbiddenTerms || forbiddenTerms.size === 0) {
    return;
  }
  if (!isDirectory(domainsRoot)) {
    return;
  }

  const directoriesToVisit = [domainsRoot];
  while (directoriesToVisit.length > 0) {
    const currentDirectory = directoriesToVisit.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(currentDirectory, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const absoluteEntryPath = path.join(currentDirectory, entry.name);
      directoriesToVisit.push(absoluteEntryPath);

      const tokens = tokenizeName(entry.name);
      const forbiddenToken = tokens.find((token) => forbiddenTerms.has(token));
      if (!forbiddenToken) {
        continue;
      }
      errors.push(
        `directory name uses forbidden term "${forbiddenToken}": ${toRelativePath(repoRoot, absoluteEntryPath)}`
      );
    }
  }
}

function resolveCanonicalTermOwnership(namingRulesConfig, errors) {
  const sourceModuleSemantics = (
    namingRulesConfig
    && namingRulesConfig.moduleSemantics instanceof Map
    && namingRulesConfig.moduleSemantics.size > 0
  )
    ? namingRulesConfig.moduleSemantics
    : new Map(
        Object.entries(DEFAULT_MODULE_SEMANTICS).map(([moduleName, terms]) => [
          moduleName,
          new Set(terms)
        ])
      );
  const ownershipMap = new Map();
  for (const [moduleName, terms] of sourceModuleSemantics.entries()) {
    for (const canonicalTerm of terms) {
      const previousOwner = ownershipMap.get(canonicalTerm);
      if (previousOwner && previousOwner !== moduleName) {
        errors.push(
          `module_semantics canonical term "${canonicalTerm}" is assigned to multiple modules: ${previousOwner}, ${moduleName}`
        );
        continue;
      }
      ownershipMap.set(canonicalTerm, moduleName);
    }
  }
  return ownershipMap;
}

function collectSourceFiles(rootDirectory) {
  const files = [];
  if (!isDirectory(rootDirectory)) {
    return files;
  }

  const stack = [rootDirectory];
  while (stack.length > 0) {
    const currentDirectory = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(currentDirectory, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    for (const entry of entries) {
      const absoluteEntryPath = path.join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        if (IGNORED_SCAN_DIRECTORIES.has(entry.name)) {
          continue;
        }
        stack.push(absoluteEntryPath);
        continue;
      }

      if (!entry.isFile()) {
        continue;
      }
      if (!SOURCE_EXTENSION_SET.has(path.extname(entry.name))) {
        continue;
      }
      files.push(absoluteEntryPath);
    }
  }

  return files;
}

function isCapabilityEnabledForApp(capability, app) {
  return (
    capability
    && Array.isArray(capability.applications)
    && capability.applications.includes(app)
  );
}

function isTenantConfigPlaceholderMode(capabilityMap, app) {
  if (!capabilityMap || !Array.isArray(capabilityMap.capabilities)) {
    return false;
  }

  const tenantConfigCapabilities = capabilityMap.capabilities.filter((capability) =>
    capability.domain === 'tenant'
    && capability.module === 'config'
    && isCapabilityEnabledForApp(capability, app)
  );
  if (tenantConfigCapabilities.length === 0) {
    return false;
  }

  const hasRegistryPlaceholder = tenantConfigCapabilities.some((capability) =>
    String(capability.capability || '').trim() === 'domain-extension/registry'
  );
  const allPlaceholder = tenantConfigCapabilities.every((capability) =>
    capability.symmetry === 'placeholder'
  );
  return hasRegistryPlaceholder && allPlaceholder;
}

function validateTenantConfigPlaceholderMode({
  app,
  repoRoot,
  domainsRoot,
  capabilityMap,
  errors
}) {
  if (!isTenantConfigPlaceholderMode(capabilityMap, app)) {
    return;
  }

  const tenantConfigRoot = path.join(domainsRoot, 'tenant', 'config');
  if (!isDirectory(tenantConfigRoot)) {
    errors.push(
      `tenant config placeholder mode requires directory: ${toRelativePath(repoRoot, tenantConfigRoot)}`
    );
    return;
  }

  const directoriesToVisit = [tenantConfigRoot];
  let hasRegistryDirectory = false;
  while (directoriesToVisit.length > 0) {
    const currentDirectory = directoriesToVisit.pop();
    const relativeDirectoryPath = toPosix(path.relative(tenantConfigRoot, currentDirectory));
    const normalizedRelativeDirectoryPath = relativeDirectoryPath === '.' ? '' : relativeDirectoryPath;

    if (!TENANT_CONFIG_PLACEHOLDER_ALLOWED_DIRECTORIES.has(normalizedRelativeDirectoryPath)) {
      errors.push(
        `tenant config placeholder mode allows only domain-extension/registry: ${toRelativePath(repoRoot, currentDirectory)}`
      );
    }
    if (normalizedRelativeDirectoryPath === 'domain-extension/registry') {
      hasRegistryDirectory = true;
    }

    let entries = [];
    try {
      entries = fs.readdirSync(currentDirectory, { withFileTypes: true });
    } catch (error) {
      errors.push(`failed to read tenant config directory ${toPosix(currentDirectory)}: ${error.message}`);
      continue;
    }

    for (const entry of entries) {
      const absoluteEntryPath = path.join(currentDirectory, entry.name);
      if (entry.isDirectory()) {
        directoriesToVisit.push(absoluteEntryPath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }

      const relativeFilePath = toPosix(path.relative(tenantConfigRoot, absoluteEntryPath));
      const parentDirectory = toPosix(path.dirname(relativeFilePath));
      const normalizedParentDirectory = parentDirectory === '.' ? '' : parentDirectory;
      if (!TENANT_CONFIG_PLACEHOLDER_ALLOWED_DIRECTORIES.has(normalizedParentDirectory)) {
        errors.push(
          `tenant config placeholder mode file parent is invalid: ${toRelativePath(repoRoot, absoluteEntryPath)}`
        );
      }
      if (!TENANT_CONFIG_PLACEHOLDER_ALLOWED_FILES.has(entry.name)) {
        errors.push(
          `tenant config placeholder mode allows only ${[...TENANT_CONFIG_PLACEHOLDER_ALLOWED_FILES].join(', ')} files: ${toRelativePath(repoRoot, absoluteEntryPath)}`
        );
      }
    }
  }

  if (!hasRegistryDirectory) {
    errors.push(
      `tenant config placeholder mode requires domain-extension/registry directory: ${toRelativePath(repoRoot, path.join(tenantConfigRoot, 'domain-extension/registry'))}`
    );
  }

  if (app === 'api') {
    const apiSourceFiles = collectSourceFiles(path.join(repoRoot, 'apps/api/src'));
    for (const sourceFile of apiSourceFiles) {
      let content = '';
      try {
        content = fs.readFileSync(sourceFile, 'utf8');
      } catch (_error) {
        continue;
      }
      if (content.includes('/tenant/config')) {
        errors.push(
          `tenant config placeholder mode forbids API route exposure: ${toRelativePath(repoRoot, sourceFile)}`
        );
      }
    }
    return;
  }

  if (app !== 'web') {
    return;
  }

  const webSourceFiles = collectSourceFiles(path.join(repoRoot, 'apps/web/src'));
  for (const sourceFile of webSourceFiles) {
    let content = '';
    try {
      content = fs.readFileSync(sourceFile, 'utf8');
    } catch (_error) {
      continue;
    }

    for (const pattern of TENANT_CONFIG_FORBIDDEN_FRONTEND_PATTERNS) {
      if (!content.includes(pattern)) {
        continue;
      }
      errors.push(
        `tenant config placeholder mode forbids frontend tenant config menu/route marker (${pattern}): ${toRelativePath(repoRoot, sourceFile)}`
      );
    }
  }

  const tenantMenuConfigPath = path.join(
    repoRoot,
    'apps/web/src/domains/tenant/settings/workbench/tenant-management.config.jsx'
  );
  if (!isFile(tenantMenuConfigPath)) {
    return;
  }

  let tenantMenuConfigContent = '';
  try {
    tenantMenuConfigContent = fs.readFileSync(tenantMenuConfigPath, 'utf8');
  } catch (_error) {
    return;
  }

  const forbiddenMenuKeyPatterns = [
    /const\s+[A-Z0-9_]*CONFIG[A-Z0-9_]*\s*=\s*['"`]/,
    /key:\s*['"`]config(?:\/[^'"`]+)?['"`]/,
    /['"`]settings\/config(?:\/[^'"`]+)?['"`]/
  ];
  for (const pattern of forbiddenMenuKeyPatterns) {
    if (!pattern.test(tenantMenuConfigContent)) {
      continue;
    }
    errors.push(
      `tenant config placeholder mode forbids tenant config menu key declaration: ${toRelativePath(repoRoot, tenantMenuConfigPath)}`
    );
    break;
  }
}

function validateCapabilityModuleOwnership({
  capabilityMap,
  namingRulesConfig,
  app,
  errors
}) {
  if (!capabilityMap || !Array.isArray(capabilityMap.capabilities)) {
    return;
  }
  const canonicalTermOwnership = resolveCanonicalTermOwnership(namingRulesConfig, errors);
  if (canonicalTermOwnership.size === 0) {
    return;
  }

  for (const capability of capabilityMap.capabilities) {
    if (!isCapabilityEnabledForApp(capability, app)) {
      continue;
    }

    const canonicalTerm = String(capability.canonical_term || '').trim();
    const expectedModule = canonicalTermOwnership.get(canonicalTerm);
    if (!expectedModule) {
      continue;
    }

    if (String(capability.module || '').trim() !== expectedModule) {
      errors.push(
        `capability ${capability.capability_id} violates module ownership: canonical_term=${canonicalTerm} expects module=${expectedModule}`
      );
    }
  }
}

function validateSwitchOrgPlacement({
  domainsRoot,
  repoRoot,
  errors
}) {
  if (!isDirectory(domainsRoot)) {
    return;
  }

  const directoriesToVisit = [domainsRoot];
  while (directoriesToVisit.length > 0) {
    const currentDirectory = directoriesToVisit.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(currentDirectory, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }

      const absoluteEntryPath = path.join(currentDirectory, entry.name);
      directoriesToVisit.push(absoluteEntryPath);

      const normalizedPath = toPosix(absoluteEntryPath);
      const pathSegments = normalizedPath.split('/').filter(Boolean);
      const switchOrgSegmentIndex = pathSegments.findIndex((segment) =>
        segment === 'switch-org' || segment === 'org-switch'
      );
      if (switchOrgSegmentIndex === -1) {
        continue;
      }

      const hasAuthSessionParent =
        switchOrgSegmentIndex >= 2
        && pathSegments[switchOrgSegmentIndex - 2] === 'auth'
        && pathSegments[switchOrgSegmentIndex - 1] === 'session';
      if (hasAuthSessionParent) {
        continue;
      }

      errors.push(
        `switch-org must be nested under auth/session: ${toRelativePath(repoRoot, absoluteEntryPath)}`
      );
    }
  }
}

function hasDomainPublicApi(domainDirectory) {
  for (const fileName of PUBLIC_API_FILES) {
    const candidate = path.join(domainDirectory, fileName);
    if (isFile(candidate)) {
      return true;
    }
  }
  return false;
}

function validateDomainTopLevelDirectoryShape({
  app,
  domainsRoot,
  capabilityMap,
  namingRulesConfig,
  repoRoot,
  errors
}) {
  const allowedTopLevelDirectories = resolveAllowedTopLevelDirectories({
    app,
    capabilityMap,
    namingRulesConfig
  });

  for (const domain of DOMAIN_SET) {
    const domainDirectory = path.join(domainsRoot, domain);
    if (!isDirectory(domainDirectory)) {
      continue;
    }

    let entries = [];
    try {
      entries = fs.readdirSync(domainDirectory, { withFileTypes: true });
    } catch (error) {
      errors.push(`failed to read domain directory ${toPosix(domainDirectory)}: ${error.message}`);
      continue;
    }

    for (const entry of entries) {
      if (!entry.isDirectory()) {
        continue;
      }
      const childDirectoryName = String(entry.name || '').trim();
      if (!childDirectoryName || childDirectoryName.startsWith('.')) {
        continue;
      }
      if (allowedTopLevelDirectories.has(childDirectoryName)) {
        continue;
      }

      const absoluteChildPath = path.join(domainDirectory, childDirectoryName);
      const relativeChildPath = toRelativePath(repoRoot, absoluteChildPath);
      errors.push(
        `invalid domain top-level directory (${relativeChildPath}). capability directories must be nested as domains/{domain}/{module}/{capability}`
      );
    }
  }
}

function validateLegacyNamespaceResidue({
  app,
  repoRoot,
  errors
}) {
  const legacyDirectories = LEGACY_NAMESPACE_DIRECTORIES_BY_APP[app] || [];
  for (const relativeDirectory of legacyDirectories) {
    const absoluteDirectory = path.join(repoRoot, relativeDirectory);
    if (isDirectory(absoluteDirectory)) {
      errors.push(
        `legacy namespace directory still exists: ${toRelativePath(repoRoot, absoluteDirectory)}`
      );
    }
  }

  const srcRoot = path.join(
    repoRoot,
    app === 'api' ? 'apps/api/src' : 'apps/web/src'
  );
  const legacyPatterns = LEGACY_NAMESPACE_PATTERNS_BY_APP[app] || [];
  if (legacyPatterns.length === 0) {
    return;
  }

  for (const sourceFile of collectSourceFiles(srcRoot)) {
    let content = '';
    try {
      content = fs.readFileSync(sourceFile, 'utf8');
    } catch (_error) {
      continue;
    }

    for (const pattern of legacyPatterns) {
      if (!content.includes(pattern)) {
        continue;
      }
      errors.push(
        `legacy namespace reference found in ${toRelativePath(repoRoot, sourceFile)}: ${pattern}`
      );
    }
  }
}

function validateDate(value) {
  return /^\d{4}-\d{2}-\d{2}$/.test(String(value));
}

function validateSchemaAlignment(map, schema, errors) {
  if (!map || typeof map !== 'object') {
    errors.push('capability map must be a JSON object');
    return;
  }

  if (!schema || typeof schema !== 'object') {
    errors.push('capability schema must be a JSON object');
    return;
  }

  const expectedVersion = schema.properties && schema.properties.schema_version
    ? schema.properties.schema_version.const
    : null;
  if (expectedVersion && map.schema_version !== expectedVersion) {
    errors.push(
      `schema_version mismatch: expected ${expectedVersion}, received ${map.schema_version || '(missing)'}`
    );
  }

  if (!Array.isArray(map.capabilities)) {
    errors.push('capability map must include a capabilities array');
  }
}

function validateCapabilityRecord({
  capability,
  requiredFields,
  namingRulesConfig,
  errors,
  index
}) {
  for (const fieldName of requiredFields) {
    if (!(fieldName in capability)) {
      errors.push(`capabilities[${index}] missing required field: ${fieldName}`);
    }
  }

  if (!DOMAIN_SET.has(capability.domain)) {
    errors.push(`capabilities[${index}] has invalid domain: ${capability.domain}`);
  }

  if (!isValidModuleName(capability.module)) {
    errors.push(`capabilities[${index}] has invalid module: ${capability.module}`);
  }
  if (
    namingRulesConfig
    && namingRulesConfig.modules instanceof Set
    && namingRulesConfig.modules.size > 0
    && !namingRulesConfig.modules.has(String(capability.module || '').trim())
  ) {
    errors.push(
      `capabilities[${index}] module is not declared in naming rules: ${capability.module}`
    );
  }

  if (!SYMMETRY_SET.has(capability.symmetry)) {
    errors.push(`capabilities[${index}] has invalid symmetry: ${capability.symmetry}`);
  }

  const canonicalTermRegex = namingRulesConfig && namingRulesConfig.canonicalTermRegex
    ? namingRulesConfig.canonicalTermRegex
    : /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
  if (
    typeof capability.canonical_term !== 'string'
    || !canonicalTermRegex.test(capability.canonical_term)
  ) {
    errors.push(`capabilities[${index}] has invalid canonical_term: ${capability.canonical_term}`);
  }

  const expectedCapabilityId = formatCapabilityIdFromTemplate(
    namingRulesConfig ? namingRulesConfig.capabilityIdTemplate : DEFAULT_CAPABILITY_ID_TEMPLATE,
    capability
  );
  if (
    typeof capability.capability_id !== 'string'
    || capability.capability_id !== expectedCapabilityId
  ) {
    errors.push(`capabilities[${index}] has invalid capability_id: ${capability.capability_id}`);
  }

  if (!validateDate(capability.review_at)) {
    errors.push(`capabilities[${index}] has invalid review_at: ${capability.review_at}`);
  }

  if (!Array.isArray(capability.applications) || capability.applications.length === 0) {
    errors.push(`capabilities[${index}] must provide at least one application target`);
  }

  if (Array.isArray(capability.applications)) {
    const appSet = new Set();
    for (const app of capability.applications) {
      if (!APP_SET.has(app)) {
        errors.push(`capabilities[${index}] has invalid application target: ${app}`);
      }
      if (appSet.has(app)) {
        errors.push(`capabilities[${index}] has duplicated application target: ${app}`);
      }
      appSet.add(app);
    }
  }

  const capabilityPathRegex = namingRulesConfig && namingRulesConfig.capabilityPathRegex
    ? namingRulesConfig.capabilityPathRegex
    : /^[a-z0-9-]+(?:\/[a-z0-9-]+)*$/;
  if (
    typeof capability.capability !== 'string'
    || !capabilityPathRegex.test(capability.capability)
  ) {
    errors.push(`capabilities[${index}] has invalid capability path: ${capability.capability}`);
  }

  const expectedPath = `${capability.module}/${capability.capability}`;
  if (capability.path && capability.path !== expectedPath) {
    errors.push(
      `capabilities[${index}] has inconsistent path: expected ${expectedPath}, received ${capability.path}`
    );
  }

  validateForbiddenTerm({
    value: capability.module,
    fieldName: 'module',
    capabilityId: capability.capability_id,
    forbiddenTerms: namingRulesConfig ? namingRulesConfig.forbiddenTerms : new Set(),
    errors
  });
  validateForbiddenTerm({
    value: capability.canonical_term,
    fieldName: 'canonical_term',
    capabilityId: capability.capability_id,
    forbiddenTerms: namingRulesConfig ? namingRulesConfig.forbiddenTerms : new Set(),
    errors
  });
  validateForbiddenTerm({
    value: capability.capability,
    fieldName: 'capability',
    capabilityId: capability.capability_id,
    forbiddenTerms: namingRulesConfig ? namingRulesConfig.forbiddenTerms : new Set(),
    errors
  });
}

function validateExtensionRegistryShape(extensionRegistry, errors) {
  if (!extensionRegistry || typeof extensionRegistry !== 'object') {
    errors.push('extension registry must be a JSON object');
    return;
  }

  if (!Array.isArray(extensionRegistry.extensions)) {
    errors.push('extension registry must include an extensions array');
    return;
  }

  const requiredFields = [
    'capability_id',
    'domain',
    'module',
    'capability',
    'owner',
    'reason',
    'exit_condition',
    'review_at'
  ];

  for (let index = 0; index < extensionRegistry.extensions.length; index += 1) {
    const extension = extensionRegistry.extensions[index];
    for (const fieldName of requiredFields) {
      if (!(fieldName in extension)) {
        errors.push(`extensions[${index}] missing required field: ${fieldName}`);
      }
    }

    if (!DOMAIN_SET.has(extension.domain)) {
      errors.push(`extensions[${index}] has invalid domain: ${extension.domain}`);
    }
    if (!isValidModuleName(extension.module)) {
      errors.push(`extensions[${index}] has invalid module: ${extension.module}`);
    }
    if (!validateDate(extension.review_at)) {
      errors.push(`extensions[${index}] has invalid review_at: ${extension.review_at}`);
    }
  }
}

function runDomainSymmetryCheck(options = {}) {
  const errors = [];

  const app = options.app || 'api';
  if (!APP_SET.has(app)) {
    return {
      ok: false,
      app,
      checked_capabilities: 0,
      errors: [`unsupported app target: ${app}`]
    };
  }

  const repoRoot = options.repoRoot || path.resolve(__dirname, '../..');
  const domainsRoot = options.domainsRoot || path.join(
    repoRoot,
    app === 'api' ? 'apps/api/src/domains' : 'apps/web/src/domains'
  );

  const capabilityMapPath = path.join(repoRoot, 'tools/domain-contract/capability-map.json');
  const capabilitySchemaPath = path.join(repoRoot, 'tools/domain-contract/capability-map.schema.json');
  const extensionRegistryPath = path.join(repoRoot, 'tools/domain-contract/domain-extension-registry.json');
  const namingRulesPath = path.join(repoRoot, 'tools/domain-contract/naming-rules.json');

  const capabilityMap = options.capabilityMap || readJson(capabilityMapPath, errors);
  const capabilitySchema = options.capabilitySchema || readJson(capabilitySchemaPath, errors);
  const extensionRegistry = options.extensionRegistry || readJson(extensionRegistryPath, errors);
  const namingRules = options.namingRules || readJson(namingRulesPath, errors);
  const namingRulesConfig = normalizeNamingRules(namingRules, errors);

  validateSchemaAlignment(capabilityMap, capabilitySchema, errors);
  validateExtensionRegistryShape(extensionRegistry, errors);

  const requiredFields = capabilitySchema
    && capabilitySchema.$defs
    && capabilitySchema.$defs.capability
    && Array.isArray(capabilitySchema.$defs.capability.required)
    ? capabilitySchema.$defs.capability.required
    : [
        'capability_id',
        'canonical_term',
        'module',
        'domain',
        'capability',
        'owner',
        'review_at',
        'parity_key',
        'symmetry',
        'applications'
      ];

  const extensionIds = new Set();
  if (extensionRegistry && Array.isArray(extensionRegistry.extensions)) {
    for (const extension of extensionRegistry.extensions) {
      if (typeof extension.capability_id === 'string' && extension.capability_id.length > 0) {
        extensionIds.add(extension.capability_id);
      }
    }
  }

  const parityStatus = new Map();
  const capabilityIdSet = new Set();
  const parityDomainSet = new Set();
  let checkedCount = 0;

  if (capabilityMap && Array.isArray(capabilityMap.capabilities)) {
    for (let index = 0; index < capabilityMap.capabilities.length; index += 1) {
      const capability = capabilityMap.capabilities[index];
      validateCapabilityRecord({
        capability,
        requiredFields,
        namingRulesConfig,
        errors,
        index
      });

      if (capabilityIdSet.has(capability.capability_id)) {
        errors.push(`duplicate capability_id detected: ${capability.capability_id}`);
      }
      capabilityIdSet.add(capability.capability_id);

      const parityDomainKey = `${capability.parity_key}::${capability.domain}`;
      if (parityDomainSet.has(parityDomainKey)) {
        errors.push(`duplicate parity_key+domain detected: ${parityDomainKey}`);
      }
      parityDomainSet.add(parityDomainKey);

      if (!Array.isArray(capability.applications) || !capability.applications.includes(app)) {
        continue;
      }

      checkedCount += 1;

      if (capability.symmetry !== 'required' && !extensionIds.has(capability.capability_id)) {
        errors.push(
          `capability ${capability.capability_id} is ${capability.symmetry} but missing extension registry entry`
        );
      }

      const parityKey = capability.parity_key;
      if (capability.symmetry === 'required' && typeof parityKey === 'string' && parityKey.length > 0) {
        const current = parityStatus.get(parityKey) || { platform: false, tenant: false };
        current[capability.domain] = true;
        parityStatus.set(parityKey, current);
      }

      const capabilityDirectory = path.join(
        domainsRoot,
        capability.domain,
        capability.module,
        capability.capability
      );

      if (!isDirectory(capabilityDirectory)) {
        errors.push(`missing capability directory: ${toPosix(capabilityDirectory)}`);
      }
    }
  }

  for (const [parityKey, status] of parityStatus.entries()) {
    if (!status.platform || !status.tenant) {
      errors.push(
        `missing mirrored capability for parity_key=${parityKey} (platform=${status.platform}, tenant=${status.tenant})`
      );
    }
  }

  for (const domain of DOMAIN_SET) {
    const domainDir = path.join(domainsRoot, domain);
    if (!isDirectory(domainDir)) {
      errors.push(`missing domain directory: ${toPosix(domainDir)}`);
      continue;
    }

    if (!hasDomainPublicApi(domainDir)) {
      errors.push(`missing public API index in domain directory: ${toPosix(domainDir)}`);
    }
  }

  validateDomainTopLevelDirectoryShape({
    app,
    domainsRoot,
    capabilityMap,
    namingRulesConfig,
    repoRoot,
    errors
  });
  validateLegacyNamespaceResidue({
    app,
    repoRoot,
    errors
  });
  validateTenantConfigPlaceholderMode({
    app,
    repoRoot,
    domainsRoot,
    capabilityMap,
    errors
  });
  validateCapabilityModuleOwnership({
    capabilityMap,
    namingRulesConfig,
    app,
    errors
  });
  validateSwitchOrgPlacement({
    domainsRoot,
    repoRoot,
    errors
  });
  validateForbiddenTermsInDomainPaths({
    domainsRoot,
    repoRoot,
    forbiddenTerms: namingRulesConfig.forbiddenTerms,
    errors
  });

  if (extensionRegistry && Array.isArray(extensionRegistry.extensions)) {
    for (const extension of extensionRegistry.extensions) {
      const extensionCapability = capabilityMap
        && Array.isArray(capabilityMap.capabilities)
        ? capabilityMap.capabilities.find((item) => item.capability_id === extension.capability_id)
        : null;

      if (!extensionCapability) {
        errors.push(
          `extension registry references unknown capability_id: ${extension.capability_id}`
        );
        continue;
      }

      if (extensionCapability.symmetry === 'required') {
        errors.push(
          `required capability cannot be listed in extension registry: ${extension.capability_id}`
        );
      }
    }
  }

  return {
    ok: errors.length === 0,
    app,
    checked_capabilities: checkedCount,
    errors
  };
}

module.exports = {
  runDomainSymmetryCheck,
  _internals: {
    toPosix,
    toNonEmptyLowerCase,
    tokenizeName,
    normalizeNamingRules,
    validateForbiddenTerm,
    validateForbiddenTermsInDomainPaths,
    resolveCanonicalTermOwnership,
    formatCapabilityIdFromTemplate,
    validateDate,
    hasDomainPublicApi,
    collectSourceFiles,
    isCapabilityEnabledForApp,
    isTenantConfigPlaceholderMode,
    validateDomainTopLevelDirectoryShape,
    collectConfiguredModules,
    resolveAllowedTopLevelDirectories,
    validateLegacyNamespaceResidue,
    validateTenantConfigPlaceholderMode,
    validateCapabilityModuleOwnership,
    validateSwitchOrgPlacement,
    isValidModuleName,
    validateSchemaAlignment,
    validateCapabilityRecord,
    validateExtensionRegistryShape
  }
};
