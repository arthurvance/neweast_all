#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repoRoot = path.resolve(__dirname, '../..');
const scaffoldScriptPath = path.join(repoRoot, 'tools/scaffold/create-domain-module.mjs');
const namingRulesPath = path.join(repoRoot, 'tools/domain-contract/naming-rules.json');
const supportedTargets = [
  {
    app: 'api',
    extension: 'index.js'
  },
  {
    app: 'web',
    extension: 'index.mjs'
  }
];
const supportedDomains = ['platform', 'tenant'];

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function runNodeScript(args) {
  return spawnSync(process.execPath, args, {
    cwd: repoRoot,
    encoding: 'utf8'
  });
}

function readNamingRules() {
  const parsed = JSON.parse(fs.readFileSync(namingRulesPath, 'utf8'));
  const modules = Array.isArray(parsed && parsed.modules) ? parsed.modules : [];
  const validModules = modules
    .map((value) => String(value || '').trim())
    .filter((value) => /^[a-z][a-z0-9-]*$/.test(value));

  if (validModules.length === 0) {
    return 'settings';
  }
  if (validModules.includes('settings')) {
    return 'settings';
  }
  return validModules[0];
}

function resolveGeneratedFilePaths(moduleName, capabilityName) {
  const paths = [];
  for (const target of supportedTargets) {
    for (const domain of supportedDomains) {
      paths.push(
        path.join(
          repoRoot,
          'apps',
          target.app,
          'src',
          'domains',
          domain,
          moduleName,
          capabilityName,
          target.extension
        )
      );
    }
  }
  return paths;
}

function validateGeneratedFiles({
  moduleName,
  capabilityName,
  generatedFilePaths
}) {
  for (const generatedPath of generatedFilePaths) {
    if (!fs.existsSync(generatedPath)) {
      throw new Error(`missing scaffold output file: ${toPosix(path.relative(repoRoot, generatedPath))}`);
    }
    const content = fs.readFileSync(generatedPath, 'utf8');
    const domain = generatedPath.includes(`${path.sep}platform${path.sep}`)
      ? 'platform'
      : 'tenant';
    const capabilityMarker = `${domain}/${moduleName}/${capabilityName}`;
    if (!content.includes(capabilityMarker)) {
      throw new Error(
        `scaffold output content missing resolved capability markers: ${toPosix(path.relative(repoRoot, generatedPath))}`
      );
    }
    if (content.includes('__DOMAIN__') || content.includes('__MODULE__') || content.includes('__CAPABILITY__')) {
      throw new Error(
        `scaffold output still contains unresolved placeholders: ${toPosix(path.relative(repoRoot, generatedPath))}`
      );
    }
  }
}

function validateSymmetryChecks() {
  const apiCheck = runNodeScript(['apps/api/scripts/check-domain-symmetry.js']);
  if (apiCheck.status !== 0) {
    throw new Error(
      `API symmetry check failed after scaffold generation:\n${apiCheck.stderr || apiCheck.stdout}`
    );
  }

  const webCheck = runNodeScript(['apps/web/scripts/check-domain-symmetry.cjs']);
  if (webCheck.status !== 0) {
    throw new Error(
      `Web symmetry check failed after scaffold generation:\n${webCheck.stderr || webCheck.stdout}`
    );
  }
}

function cleanupGeneratedArtifacts(moduleName, capabilityName) {
  for (const target of supportedTargets) {
    for (const domain of supportedDomains) {
      const capabilityDirectory = path.join(
        repoRoot,
        'apps',
        target.app,
        'src',
        'domains',
        domain,
        moduleName,
        capabilityName
      );
      fs.rmSync(capabilityDirectory, { recursive: true, force: true });
    }
  }
}

function run() {
  const moduleName = readNamingRules();
  const capabilityName = `scaffold-smoke-${Date.now().toString(36)}`;
  const generatedFilePaths = resolveGeneratedFilePaths(moduleName, capabilityName);

  try {
    const scaffoldResult = runNodeScript([
      scaffoldScriptPath,
      '--module',
      moduleName,
      '--capability',
      capabilityName,
      '--domain',
      'all',
      '--target',
      'all'
    ]);
    if (scaffoldResult.status !== 0) {
      throw new Error(
        `scaffold command failed:\n${scaffoldResult.stderr || scaffoldResult.stdout}`
      );
    }

    validateGeneratedFiles({
      moduleName,
      capabilityName,
      generatedFilePaths
    });
    validateSymmetryChecks();

    console.log(
      `[check-domain-module-scaffold-smoke] passed (module=${moduleName}, capability=${capabilityName})`
    );
  } finally {
    cleanupGeneratedArtifacts(moduleName, capabilityName);
  }
}

try {
  run();
} catch (error) {
  console.error(`[check-domain-module-scaffold-smoke] ${error.message}`);
  process.exit(1);
}
