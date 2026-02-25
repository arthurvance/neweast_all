#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const DOMAIN_VALUES = new Set(['platform', 'tenant', 'all']);
const TARGET_VALUES = new Set(['api', 'web', 'all']);
const NAME_RE = /^[a-z][a-z0-9-]*$/;

const scriptPath = fileURLToPath(import.meta.url);
const scriptDir = dirname(scriptPath);
const repoRoot = resolve(scriptDir, '..', '..');
const templateRoot = resolve(scriptDir, 'templates', 'domain-module');

const parseArgs = (argv = []) => {
  const args = [...argv];
  const options = {
    moduleName: '',
    capabilityName: '',
    domain: 'all',
    target: 'all',
    force: false,
    dryRun: false
  };

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--force') {
      options.force = true;
      continue;
    }
    if (arg === '--dry-run') {
      options.dryRun = true;
      continue;
    }
    if (arg === '--module') {
      options.moduleName = String(args[index + 1] || '').trim();
      index += 1;
      continue;
    }
    if (arg === '--capability') {
      options.capabilityName = String(args[index + 1] || '').trim();
      index += 1;
      continue;
    }
    if (arg === '--domain') {
      options.domain = String(args[index + 1] || '').trim().toLowerCase();
      index += 1;
      continue;
    }
    if (arg === '--target') {
      options.target = String(args[index + 1] || '').trim().toLowerCase();
      index += 1;
      continue;
    }
    throw new Error(`Unknown argument: ${arg}`);
  }

  return options;
};

const assertValidOptions = (options = {}) => {
  if (!options.moduleName || !NAME_RE.test(options.moduleName)) {
    throw new Error(
      '--module is required and must match /^[a-z][a-z0-9-]*$/'
    );
  }
  if (!options.capabilityName || !NAME_RE.test(options.capabilityName)) {
    throw new Error(
      '--capability is required and must match /^[a-z][a-z0-9-]*$/'
    );
  }
  if (!DOMAIN_VALUES.has(options.domain)) {
    throw new Error('--domain must be one of: platform, tenant, all');
  }
  if (!TARGET_VALUES.has(options.target)) {
    throw new Error('--target must be one of: api, web, all');
  }
};

const resolveDomains = (domainOption) =>
  domainOption === 'all' ? ['platform', 'tenant'] : [domainOption];

const resolveTargets = (targetOption) =>
  targetOption === 'all' ? ['api', 'web'] : [targetOption];

const toTemplateContent = ({
  target,
  domain,
  moduleName,
  capabilityName
}) => {
  const templatePath = resolve(
    templateRoot,
    target,
    target === 'api' ? 'index.js.tpl' : 'index.mjs.tpl'
  );
  const template = readFileSync(templatePath, 'utf8');
  return template
    .replaceAll('__DOMAIN__', domain)
    .replaceAll('__MODULE__', moduleName)
    .replaceAll('__CAPABILITY__', capabilityName);
};

const resolveOutputPath = ({
  target,
  domain,
  moduleName,
  capabilityName
}) => {
  const extension = target === 'api' ? 'index.js' : 'index.mjs';
  return resolve(
    repoRoot,
    'apps',
    target,
    'src',
    'domains',
    domain,
    moduleName,
    capabilityName,
    extension
  );
};

const run = () => {
  const options = parseArgs(process.argv.slice(2));
  assertValidOptions(options);

  const domains = resolveDomains(options.domain);
  const targets = resolveTargets(options.target);

  let createdCount = 0;
  let skippedCount = 0;
  for (const target of targets) {
    for (const domain of domains) {
      const outputPath = resolveOutputPath({
        target,
        domain,
        moduleName: options.moduleName,
        capabilityName: options.capabilityName
      });
      const outputDir = dirname(outputPath);
      const exists = existsSync(outputPath);
      if (exists && !options.force) {
        skippedCount += 1;
        console.log(`[create-domain-module] skip existing: ${outputPath}`);
        continue;
      }

      if (!options.dryRun) {
        mkdirSync(outputDir, { recursive: true });
        const templateContent = toTemplateContent({
          target,
          domain,
          moduleName: options.moduleName,
          capabilityName: options.capabilityName
        });
        writeFileSync(outputPath, templateContent, 'utf8');
      }
      createdCount += 1;
      console.log(
        `[create-domain-module] ${options.dryRun ? 'plan create' : 'created'}: ${outputPath}`
      );
    }
  }

  console.log(
    `[create-domain-module] done: created=${createdCount}, skipped=${skippedCount}, dry_run=${options.dryRun}`
  );
};

try {
  run();
} catch (error) {
  console.error(`[create-domain-module] ${error.message}`);
  console.error(
    'Usage: node tools/scaffold/create-domain-module.mjs --module <name> --capability <name> [--domain platform|tenant|all] [--target api|web|all] [--force] [--dry-run]'
  );
  process.exit(1);
}
