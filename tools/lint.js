#!/usr/bin/env node
const { readdirSync, readFileSync, statSync } = require('node:fs');
const { join, resolve } = require('node:path');
const { spawnSync } = require('node:child_process');

const targetDirs = process.argv.slice(2);
if (targetDirs.length === 0) {
  console.error('Usage: node tools/lint.js <dir> [dir ...]');
  process.exit(1);
}

const files = [];
const validExtensions = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);
const customRules = [
  require(join(__dirname, 'lint-rules/no-cross-domain-imports.js')),
  require(join(__dirname, 'lint-rules/no-domain-deep-imports.js')),
  require(join(__dirname, 'lint-rules/no-domain-module-constants-imports.js')),
  require(join(__dirname, 'lint-rules/no-domain-api-client-direct-imports.js')),
  require(join(__dirname, 'lint-rules/file-granularity-thresholds.js'))
];
const ESM_HINT_RE = /\b(?:import|export)\b/;

const runSyntaxCheck = (filePath, content) => {
  const primaryCheck = spawnSync(process.execPath, ['--check', filePath], {
    encoding: 'utf8'
  });

  if (primaryCheck.status === 0) {
    return null;
  }

  if (filePath.endsWith('.js') && ESM_HINT_RE.test(content)) {
    const esmCheck = spawnSync(process.execPath, ['--input-type=module', '--check'], {
      input: content,
      encoding: 'utf8'
    });
    if (esmCheck.status === 0) {
      return null;
    }
    return (esmCheck.stderr || esmCheck.stdout || '').trim();
  }

  return (primaryCheck.stderr || primaryCheck.stdout || '').trim();
};

const walk = (dir) => {
  for (const entry of readdirSync(dir)) {
    const fullPath = join(dir, entry);
    const stats = statSync(fullPath);

    if (stats.isDirectory()) {
      if (entry === 'dist' || entry === 'node_modules' || entry === '.next') {
        continue;
      }
      walk(fullPath);
      continue;
    }

    const extension = fullPath.slice(fullPath.lastIndexOf('.'));
    if (validExtensions.has(extension)) {
      files.push(fullPath);
    }
  }
};

for (const target of targetDirs) {
  walk(target);
}

let hasError = false;
for (const file of files) {
  const absoluteFilePath = resolve(process.cwd(), file);
  const content = readFileSync(absoluteFilePath, 'utf8');

  if (content.includes('\t')) {
    console.error(`Tab character is not allowed: ${absoluteFilePath}`);
    hasError = true;
  }

  if (file.endsWith('.js') || file.endsWith('.mjs') || file.endsWith('.cjs')) {
    const syntaxErrorOutput = runSyntaxCheck(absoluteFilePath, content);
    if (syntaxErrorOutput) {
      console.error(syntaxErrorOutput);
      hasError = true;
    }
  }

  for (const rule of customRules) {
    const issues = rule.checkFile({
      filePath: absoluteFilePath,
      content
    });
    if (!Array.isArray(issues)) {
      console.error(
        `Lint rule ${rule.id || '(unknown)'} must return an array of issues: ${absoluteFilePath}`
      );
      hasError = true;
      continue;
    }
    for (const issue of issues) {
      console.error(`[${rule.id || 'custom-rule'}] ${absoluteFilePath}: ${issue}`);
      hasError = true;
    }
  }
}

if (hasError) {
  process.exit(1);
}

console.log(`Lint passed (${files.length} files checked)`);
