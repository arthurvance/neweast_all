#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function isFile(targetPath) {
  try {
    return fs.statSync(targetPath).isFile();
  } catch (_error) {
    return false;
  }
}

function listSourceFiles(rootDirectories) {
  const files = [];
  const stack = [...rootDirectories];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }
    for (const entry of entries) {
      if (entry.name === 'node_modules' || entry.name === '.git' || entry.name === 'dist') {
        continue;
      }
      const absolutePath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(absolutePath);
        continue;
      }
      if (entry.isFile() && /\.(?:[mc]?js|ts|tsx|jsx)$/.test(entry.name)) {
        files.push(absolutePath);
      }
    }
  }
  return files;
}

function parseRelativeImports(content) {
  const imports = new Set();
  const text = String(content || '');

  const requirePattern = /require\(\s*['"](\.[^'"]+)['"]\s*\)/g;
  let match = requirePattern.exec(text);
  while (match) {
    imports.add(match[1]);
    match = requirePattern.exec(text);
  }

  const importPattern = /from\s+['"](\.[^'"]+)['"]/g;
  match = importPattern.exec(text);
  while (match) {
    imports.add(match[1]);
    match = importPattern.exec(text);
  }

  return [...imports];
}

function resolveImportPath(sourceFile, specifier) {
  const sourceDir = path.dirname(sourceFile);
  const base = path.resolve(sourceDir, specifier);
  const candidates = [
    base,
    `${base}.js`,
    `${base}.mjs`,
    `${base}.cjs`,
    `${base}.ts`,
    `${base}.tsx`,
    `${base}.jsx`,
    path.join(base, 'index.js'),
    path.join(base, 'index.mjs'),
    path.join(base, 'index.cjs'),
    path.join(base, 'index.ts')
  ];

  for (const candidate of candidates) {
    if (isFile(candidate)) {
      return path.resolve(candidate);
    }
  }
  return null;
}

function buildGraph(files) {
  const fileSet = new Set(files.map((filePath) => path.resolve(filePath)));
  const graph = new Map();

  for (const filePath of fileSet) {
    const content = fs.readFileSync(filePath, 'utf8');
    const dependencies = [];
    for (const specifier of parseRelativeImports(content)) {
      const resolvedPath = resolveImportPath(filePath, specifier);
      if (resolvedPath && fileSet.has(resolvedPath)) {
        dependencies.push(resolvedPath);
      }
    }
    graph.set(filePath, dependencies);
  }

  return graph;
}

function detectCycles(graph) {
  const cycles = [];
  const visiting = new Set();
  const visited = new Set();
  const stack = [];

  function dfs(node) {
    if (visiting.has(node)) {
      const index = stack.indexOf(node);
      if (index >= 0) {
        cycles.push([...stack.slice(index), node]);
      }
      return;
    }
    if (visited.has(node)) {
      return;
    }

    visiting.add(node);
    stack.push(node);

    for (const dependency of graph.get(node) || []) {
      dfs(dependency);
    }

    stack.pop();
    visiting.delete(node);
    visited.add(node);
  }

  for (const node of graph.keys()) {
    dfs(node);
  }

  const unique = new Set();
  const normalized = [];
  for (const cycle of cycles) {
    const signature = cycle.join(' -> ');
    if (!unique.has(signature)) {
      unique.add(signature);
      normalized.push(cycle);
    }
  }

  return normalized;
}

function runAuthImportCycleCheck(options = {}) {
  const repoRoot = options.repoRoot || path.resolve(__dirname, '..', '..');
  const authRoots = options.authRoots || [
    path.join(repoRoot, 'apps/api/src/modules/auth'),
    path.join(repoRoot, 'apps/api/src/shared-kernel/auth'),
    path.join(repoRoot, 'apps/api/src/domains/platform/auth'),
    path.join(repoRoot, 'apps/api/src/domains/tenant/auth')
  ];

  const files = listSourceFiles(authRoots.filter((root) => fs.existsSync(root)));
  const graph = buildGraph(files);
  const cycles = detectCycles(graph);

  const errors = cycles.map((cycle, index) =>
    `cycle ${index + 1}: ${cycle.map((item) => toPosix(path.relative(repoRoot, item))).join(' -> ')}`
  );

  return {
    ok: errors.length === 0,
    checked_files: files.length,
    cycles,
    errors
  };
}

if (require.main === module) {
  const result = runAuthImportCycleCheck();
  if (!result.ok) {
    process.stderr.write(`${result.errors.join('\n')}\n`);
    process.exit(1);
  }
  process.stdout.write(`OK: no auth import cycles detected (${result.checked_files} files scanned).\n`);
}

module.exports = {
  runAuthImportCycleCheck
};
