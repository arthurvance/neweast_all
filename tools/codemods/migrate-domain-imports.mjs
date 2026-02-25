#!/usr/bin/env node
import { readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import process from 'node:process';
import { parse } from '@babel/parser';

const DEFAULT_TARGETS = [
  'apps/api/src',
  'apps/api/test',
  'apps/web/src',
  'apps/web/test'
];
const VALID_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.tsx', '.jsx']);
const PARSE_OPTIONS = {
  sourceType: 'unambiguous',
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  plugins: ['jsx', 'typescript']
};
const MODULE_CONSTANTS_SPECIFIER_RE =
  /^(?<prefix>.*?)(?:\/)?modules\/(?<domain>platform|tenant)\/[^/]+\.constants(?:\.(?:[mc]?js|tsx?|jsx))?$/;

const toPosix = (value) => String(value || '').replace(/\\/g, '/');

const readStaticStringNode = (node) => {
  if (!node || typeof node !== 'object') {
    return null;
  }

  if (node.type === 'StringLiteral') {
    return node.value;
  }

  if (node.type === 'Literal' && typeof node.value === 'string') {
    return node.value;
  }

  if (
    node.type === 'TemplateLiteral'
    && Array.isArray(node.expressions)
    && node.expressions.length === 0
    && Array.isArray(node.quasis)
    && node.quasis.length === 1
  ) {
    return node.quasis[0].value.cooked || node.quasis[0].value.raw || '';
  }

  if (node.type === 'TSLiteralType') {
    return readStaticStringNode(node.literal);
  }

  return null;
};

const parseArgs = (argv) => {
  const args = argv.slice(2);
  const write = args.includes('--write');
  const targets = args.filter((arg) => arg !== '--write');
  return {
    write,
    targets: targets.length > 0 ? targets : DEFAULT_TARGETS
  };
};

const shouldSkipDirectory = (directoryName) =>
  directoryName === 'node_modules'
  || directoryName === 'dist'
  || directoryName === '.next'
  || directoryName === '.git';

const listTargetFiles = (targets) => {
  const files = [];
  const walk = (directoryPath) => {
    for (const entry of readdirSync(directoryPath)) {
      const fullPath = join(directoryPath, entry);
      const stats = statSync(fullPath);

      if (stats.isDirectory()) {
        if (shouldSkipDirectory(entry)) {
          continue;
        }
        walk(fullPath);
        continue;
      }

      const dotIndex = fullPath.lastIndexOf('.');
      if (dotIndex < 0) {
        continue;
      }
      const extension = fullPath.slice(dotIndex);
      if (VALID_EXTENSIONS.has(extension)) {
        files.push(fullPath);
      }
    }
  };

  for (const target of targets) {
    const absoluteTarget = resolve(process.cwd(), target);
    walk(absoluteTarget);
  }

  return files;
};

const collectSpecifierNodes = (ast) => {
  const nodes = [];
  const stack = [ast];
  while (stack.length > 0) {
    const current = stack.pop();
    if (!current || typeof current !== 'object') {
      continue;
    }

    switch (current.type) {
      case 'ImportDeclaration':
      case 'ExportAllDeclaration':
        if (current.source) {
          nodes.push(current.source);
        }
        break;
      case 'ExportNamedDeclaration':
        if (current.source) {
          nodes.push(current.source);
        }
        break;
      case 'ImportExpression':
        if (current.source) {
          nodes.push(current.source);
        }
        break;
      case 'CallExpression':
        if (
          current.callee
          && current.callee.type === 'Identifier'
          && current.callee.name === 'require'
          && Array.isArray(current.arguments)
          && current.arguments.length >= 1
        ) {
          nodes.push(current.arguments[0]);
        }
        break;
      case 'TSImportType':
        if (current.argument) {
          nodes.push(current.argument);
        }
        break;
      default:
        break;
    }

    for (const value of Object.values(current)) {
      if (!value || typeof value !== 'object') {
        continue;
      }
      if (Array.isArray(value)) {
        for (const child of value) {
          if (child && typeof child === 'object' && typeof child.type === 'string') {
            stack.push(child);
          }
        }
        continue;
      }
      if (typeof value.type === 'string') {
        stack.push(value);
      }
    }
  }
  return nodes;
};

const mapSpecifier = (value) => {
  const normalized = toPosix(value);
  const match = normalized.match(MODULE_CONSTANTS_SPECIFIER_RE);
  if (!match || !match.groups) {
    return null;
  }

  const domain = match.groups.domain;
  let prefix = match.groups.prefix || '';
  if (prefix.length > 0 && !prefix.endsWith('/')) {
    prefix = `${prefix}/`;
  }
  return `${prefix}domains/${domain}`;
};

const shouldSkipFile = (filePath) => {
  const normalized = toPosix(filePath);
  return normalized.includes('/src/domains/') || normalized.includes('/src/modules/');
};

const renderReplacement = (fileContent, node, replacementValue) => {
  const raw = fileContent.slice(node.start, node.end);
  const quote = raw.startsWith('"') || raw.startsWith("'") || raw.startsWith('`') ? raw[0] : "'";
  return `${quote}${replacementValue}${quote}`;
};

const applyReplacements = (content, replacements) => {
  if (replacements.length === 0) {
    return content;
  }
  const sorted = [...replacements].sort((left, right) => right.start - left.start);
  let nextContent = content;
  for (const replacement of sorted) {
    nextContent =
      nextContent.slice(0, replacement.start)
      + replacement.value
      + nextContent.slice(replacement.end);
  }
  return nextContent;
};

const migrateFile = (filePath, { write }) => {
  if (shouldSkipFile(filePath)) {
    return {
      updated: false,
      replacementCount: 0
    };
  }

  const content = readFileSync(filePath, 'utf8');
  let ast;
  try {
    ast = parse(content, PARSE_OPTIONS);
  } catch (error) {
    throw new Error(`Failed to parse ${toPosix(filePath)}: ${error.message}`);
  }

  const specifierNodes = collectSpecifierNodes(ast);
  const replacements = [];

  for (const node of specifierNodes) {
    const rawValue = readStaticStringNode(node);
    if (typeof rawValue !== 'string' || rawValue.length === 0) {
      continue;
    }
    const mappedValue = mapSpecifier(rawValue);
    if (!mappedValue || mappedValue === rawValue) {
      continue;
    }
    replacements.push({
      start: node.start,
      end: node.end,
      value: renderReplacement(content, node, mappedValue)
    });
  }

  if (replacements.length === 0) {
    return {
      updated: false,
      replacementCount: 0
    };
  }

  const nextContent = applyReplacements(content, replacements);
  if (write) {
    writeFileSync(filePath, nextContent, 'utf8');
  }

  return {
    updated: true,
    replacementCount: replacements.length
  };
};

const main = () => {
  const { write, targets } = parseArgs(process.argv);
  const files = listTargetFiles(targets);
  let changedFiles = 0;
  let changedImports = 0;

  for (const filePath of files) {
    const result = migrateFile(filePath, { write });
    if (!result.updated) {
      continue;
    }
    changedFiles += 1;
    changedImports += result.replacementCount;
    console.log(
      `[migrate-domain-imports] ${write ? 'updated' : 'would update'} ${toPosix(filePath)} (${result.replacementCount} imports)`
    );
  }

  console.log(
    `[migrate-domain-imports] scanned ${files.length} files, ${write ? 'updated' : 'matched'} ${changedFiles} files, ${changedImports} imports${write ? '' : ' (dry-run)'}`
  );
};

main();
