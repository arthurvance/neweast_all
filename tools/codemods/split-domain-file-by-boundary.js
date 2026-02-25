#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const parser = require('@babel/parser');

const SUPPORTED_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);
const DEFAULT_MAX_LOC = 800;
const DEFAULT_MIN_BOUNDARY_LOC = 120;
const LINT_MIN_CAPABILITY_LOC = 120;
const SOURCE_EXTENSIONS = /\.(?:[mc]?js|ts)$/;
const DOMAIN_SERVICE_PATH_RE = /\/apps\/api\/src\/domains\/.+\/service\/index\.[mc]?js$/;

const RESERVED_WORD_SET = new Set([
  'break',
  'case',
  'catch',
  'class',
  'const',
  'continue',
  'debugger',
  'default',
  'delete',
  'do',
  'else',
  'export',
  'extends',
  'finally',
  'for',
  'function',
  'if',
  'import',
  'in',
  'instanceof',
  'new',
  'return',
  'super',
  'switch',
  'this',
  'throw',
  'try',
  'typeof',
  'var',
  'void',
  'while',
  'with',
  'yield',
  'let',
  'static',
  'enum',
  'await',
  'implements',
  'package',
  'protected',
  'interface',
  'private',
  'public',
  'null',
  'true',
  'false',
  'undefined',
  'NaN',
  'Infinity'
]);

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function countEffectiveLoc(content = '') {
  return String(content)
    .split(/\r?\n/)
    .filter((line) => line.trim().length > 0).length;
}

function countExportStatements(content = '') {
  const normalized = String(content);
  let count = 0;
  const patterns = [
    /\bmodule\.exports\b/g,
    /\bexports\.[A-Za-z0-9_$]+\b/g,
    /\bexport\s+default\b/g,
    /\bexport\s+(?:const|function|class)\b/g,
    /\bexport\s*\{/g
  ];
  for (const pattern of patterns) {
    const matches = normalized.match(pattern);
    if (matches) {
      count += matches.length;
    }
  }
  return count;
}

function isIdentifierNode(node) {
  return node && node.type === 'Identifier' && typeof node.name === 'string';
}

function parseFileContent(filePath, content) {
  try {
    return parser.parse(content, {
      sourceType: 'unambiguous',
      plugins: ['jsx', 'typescript'],
      ranges: false,
      tokens: false,
      errorRecovery: false
    });
  } catch (error) {
    throw new Error(`parse failed for ${toPosix(filePath)}: ${error.message}`);
  }
}

function collectPatternIdentifiers(pattern, bucket) {
  if (!pattern || typeof pattern !== 'object') {
    return;
  }

  switch (pattern.type) {
    case 'Identifier':
      bucket.add(pattern.name);
      return;
    case 'ObjectPattern':
      for (const property of pattern.properties || []) {
        if (property.type === 'RestElement') {
          collectPatternIdentifiers(property.argument, bucket);
          continue;
        }
        collectPatternIdentifiers(property.value, bucket);
      }
      return;
    case 'ArrayPattern':
      for (const element of pattern.elements || []) {
        if (element) {
          collectPatternIdentifiers(element, bucket);
        }
      }
      return;
    case 'AssignmentPattern':
      collectPatternIdentifiers(pattern.left, bucket);
      return;
    case 'RestElement':
      collectPatternIdentifiers(pattern.argument, bucket);
      return;
    default:
      return;
  }
}

function getDefinedNamesFromStatement(statement) {
  const names = new Set();

  if (!statement || typeof statement !== 'object') {
    return names;
  }

  if (statement.type === 'FunctionDeclaration' && isIdentifierNode(statement.id)) {
    names.add(statement.id.name);
    return names;
  }

  if (statement.type === 'ClassDeclaration' && isIdentifierNode(statement.id)) {
    names.add(statement.id.name);
    return names;
  }

  if (statement.type === 'VariableDeclaration') {
    for (const declarator of statement.declarations || []) {
      collectPatternIdentifiers(declarator.id, names);
    }
  }

  return names;
}

function isRequireCallExpression(node) {
  return (
    node
    && node.type === 'CallExpression'
    && node.callee
    && node.callee.type === 'Identifier'
    && node.callee.name === 'require'
    && Array.isArray(node.arguments)
    && node.arguments.length >= 1
  );
}

function statementContainsRequire(statement) {
  if (!statement || statement.type !== 'VariableDeclaration') {
    return false;
  }
  for (const declarator of statement.declarations || []) {
    if (isRequireCallExpression(declarator.init)) {
      return true;
    }
  }
  return false;
}

function isModuleExportsNode(node) {
  return (
    node
    && node.type === 'MemberExpression'
    && !node.computed
    && node.object
    && node.object.type === 'Identifier'
    && node.object.name === 'module'
    && node.property
    && node.property.type === 'Identifier'
    && node.property.name === 'exports'
  );
}

function resolveModuleExportsInfo(programBody = []) {
  for (let index = 0; index < programBody.length; index += 1) {
    const statement = programBody[index];
    if (
      !statement
      || statement.type !== 'ExpressionStatement'
      || !statement.expression
      || statement.expression.type !== 'AssignmentExpression'
      || statement.expression.operator !== '='
      || !isModuleExportsNode(statement.expression.left)
    ) {
      continue;
    }

    const right = statement.expression.right;
    const exportedIdentifierSet = new Set();
    if (right && right.type === 'ObjectExpression') {
      for (const property of right.properties || []) {
        if (!property || property.type !== 'ObjectProperty') {
          continue;
        }
        if (property.shorthand && isIdentifierNode(property.key)) {
          exportedIdentifierSet.add(property.key.name);
          continue;
        }
        if (isIdentifierNode(property.value)) {
          exportedIdentifierSet.add(property.value.name);
        }
      }
    } else if (isIdentifierNode(right)) {
      exportedIdentifierSet.add(right.name);
    }

    return {
      index,
      statement,
      exportedIdentifierSet
    };
  }

  return null;
}

function resolveBoundaryFromName(name = '') {
  const normalizedName = String(name || '').trim();
  if (!normalizedName) {
    return 'helpers';
  }

  if (/^[A-Z][A-Z0-9_]*$/.test(normalizedName)) {
    return 'constants';
  }

  if (/error|problem/i.test(normalizedName)) {
    return 'errors';
  }

  if (/^parse|^validate/.test(normalizedName)) {
    return 'parsers';
  }

  if (/^normalize|^to[A-Z]|^mask|^sanitize|^is[A-Z]/.test(normalizedName)) {
    return 'normalizers';
  }

  return 'helpers';
}

function collectNameTokens(sourceText = '') {
  const identifiers = new Set();
  const matches = String(sourceText).match(/[A-Za-z_$][A-Za-z0-9_$]*/g) || [];
  for (const candidate of matches) {
    if (RESERVED_WORD_SET.has(candidate)) {
      continue;
    }
    identifiers.add(candidate);
  }
  return identifiers;
}

function resolveDeclarationDependencies(entries) {
  const declarationByName = new Map();
  for (const entry of entries) {
    for (const name of entry.definedNames) {
      if (!declarationByName.has(name)) {
        declarationByName.set(name, entry.id);
      }
    }
  }

  for (const entry of entries) {
    const tokenSet = collectNameTokens(entry.sourceText);
    for (const ownName of entry.definedNames) {
      tokenSet.delete(ownName);
    }
    const dependencyIds = new Set();
    for (const token of tokenSet) {
      const dependencyId = declarationByName.get(token);
      if (dependencyId === undefined) {
        continue;
      }
      dependencyIds.add(dependencyId);
    }
    entry.dependencyIds = [...dependencyIds];
  }
}

function resolveStronglyConnectedComponents(entries) {
  const entryById = new Map(entries.map((entry) => [entry.id, entry]));
  let currentIndex = 0;
  const stack = [];
  const indexById = new Map();
  const lowLinkById = new Map();
  const onStack = new Set();
  const componentById = new Map();
  const components = [];

  const strongConnect = (entry) => {
    indexById.set(entry.id, currentIndex);
    lowLinkById.set(entry.id, currentIndex);
    currentIndex += 1;
    stack.push(entry.id);
    onStack.add(entry.id);

    for (const dependencyId of entry.dependencyIds || []) {
      if (!entryById.has(dependencyId)) {
        continue;
      }
      if (!indexById.has(dependencyId)) {
        strongConnect(entryById.get(dependencyId));
        lowLinkById.set(
          entry.id,
          Math.min(lowLinkById.get(entry.id), lowLinkById.get(dependencyId))
        );
      } else if (onStack.has(dependencyId)) {
        lowLinkById.set(
          entry.id,
          Math.min(lowLinkById.get(entry.id), indexById.get(dependencyId))
        );
      }
    }

    if (lowLinkById.get(entry.id) !== indexById.get(entry.id)) {
      return;
    }

    const component = [];
    while (stack.length > 0) {
      const poppedId = stack.pop();
      onStack.delete(poppedId);
      component.push(poppedId);
      componentById.set(poppedId, components.length);
      if (poppedId === entry.id) {
        break;
      }
    }
    components.push(component);
  };

  for (const entry of entries) {
    if (!indexById.has(entry.id)) {
      strongConnect(entry);
    }
  }

  return { componentById, components };
}

function pickBoundaryLabelForComponent(componentEntries) {
  const labels = new Set(componentEntries.map((entry) => entry.boundaryLabel));
  if (labels.size === 1) {
    return componentEntries[0].boundaryLabel;
  }
  if (labels.has('helpers')) {
    return 'helpers';
  }
  if (labels.has('parsers')) {
    return 'parsers';
  }
  if (labels.has('normalizers')) {
    return 'normalizers';
  }
  if (labels.has('errors')) {
    return 'errors';
  }
  return 'constants';
}

function collapseBoundaryByScc(entries) {
  const { componentById, components } = resolveStronglyConnectedComponents(entries);
  for (let componentIndex = 0; componentIndex < components.length; componentIndex += 1) {
    const component = components[componentIndex];
    const componentEntries = component
      .map((entryId) => entries.find((entry) => entry.id === entryId))
      .filter(Boolean);
    const label = pickBoundaryLabelForComponent(componentEntries);
    for (const entry of componentEntries) {
      entry.boundaryLabel = label;
    }
  }

  for (const entry of entries) {
    entry.componentIndex = componentById.get(entry.id);
  }
}

function computeStemName(filePath) {
  const extension = path.extname(filePath);
  const basename = path.basename(filePath, extension);
  if (basename !== 'index') {
    return basename;
  }
  const parentName = path.basename(path.dirname(filePath));
  return parentName || 'index';
}

function resolveBoundaryFileName(stemName, boundaryLabel) {
  return `${stemName}.${boundaryLabel}.js`;
}

function normalizeSpacing(content) {
  return String(content)
    .replace(/\n{3,}/g, '\n\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n+$/g, '\n');
}

function appendBoundaryStatement({
  mainContent,
  insertionOffset,
  boundaryStatement
}) {
  const prefix = mainContent.slice(0, insertionOffset);
  const suffix = mainContent.slice(insertionOffset);
  return `${prefix}\n${boundaryStatement}\n${suffix}`;
}

function normalizeRemovalRanges(ranges = [], contentLength = 0) {
  const sortedRanges = ranges
    .map((range) => ({
      start: Math.max(0, Math.min(contentLength, Number(range?.start || 0))),
      end: Math.max(0, Math.min(contentLength, Number(range?.end || 0)))
    }))
    .filter((range) => range.end > range.start)
    .sort((a, b) => a.start - b.start);

  if (sortedRanges.length <= 1) {
    return sortedRanges;
  }

  const merged = [];
  for (const range of sortedRanges) {
    const last = merged[merged.length - 1];
    if (!last || range.start > last.end) {
      merged.push({ start: range.start, end: range.end });
      continue;
    }
    last.end = Math.max(last.end, range.end);
  }

  return merged;
}

function removeRangesFromContent(content, ranges = []) {
  if (ranges.length === 0) {
    return content;
  }
  const mergedRanges = normalizeRemovalRanges(ranges, String(content).length);
  const sortedRanges = [...mergedRanges].sort((a, b) => b.start - a.start);
  let transformed = content;
  for (const range of sortedRanges) {
    transformed = `${transformed.slice(0, range.start)}${transformed.slice(range.end)}`;
  }
  return transformed;
}

function normalizeDestructureNames(names) {
  return [...new Set(names)].sort();
}

function resolveRequireModuleLiteralValue(node) {
  if (!node || typeof node !== 'object') {
    return '';
  }
  if (node.type === 'StringLiteral') {
    return String(node.value || '').trim();
  }
  if (node.type === 'Literal' && typeof node.value === 'string') {
    return String(node.value).trim();
  }
  return '';
}

function collectNamesFromPatternNode(pattern) {
  const names = new Set();
  collectPatternIdentifiers(pattern, names);
  return normalizeDestructureNames([...names]);
}

function resolveRequireStatementSignature(statement) {
  if (!statement || statement.type !== 'VariableDeclaration') {
    return '';
  }

  const declaratorSignatures = [];
  for (const declarator of statement.declarations || []) {
    if (!isRequireCallExpression(declarator.init)) {
      return '';
    }
    const modulePath = resolveRequireModuleLiteralValue(declarator.init.arguments[0]);
    if (!modulePath) {
      return '';
    }
    const names = collectNamesFromPatternNode(declarator.id);
    declaratorSignatures.push(`${modulePath}|${names.join(',')}`);
  }

  return declaratorSignatures.join('||');
}

function collectUniqueRequireStatementSource(requireStatements = []) {
  const dedupedSources = [];
  const seenSignatures = new Set();
  const seenSourceTexts = new Set();

  for (const item of requireStatements) {
    const sourceText = String(item?.sourceText || '').trim();
    if (!sourceText) {
      continue;
    }
    const signature = resolveRequireStatementSignature(item?.statement);
    if (signature) {
      if (seenSignatures.has(signature)) {
        continue;
      }
      seenSignatures.add(signature);
      dedupedSources.push(sourceText);
      continue;
    }
    if (seenSourceTexts.has(sourceText)) {
      continue;
    }
    seenSourceTexts.add(sourceText);
    dedupedSources.push(sourceText);
  }

  return dedupedSources;
}

function computeGroupLoc(entries = []) {
  return entries
    .map((entry) => countEffectiveLoc(entry.sourceText))
    .reduce((sum, value) => sum + value, 0);
}

function mergeOverFragmentedGroups(boundaryMap, minimumLoc = LINT_MIN_CAPABILITY_LOC) {
  const map = new Map(boundaryMap);
  const labels = [...map.keys()];
  if (labels.length <= 1) {
    return map;
  }

  const findLargestAlternativeLabel = (excludeLabel) => {
    let bestLabel = null;
    let bestLoc = -1;
    for (const [label, entries] of map.entries()) {
      if (label === excludeLabel) {
        continue;
      }
      const loc = computeGroupLoc(entries);
      if (loc > bestLoc) {
        bestLoc = loc;
        bestLabel = label;
      }
    }
    return bestLabel;
  };

  let merged = true;
  while (merged) {
    merged = false;
    for (const [label, entries] of [...map.entries()]) {
      const loc = computeGroupLoc(entries);
      if (loc >= minimumLoc) {
        continue;
      }

      const targetLabel = label === 'helpers'
        ? findLargestAlternativeLabel(label)
        : (map.has('helpers') ? 'helpers' : findLargestAlternativeLabel(label));
      if (!targetLabel || targetLabel === label) {
        continue;
      }

      const targetEntries = map.get(targetLabel) || [];
      map.set(targetLabel, [...targetEntries, ...entries]);
      map.delete(label);
      merged = true;
      break;
    }
  }

  return map;
}

function resolveBoundaryDependencyMap(boundaryMap) {
  const boundaryByDeclarationId = new Map();
  for (const [label, entries] of boundaryMap.entries()) {
    for (const entry of entries) {
      boundaryByDeclarationId.set(entry.id, label);
    }
  }

  const dependencyMap = new Map();
  for (const label of boundaryMap.keys()) {
    dependencyMap.set(label, new Set());
  }

  for (const [label, entries] of boundaryMap.entries()) {
    const deps = dependencyMap.get(label) || new Set();
    for (const entry of entries) {
      for (const dependencyId of entry.dependencyIds || []) {
        const dependencyLabel = boundaryByDeclarationId.get(dependencyId);
        if (!dependencyLabel || dependencyLabel === label) {
          continue;
        }
        deps.add(dependencyLabel);
      }
    }
    dependencyMap.set(label, deps);
  }

  return dependencyMap;
}

function resolveBoundaryStronglyConnectedComponents(dependencyMap) {
  const labels = [...dependencyMap.keys()];
  const indexByLabel = new Map();
  const lowLinkByLabel = new Map();
  const onStack = new Set();
  const stack = [];
  let index = 0;
  const components = [];

  const strongConnect = (label) => {
    indexByLabel.set(label, index);
    lowLinkByLabel.set(label, index);
    index += 1;
    stack.push(label);
    onStack.add(label);

    const dependencies = dependencyMap.get(label) || new Set();
    for (const dependencyLabel of dependencies) {
      if (!dependencyMap.has(dependencyLabel)) {
        continue;
      }
      if (!indexByLabel.has(dependencyLabel)) {
        strongConnect(dependencyLabel);
        lowLinkByLabel.set(
          label,
          Math.min(lowLinkByLabel.get(label), lowLinkByLabel.get(dependencyLabel))
        );
      } else if (onStack.has(dependencyLabel)) {
        lowLinkByLabel.set(
          label,
          Math.min(lowLinkByLabel.get(label), indexByLabel.get(dependencyLabel))
        );
      }
    }

    if (lowLinkByLabel.get(label) !== indexByLabel.get(label)) {
      return;
    }

    const component = [];
    while (stack.length > 0) {
      const popped = stack.pop();
      onStack.delete(popped);
      component.push(popped);
      if (popped === label) {
        break;
      }
    }
    components.push(component);
  };

  for (const label of labels) {
    if (!indexByLabel.has(label)) {
      strongConnect(label);
    }
  }

  return components;
}

function resolveCycleMergeTargetLabel(componentLabels = []) {
  const ordered = ['helpers', 'normalizers', 'parsers', 'errors', 'constants'];
  for (const label of ordered) {
    if (componentLabels.includes(label)) {
      return label;
    }
  }
  return componentLabels.slice().sort((a, b) => a.localeCompare(b))[0] || 'helpers';
}

function collapseBoundaryCycles(boundaryMap) {
  const map = new Map(boundaryMap);
  if (map.size <= 1) {
    return map;
  }

  let collapsed = true;
  while (collapsed) {
    collapsed = false;
    const dependencyMap = resolveBoundaryDependencyMap(map);
    const cyclicComponents = resolveBoundaryStronglyConnectedComponents(dependencyMap)
      .filter((component) => component.length > 1);
    if (cyclicComponents.length === 0) {
      break;
    }

    const [component] = cyclicComponents;
    const targetLabel = resolveCycleMergeTargetLabel(component);
    const mergedEntries = [];
    for (const label of component) {
      const entries = map.get(label) || [];
      mergedEntries.push(...entries);
      if (label !== targetLabel) {
        map.delete(label);
      }
    }
    map.set(targetLabel, mergedEntries);
    collapsed = true;
  }

  return map;
}

function validateBestPracticeOutcome({
  filePath,
  originalContent,
  mainContent,
  boundaryOutputs,
  maxLoc = DEFAULT_MAX_LOC,
  minBoundaryLoc = DEFAULT_MIN_BOUNDARY_LOC
}) {
  const issues = [];
  const originalLoc = countEffectiveLoc(originalContent);
  const mainLoc = countEffectiveLoc(mainContent);
  if (mainLoc >= originalLoc) {
    issues.push(
      `main file LOC did not decrease (${mainLoc} >= ${originalLoc}) for ${toPosix(filePath)}`
    );
  }
  if (mainLoc > maxLoc) {
    issues.push(
      `main file still oversized after split (${mainLoc} > ${maxLoc}) for ${toPosix(filePath)}`
    );
  }

  for (const output of boundaryOutputs) {
    const loc = countEffectiveLoc(output.content);
    if (!/^[a-z0-9-]+\.(constants|errors|normalizers|parsers|helpers)\.js$/.test(output.fileName)) {
      issues.push(`boundary file naming is not semantic: ${output.fileName}`);
    }
    if (loc > maxLoc) {
      issues.push(
        `boundary file oversized after split (${loc} > ${maxLoc}): ${output.fileName}`
      );
    }
    if (loc < minBoundaryLoc) {
      issues.push(
        `boundary file too small (${loc} < ${minBoundaryLoc}), likely over-fragmented: ${output.fileName}`
      );
    }
    const exportStatementCount = countExportStatements(output.content);
    if (loc < LINT_MIN_CAPABILITY_LOC && exportStatementCount <= 1) {
      issues.push(
        `boundary file violates granularity lint baseline (${loc} LOC with ${exportStatementCount} export): ${output.fileName}`
      );
    }
    if (output.exportedNames.length === 0) {
      issues.push(`boundary file exports no identifiers: ${output.fileName}`);
    }
  }

  return issues;
}

function transformDomainFileByBoundary({
  filePath,
  content,
  maxLoc = DEFAULT_MAX_LOC,
  minBoundaryLoc = DEFAULT_MIN_BOUNDARY_LOC
}) {
  const effectiveLoc = countEffectiveLoc(content);
  if (effectiveLoc <= maxLoc) {
    return {
      changed: false,
      reason: `skip: effective LOC ${effectiveLoc} <= ${maxLoc}`
    };
  }

  const ast = parseFileContent(filePath, content);
  const programBody = ast.program && Array.isArray(ast.program.body)
    ? ast.program.body
    : [];
  if (programBody.length === 0) {
    return {
      changed: false,
      reason: 'skip: empty program body'
    };
  }

  const moduleExportsInfo = resolveModuleExportsInfo(programBody);
  if (!moduleExportsInfo) {
    return {
      changed: false,
      reason: 'skip: missing module.exports assignment'
    };
  }

  const requireStatements = [];
  const declarationEntries = [];
  let declarationId = 0;

  for (let statementIndex = 0; statementIndex < programBody.length; statementIndex += 1) {
    const statement = programBody[statementIndex];
    if (statementContainsRequire(statement)) {
      requireStatements.push({
        index: statementIndex,
        statement,
        sourceText: content.slice(statement.start, statement.end)
      });
    }

    const definedNames = [...getDefinedNamesFromStatement(statement)];
    if (definedNames.length === 0) {
      continue;
    }

    declarationEntries.push({
      id: declarationId,
      statementIndex,
      statement,
      definedNames,
      sourceText: content.slice(statement.start, statement.end),
      boundaryLabel: resolveBoundaryFromName(definedNames[0]),
      dependencyIds: [],
      componentIndex: -1
    });
    declarationId += 1;
  }

  const exportedIdentifierSet = moduleExportsInfo.exportedIdentifierSet;
  const helperEntries = declarationEntries.filter((entry) => (
    entry.statementIndex < moduleExportsInfo.index
    && !statementContainsRequire(entry.statement)
    && entry.definedNames.every((name) => !exportedIdentifierSet.has(name))
  ));

  if (helperEntries.length === 0) {
    return {
      changed: false,
      reason: 'skip: no helper declarations available for extraction'
    };
  }

  resolveDeclarationDependencies(helperEntries);
  collapseBoundaryByScc(helperEntries);

  const boundaryMap = new Map();
  for (const entry of helperEntries) {
    const currentEntries = boundaryMap.get(entry.boundaryLabel) || [];
    currentEntries.push(entry);
    boundaryMap.set(entry.boundaryLabel, currentEntries);
  }

  if (boundaryMap.has('helpers')) {
    const helperLoc = boundaryMap.get('helpers')
      .map((entry) => countEffectiveLoc(entry.sourceText))
      .reduce((sum, value) => sum + value, 0);
    if (helperLoc < minBoundaryLoc && boundaryMap.size > 1) {
      boundaryMap.delete('helpers');
    }
  }

  const tinyBoundaries = [...boundaryMap.entries()]
    .filter(([label]) => label !== 'helpers')
    .filter(([, entries]) => entries
      .map((entry) => countEffectiveLoc(entry.sourceText))
      .reduce((sum, value) => sum + value, 0) < minBoundaryLoc);

  if (tinyBoundaries.length > 0) {
    const helperEntriesBucket = boundaryMap.get('helpers') || [];
    for (const [, entries] of tinyBoundaries) {
      for (const entry of entries) {
        entry.boundaryLabel = 'helpers';
        helperEntriesBucket.push(entry);
      }
    }
    boundaryMap.set('helpers', helperEntriesBucket);
    for (const [label] of tinyBoundaries) {
      boundaryMap.delete(label);
    }
  }

  if (boundaryMap.size === 0) {
    return {
      changed: false,
      reason: 'skip: extracted boundaries collapsed to empty'
    };
  }

  const stemName = computeStemName(filePath);
  const declarationById = new Map(helperEntries.map((entry) => [entry.id, entry]));
  const requireStatementSource = collectUniqueRequireStatementSource(requireStatements);
  const requireDefinedNameSet = new Set();
  for (const requireStatement of requireStatements) {
    for (const name of getDefinedNamesFromStatement(requireStatement.statement)) {
      requireDefinedNameSet.add(name);
    }
  }

  const minimumBoundaryLoc = Math.max(minBoundaryLoc, LINT_MIN_CAPABILITY_LOC);
  const mergedBoundaryMap = mergeOverFragmentedGroups(
    collapseBoundaryCycles(
      mergeOverFragmentedGroups(boundaryMap, minimumBoundaryLoc)
    ),
    minimumBoundaryLoc
  );
  const boundaryByDeclarationId = new Map();
  const exportedNamesByBoundary = new Map();
  for (const [label, entries] of mergedBoundaryMap.entries()) {
    const exportedNames = normalizeDestructureNames(entries.flatMap((entry) => entry.definedNames));
    exportedNamesByBoundary.set(label, exportedNames);
    for (const entry of entries) {
      boundaryByDeclarationId.set(entry.id, label);
    }
  }

  const boundaryOutputs = [];
  const sortedBoundaryLabels = [...mergedBoundaryMap.keys()].sort((a, b) => {
    const order = ['constants', 'errors', 'normalizers', 'parsers', 'helpers'];
    const indexA = order.indexOf(a);
    const indexB = order.indexOf(b);
    if (indexA === -1 && indexB === -1) {
      return a.localeCompare(b);
    }
    if (indexA === -1) {
      return 1;
    }
    if (indexB === -1) {
      return -1;
    }
    return indexA - indexB;
  });

  for (const label of sortedBoundaryLabels) {
    const entries = (mergedBoundaryMap.get(label) || [])
      .slice()
      .sort((a, b) => a.statementIndex - b.statementIndex);

    const crossBoundaryDependencyMap = new Map();
    for (const entry of entries) {
      for (const dependencyId of entry.dependencyIds || []) {
        const dependencyEntry = declarationById.get(dependencyId);
        if (!dependencyEntry) {
          continue;
        }
        const dependencyBoundaryLabel = boundaryByDeclarationId.get(dependencyId);
        if (!dependencyBoundaryLabel || !mergedBoundaryMap.has(dependencyBoundaryLabel)) {
          continue;
        }
        if (dependencyBoundaryLabel === label) {
          continue;
        }
        const current = crossBoundaryDependencyMap.get(dependencyBoundaryLabel) || new Set();
        for (const name of dependencyEntry.definedNames) {
          if (requireDefinedNameSet.has(name)) {
            continue;
          }
          current.add(name);
        }
        crossBoundaryDependencyMap.set(dependencyBoundaryLabel, current);
      }
    }

    const dependencyRequireStatements = [...crossBoundaryDependencyMap.entries()]
      .sort((a, b) => a[0].localeCompare(b[0]))
      .map(([dependencyLabel, nameSet]) => {
        const names = normalizeDestructureNames([...nameSet]);
        if (names.length === 0) {
          return '';
        }
        return `const { ${names.join(', ')} } = require('./${resolveBoundaryFileName(stemName, dependencyLabel).replace(/\.js$/, '')}');`;
      })
      .filter(Boolean);

    const exportedNames = exportedNamesByBoundary.get(label) || [];
    if (exportedNames.length === 0) {
      continue;
    }

    const sectionParts = [];
    sectionParts.push("'use strict';");
    if (requireStatementSource.length > 0) {
      sectionParts.push(requireStatementSource.join('\n'));
    }
    if (dependencyRequireStatements.length > 0) {
      sectionParts.push(dependencyRequireStatements.join('\n'));
    }
    sectionParts.push(entries.map((entry) => entry.sourceText.trim()).join('\n\n'));
    sectionParts.push(
      `module.exports = {\n  ${exportedNames.join(',\n  ')}\n};`
    );

    const boundaryContent = normalizeSpacing(`${sectionParts.join('\n\n')}\n`);
    const boundaryFileName = resolveBoundaryFileName(stemName, label);
    boundaryOutputs.push({
      label,
      fileName: boundaryFileName,
      absolutePath: path.join(path.dirname(filePath), boundaryFileName),
      content: boundaryContent,
      exportedNames,
      extractedStatementCount: entries.length
    });
  }

  if (boundaryOutputs.length === 0) {
    return {
      changed: false,
      reason: 'skip: no boundary output generated after aggregation'
    };
  }

  const boundaryRequireStatements = boundaryOutputs.map((output) => {
    const modulePath = `./${output.fileName.replace(/\.js$/, '')}`;
    return `const { ${output.exportedNames.join(', ')} } = require('${modulePath}');`;
  });

  let mainContent = content;
  const removalRanges = helperEntries.map((entry) => {
    let start = entry.statement.start;
    let end = entry.statement.end;
    while (start > 0 && /\s/.test(mainContent[start - 1])) {
      if (mainContent[start - 1] === '\n' && (start - 2 < 0 || mainContent[start - 2] === '\n')) {
        break;
      }
      start -= 1;
      if (mainContent[start] === '\n') {
        break;
      }
    }
    while (end < mainContent.length && /\s/.test(mainContent[end])) {
      const ch = mainContent[end];
      end += 1;
      if (ch === '\n') {
        break;
      }
    }
    return { start, end };
  });

  mainContent = removeRangesFromContent(mainContent, removalRanges);

  const insertionStatement = requireStatements.length > 0
    ? requireStatements[requireStatements.length - 1].statement
    : null;
  let insertionOffset = insertionStatement ? insertionStatement.end : 0;
  if (insertionOffset < 0) {
    insertionOffset = 0;
  }

  if (insertionOffset === 0) {
    mainContent = `${boundaryRequireStatements.join('\n')}\n${mainContent}`;
  } else {
    const originalPrefix = content.slice(0, insertionOffset);
    const adjustedPrefix = removeRangesFromContent(originalPrefix, removalRanges);
    const adjustedInsertionOffset = adjustedPrefix.length;
    mainContent = appendBoundaryStatement({
      mainContent,
      insertionOffset: adjustedInsertionOffset,
      boundaryStatement: boundaryRequireStatements.join('\n')
    });
  }

  mainContent = normalizeSpacing(mainContent);

  const bestPracticeIssues = validateBestPracticeOutcome({
    filePath,
    originalContent: content,
    mainContent,
    boundaryOutputs,
    maxLoc,
    minBoundaryLoc
  });

  return {
    changed: true,
    mainContent,
    boundaryOutputs,
    bestPracticeIssues,
    summary: {
      effectiveLoc,
      extractedDeclarations: helperEntries.length,
      boundaryCount: boundaryOutputs.length
    }
  };
}

function cleanupStaleBoundaryFiles({ targetFile, boundaryOutputs }) {
  const directory = path.dirname(targetFile);
  const stemName = computeStemName(targetFile);
  const knownBoundaryFiles = [
    'constants',
    'errors',
    'normalizers',
    'parsers',
    'helpers'
  ].map((label) => path.join(directory, resolveBoundaryFileName(stemName, label)));
  const activeFileSet = new Set(boundaryOutputs.map((output) => output.absolutePath));

  for (const candidatePath of knownBoundaryFiles) {
    if (activeFileSet.has(candidatePath)) {
      continue;
    }
    if (!fs.existsSync(candidatePath)) {
      continue;
    }
    fs.unlinkSync(candidatePath);
  }
}

function collectDefaultTargets(repoRoot) {
  const results = [];
  const stack = [path.join(repoRoot, 'apps/api/src/domains')];
  while (stack.length > 0) {
    const current = stack.pop();
    let entries = [];
    try {
      entries = fs.readdirSync(current, { withFileTypes: true });
    } catch (_error) {
      continue;
    }

    for (const entry of entries) {
      const absolutePath = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(absolutePath);
        continue;
      }
      if (!entry.isFile()) {
        continue;
      }
      const normalized = toPosix(absolutePath);
      if (!SOURCE_EXTENSIONS.test(normalized)) {
        continue;
      }
      if (!DOMAIN_SERVICE_PATH_RE.test(normalized)) {
        continue;
      }
      results.push(absolutePath);
    }
  }
  return results.sort();
}

function parseArgs(argv = []) {
  const options = {
    write: false,
    enforceBestPractice: true,
    maxLoc: DEFAULT_MAX_LOC,
    minBoundaryLoc: DEFAULT_MIN_BOUNDARY_LOC,
    files: []
  };

  const args = [...argv];
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === '--write') {
      options.write = true;
      continue;
    }
    if (arg === '--allow-best-practice-violations') {
      options.enforceBestPractice = false;
      continue;
    }
    if (arg === '--file') {
      const value = String(args[index + 1] || '').trim();
      if (!value) {
        throw new Error('--file requires a value');
      }
      options.files.push(value);
      index += 1;
      continue;
    }
    if (arg === '--max-loc') {
      const value = Number(args[index + 1]);
      if (!Number.isFinite(value) || value <= 0) {
        throw new Error('--max-loc must be a positive number');
      }
      options.maxLoc = Math.floor(value);
      index += 1;
      continue;
    }
    if (arg === '--min-boundary-loc') {
      const value = Number(args[index + 1]);
      if (!Number.isFinite(value) || value < 0) {
        throw new Error('--min-boundary-loc must be a non-negative number');
      }
      options.minBoundaryLoc = Math.floor(value);
      index += 1;
      continue;
    }
    throw new Error(`unknown argument: ${arg}`);
  }

  return options;
}

function runWithOptions(options = {}) {
  const repoRoot = path.resolve(__dirname, '..', '..');
  const targetFiles = (options.files || []).length > 0
    ? options.files.map((filePath) => path.resolve(repoRoot, filePath))
    : collectDefaultTargets(repoRoot);

  if (targetFiles.length === 0) {
    console.log('[split-domain-file-by-boundary] no target files found');
    return { changedCount: 0, skippedCount: 0 };
  }

  let changedCount = 0;
  let skippedCount = 0;

  for (const targetFile of targetFiles) {
    const normalizedTargetFile = toPosix(targetFile);
    if (!SUPPORTED_EXTENSIONS.has(path.extname(targetFile))) {
      console.log(`[split-domain-file-by-boundary] skip unsupported extension: ${normalizedTargetFile}`);
      skippedCount += 1;
      continue;
    }

    let content = '';
    try {
      content = fs.readFileSync(targetFile, 'utf8');
    } catch (error) {
      console.error(`[split-domain-file-by-boundary] read failed: ${normalizedTargetFile} (${error.message})`);
      skippedCount += 1;
      continue;
    }

    let result = null;
    try {
      result = transformDomainFileByBoundary({
        filePath: targetFile,
        content,
        maxLoc: options.maxLoc,
        minBoundaryLoc: options.minBoundaryLoc
      });
    } catch (error) {
      console.error(`[split-domain-file-by-boundary] transform failed: ${normalizedTargetFile} (${error.message})`);
      skippedCount += 1;
      continue;
    }

    if (!result.changed) {
      console.log(`[split-domain-file-by-boundary] ${normalizedTargetFile}: ${result.reason}`);
      skippedCount += 1;
      continue;
    }

    const boundarySummary = result.boundaryOutputs
      .map((output) => `${output.label}:${output.extractedStatementCount}`)
      .join(', ');
    const issueSummary = Array.isArray(result.bestPracticeIssues) && result.bestPracticeIssues.length > 0
      ? `, best-practice-issues=${result.bestPracticeIssues.length}`
      : '';
    console.log(
      `[split-domain-file-by-boundary] ${options.write ? 'split' : 'plan split'} ${normalizedTargetFile} -> ${result.boundaryOutputs.length} boundaries (${boundarySummary}${issueSummary})`
    );

    if (Array.isArray(result.bestPracticeIssues) && result.bestPracticeIssues.length > 0) {
      for (const issue of result.bestPracticeIssues) {
        console.error(`  - ${issue}`);
      }
      if (options.enforceBestPractice) {
        console.error(
          `[split-domain-file-by-boundary] blocked by best-practice enforcement: ${normalizedTargetFile}`
        );
        skippedCount += 1;
        continue;
      }
    }

    if (!options.write) {
      changedCount += 1;
      continue;
    }

    fs.writeFileSync(targetFile, result.mainContent, 'utf8');
    for (const boundaryOutput of result.boundaryOutputs) {
      fs.writeFileSync(boundaryOutput.absolutePath, boundaryOutput.content, 'utf8');
    }
    cleanupStaleBoundaryFiles({
      targetFile,
      boundaryOutputs: result.boundaryOutputs
    });
    changedCount += 1;
  }

  console.log(
    `[split-domain-file-by-boundary] done: changed=${changedCount}, skipped=${skippedCount}, write=${options.write}`
  );
  return { changedCount, skippedCount };
}

function main() {
  const options = parseArgs(process.argv.slice(2));
  runWithOptions(options);
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`[split-domain-file-by-boundary] ${error.message}`);
    console.error(
      'Usage: node tools/codemods/split-domain-file-by-boundary.js [--write] [--file <relative-path>] [--max-loc <n>] [--min-boundary-loc <n>] [--allow-best-practice-violations]'
    );
    process.exit(1);
  }
}

module.exports = {
  transformDomainFileByBoundary,
  _internals: {
    countEffectiveLoc,
    resolveBoundaryFromName,
    collectNameTokens,
    getDefinedNamesFromStatement,
    resolveDeclarationDependencies,
    resolveStronglyConnectedComponents,
    collapseBoundaryByScc,
    computeStemName,
    resolveBoundaryFileName,
    normalizeSpacing,
    validateBestPracticeOutcome,
    countExportStatements,
    resolveRequireStatementSignature,
    collectUniqueRequireStatementSource,
    normalizeRemovalRanges
  },
  runWithOptions
};
