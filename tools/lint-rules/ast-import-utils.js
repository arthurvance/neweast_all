'use strict';

const path = require('node:path');
const { parse } = require('@babel/parser');

const PARSE_OPTIONS = {
  sourceType: 'unambiguous',
  allowReturnOutsideFunction: true,
  allowAwaitOutsideFunction: true,
  plugins: ['jsx', 'typescript']
};

function toPosix(value) {
  return String(value).replace(/\\/g, '/');
}

function resolveSpecifier(filePath, specifier) {
  if (specifier.startsWith('.')) {
    return toPosix(path.resolve(path.dirname(filePath), specifier));
  }
  return toPosix(specifier);
}

function readStaticStringNode(node) {
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
    && node.expressions
    && node.expressions.length === 0
    && node.quasis
    && node.quasis.length === 1
  ) {
    return node.quasis[0].value.cooked || node.quasis[0].value.raw || '';
  }

  if (node.type === 'TSLiteralType') {
    return readStaticStringNode(node.literal);
  }

  return null;
}

function collectImportSpecifiers(content, filePath) {
  let ast;
  try {
    ast = parse(content, PARSE_OPTIONS);
  } catch (error) {
    return {
      specifiers: [],
      parseError: `failed to parse ${toPosix(filePath)}: ${error.message}`
    };
  }

  const specifiers = [];
  const seen = new Set();
  const stack = [ast];

  const pushSpecifier = (node) => {
    const value = readStaticStringNode(node);
    if (typeof value !== 'string' || value.length === 0) {
      return;
    }
    if (seen.has(value)) {
      return;
    }
    seen.add(value);
    specifiers.push(value);
  };

  while (stack.length > 0) {
    const node = stack.pop();
    if (!node || typeof node !== 'object') {
      continue;
    }

    switch (node.type) {
      case 'ImportDeclaration':
      case 'ExportAllDeclaration':
        pushSpecifier(node.source);
        break;
      case 'ExportNamedDeclaration':
        if (node.source) {
          pushSpecifier(node.source);
        }
        break;
      case 'ImportExpression':
        pushSpecifier(node.source);
        break;
      case 'CallExpression':
        if (
          node.callee
          && node.callee.type === 'Identifier'
          && node.callee.name === 'require'
          && Array.isArray(node.arguments)
          && node.arguments.length >= 1
        ) {
          pushSpecifier(node.arguments[0]);
        }
        break;
      case 'TSImportType':
        pushSpecifier(node.argument);
        break;
      default:
        break;
    }

    for (const value of Object.values(node)) {
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

  return {
    specifiers,
    parseError: null
  };
}

module.exports = {
  collectImportSpecifiers,
  resolveSpecifier,
  toPosix,
  _internals: {
    readStaticStringNode
  }
};
