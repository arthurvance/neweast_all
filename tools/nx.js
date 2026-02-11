#!/usr/bin/env node
const { existsSync, readFileSync } = require('node:fs');
const { resolve } = require('node:path');
const { spawnSync } = require('node:child_process');

const root = process.cwd();
const nxConfigPath = resolve(root, 'nx.json');

if (!existsSync(nxConfigPath)) {
  console.error('nx.json not found in workspace root');
  process.exit(1);
}

const nxConfig = JSON.parse(readFileSync(nxConfigPath, 'utf8'));

const loadProject = (name) => {
  const rootDir = nxConfig.projects?.[name]?.root;
  if (!rootDir) {
    return null;
  }

  const projectConfigPath = resolve(root, rootDir, 'project.json');
  if (!existsSync(projectConfigPath)) {
    return null;
  }

  return {
    name,
    rootDir,
    config: JSON.parse(readFileSync(projectConfigPath, 'utf8'))
  };
};

const runCommand = (command, label) => {
  console.log(`\n> ${label}`);
  const result = spawnSync('zsh', ['-lc', command], {
    cwd: root,
    stdio: 'inherit',
    env: process.env
  });
  return result.status || 0;
};

const args = process.argv.slice(2);
if (args.length === 0) {
  console.error('Usage: pnpm nx <target> [project] | pnpm nx run <project>:<target>');
  process.exit(1);
}

let target = null;
let selectedProject = null;

if (args[0] === 'run') {
  if (!args[1] || !args[1].includes(':')) {
    console.error('Usage: pnpm nx run <project>:<target>');
    process.exit(1);
  }
  const [projectName, runTarget] = args[1].split(':');
  selectedProject = projectName;
  target = runTarget;
} else {
  target = args[0];
  selectedProject = args[1] || null;
}

const knownTargets = new Set(['lint', 'build', 'test', 'smoke']);
if (!knownTargets.has(target)) {
  console.error(`Unsupported target: ${target}`);
  process.exit(1);
}

const projectNames = selectedProject
  ? [selectedProject]
  : Object.keys(nxConfig.projects || {});

if (projectNames.length === 0) {
  console.error('No projects configured in nx.json');
  process.exit(1);
}

let failed = false;
for (const projectName of projectNames) {
  const project = loadProject(projectName);
  if (!project) {
    console.error(`Missing project.json for project: ${projectName}`);
    failed = true;
    break;
  }

  const targetConfig = project.config.targets?.[target];
  if (!targetConfig || !targetConfig.command) {
    console.error(`Missing target command for ${projectName}:${target}`);
    failed = true;
    break;
  }

  const status = runCommand(targetConfig.command, `nx ${target} ${projectName}`);
  if (status !== 0) {
    failed = true;
    break;
  }
}

if (!failed && target === 'smoke' && !selectedProject) {
  const smokeStatus = runCommand('node tools/smoke.js', 'workspace smoke chain');
  if (smokeStatus !== 0) {
    failed = true;
  }
}

process.exit(failed ? 1 : 0);
