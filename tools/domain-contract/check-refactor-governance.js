#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const MILESTONE_STATUS_SET = new Set(['pending', 'in-progress', 'completed']);
const DIFF_STATUS_SET = new Set(['pending', 'accepted', 'rejected']);
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const REVIEW_STATUS_SET = new Set(['pass', 'needs-fix']);
const REQUIRED_DIFF_JUSTIFICATION_HEADINGS = [
  '## Summary',
  '## Difference Type',
  '## What Changed',
  '## Why It Is Acceptable',
  '## Guardrails',
  '## Approval'
];
const GOVERNED_BASELINE_FILE_PATTERNS = [
  /^apps\/api\/test\/contracts\/.+\.snapshot\.json$/,
  /^apps\/api\/test\/fixtures\/golden-(?:user|data)-side\.json$/,
  /^apps\/web\/test\/visual-baseline\/.+\.json$/
];

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

function readText(targetPath, errors) {
  try {
    return fs.readFileSync(targetPath, 'utf8');
  } catch (error) {
    errors.push(`failed to read file ${toPosix(targetPath)}: ${error.message}`);
    return '';
  }
}

function readJson(targetPath, errors) {
  try {
    return JSON.parse(fs.readFileSync(targetPath, 'utf8'));
  } catch (error) {
    errors.push(`failed to read JSON ${toPosix(targetPath)}: ${error.message}`);
    return null;
  }
}

function parseTaskStatusFromSpec(specContent) {
  const checkedStatusByTask = new Map();
  const taskLinePattern = /^- \[(x| )\] Task (\d+):/gm;
  let match = taskLinePattern.exec(specContent);
  while (match) {
    const isChecked = match[1] === 'x';
    const taskId = Number(match[2]);
    checkedStatusByTask.set(taskId, isChecked);
    match = taskLinePattern.exec(specContent);
  }
  return checkedStatusByTask;
}

function parseAcStatusFromSpec(specContent) {
  const checkedStatusByAc = new Map();
  const acLinePattern = /^- \[(x| )\] AC (\d+):/gm;
  let match = acLinePattern.exec(specContent);
  while (match) {
    const isChecked = match[1] === 'x';
    const acId = Number(match[2]);
    checkedStatusByAc.set(acId, isChecked);
    match = acLinePattern.exec(specContent);
  }
  return checkedStatusByAc;
}

function parseMilestonesFromYaml(yamlContent) {
  const lines = String(yamlContent || '').split(/\r?\n/);
  const milestones = [];
  let currentMilestone = null;
  let collectingTasks = false;

  const flushCurrentMilestone = () => {
    if (!currentMilestone) {
      return;
    }
    milestones.push(currentMilestone);
    currentMilestone = null;
    collectingTasks = false;
  };

  for (const line of lines) {
    const milestoneMatch = line.match(/^\s*-\s+id:\s*([A-Za-z0-9_-]+)\s*$/);
    if (milestoneMatch) {
      flushCurrentMilestone();
      currentMilestone = {
        id: milestoneMatch[1],
        status: '',
        tasks: []
      };
      continue;
    }

    if (!currentMilestone) {
      continue;
    }

    const statusMatch = line.match(/^\s{4}status:\s*([a-z-]+)\s*$/);
    if (statusMatch) {
      currentMilestone.status = statusMatch[1];
      collectingTasks = false;
      continue;
    }

    if (/^\s{4}tasks:\s*$/.test(line)) {
      collectingTasks = true;
      continue;
    }

    if (!collectingTasks) {
      continue;
    }

    const taskMatch = line.match(/^\s{6}-\s*(\d+)\s*$/);
    if (taskMatch) {
      currentMilestone.tasks.push(Number(taskMatch[1]));
      continue;
    }

    if (!/^\s{6}/.test(line)) {
      collectingTasks = false;
    }
  }

  flushCurrentMilestone();
  return milestones;
}

function parseScopeFreezeEnabled(yamlContent) {
  const lines = String(yamlContent || '').split(/\r?\n/);
  let inScopeFreeze = false;
  for (const line of lines) {
    if (/^scope_freeze:\s*$/.test(line)) {
      inScopeFreeze = true;
      continue;
    }
    if (!inScopeFreeze) {
      continue;
    }
    if (/^[^\s]/.test(line)) {
      break;
    }
    const enabledMatch = line.match(/^\s{2}enabled:\s*(true|false)\s*$/);
    if (enabledMatch) {
      return enabledMatch[1] === 'true';
    }
  }
  return false;
}

function normalizeToRelativePath(repoRoot, candidatePath) {
  const rawPath = toPosix(String(candidatePath || '').trim());
  if (!rawPath) {
    return '';
  }
  if (path.isAbsolute(rawPath)) {
    return toPosix(path.relative(repoRoot, rawPath));
  }
  return rawPath.replace(/^\.\//, '');
}

function parseChangedFilesFromEnv(rawValue) {
  return String(rawValue || '')
    .split(/[\n,]/)
    .map((item) => item.trim())
    .filter(Boolean);
}

function parseChangedFilesFromGitStatus(statusOutput) {
  const changedFiles = [];
  for (const line of String(statusOutput || '').split(/\r?\n/)) {
    if (!line || line.length < 4) {
      continue;
    }
    let normalizedPath = line.slice(3).trim();
    if (!normalizedPath) {
      continue;
    }
    if (normalizedPath.includes(' -> ')) {
      const parts = normalizedPath.split(' -> ');
      normalizedPath = parts[parts.length - 1].trim();
    }
    if (normalizedPath.startsWith('"') && normalizedPath.endsWith('"')) {
      try {
        normalizedPath = JSON.parse(normalizedPath);
      } catch (_error) {
        // ignore malformed quoted path and continue with raw value
      }
    }
    changedFiles.push(toPosix(normalizedPath));
  }
  return changedFiles;
}

function collectChangedFiles({
  repoRoot,
  changedFiles,
  errors
}) {
  if (Array.isArray(changedFiles)) {
    return changedFiles
      .map((entry) => normalizeToRelativePath(repoRoot, entry))
      .filter(Boolean);
  }

  const envChangedFiles = parseChangedFilesFromEnv(process.env.REFACTOR_GOVERNANCE_CHANGED_FILES);
  if (envChangedFiles.length > 0) {
    return envChangedFiles
      .map((entry) => normalizeToRelativePath(repoRoot, entry))
      .filter(Boolean);
  }

  const gitStatusResult = spawnSync(
    'git',
    ['-C', repoRoot, 'status', '--porcelain', '--untracked-files=all'],
    { encoding: 'utf8' }
  );
  if (gitStatusResult.status !== 0) {
    const errorOutput = String(gitStatusResult.stderr || gitStatusResult.stdout || '').trim();
    if (/not a git repository/i.test(errorOutput)) {
      return [];
    }
    errors.push(`failed to collect changed files from git status: ${errorOutput || 'unknown error'}`);
    return [];
  }
  return parseChangedFilesFromGitStatus(gitStatusResult.stdout)
    .map((entry) => normalizeToRelativePath(repoRoot, entry))
    .filter(Boolean);
}

function isGovernedBaselineFile(relativePath) {
  const normalizedPath = toPosix(relativePath).replace(/^\/+/, '');
  return GOVERNED_BASELINE_FILE_PATTERNS.some((pattern) => pattern.test(normalizedPath));
}

function validateMilestoneProgression({
  milestones,
  taskStatusByTaskId,
  errors
}) {
  if (!Array.isArray(milestones) || milestones.length === 0) {
    errors.push('refactor milestones file must provide at least one milestone');
    return;
  }

  let inProgressCount = 0;
  let inProgressIndex = -1;
  let seenPending = false;
  for (let index = 0; index < milestones.length; index += 1) {
    const milestone = milestones[index];
    const status = String(milestone.status || '').trim();
    if (!MILESTONE_STATUS_SET.has(status)) {
      errors.push(
        `milestone ${milestone.id || `#${index + 1}`} has invalid status: ${status || '(missing)'}`
      );
      continue;
    }

    if (status === 'in-progress') {
      inProgressCount += 1;
      inProgressIndex = index;
    }
    if (status === 'pending') {
      seenPending = true;
    }
    if (status === 'completed' && seenPending) {
      errors.push(
        `milestone ${milestone.id} cannot be completed after a pending milestone`
      );
    }

    if ((status === 'in-progress' || status === 'completed') && index > 0) {
      for (let previousIndex = 0; previousIndex < index; previousIndex += 1) {
        const previous = milestones[previousIndex];
        if (previous.status !== 'completed') {
          errors.push(
            `milestone ${milestone.id} cannot start before ${previous.id} is completed`
          );
          break;
        }
      }
    }

    if (status !== 'completed') {
      continue;
    }
    for (const taskId of milestone.tasks || []) {
      const taskChecked = taskStatusByTaskId.get(taskId);
      if (taskChecked !== true) {
        errors.push(
          `milestone ${milestone.id} is completed but Task ${taskId} is not checked in tech spec`
        );
      }
    }
  }

  if (inProgressCount > 1) {
    errors.push(`only one milestone can be in-progress, received ${inProgressCount}`);
  }
  if (inProgressIndex !== -1) {
    for (let index = inProgressIndex + 1; index < milestones.length; index += 1) {
      if (milestones[index].status !== 'pending') {
        errors.push(
          `milestone ${milestones[index].id} must remain pending while ${milestones[inProgressIndex].id} is in-progress`
        );
      }
    }
  }
}

function resolveDiffJustificationPath(repoRoot, entry) {
  const rawPath = String(entry.justification_file || '').trim();
  if (!rawPath) {
    return '';
  }
  if (path.isAbsolute(rawPath)) {
    return rawPath;
  }
  return path.join(repoRoot, rawPath);
}

function validateDiffRegister({
  repoRoot,
  diffRegister,
  errors
}) {
  const acceptedDiffEntries = [];
  if (!diffRegister || typeof diffRegister !== 'object') {
    errors.push('spec diff register must be a JSON object');
    return acceptedDiffEntries;
  }
  if (!Array.isArray(diffRegister.entries)) {
    errors.push('spec diff register must provide an entries array');
    return acceptedDiffEntries;
  }

  for (let index = 0; index < diffRegister.entries.length; index += 1) {
    const entry = diffRegister.entries[index] || {};
    const status = String(entry.status || '').trim();
    if (!DIFF_STATUS_SET.has(status)) {
      errors.push(`diff entries[${index}] has invalid status: ${status || '(missing)'}`);
      continue;
    }

    if (status !== 'accepted') {
      continue;
    }

    const changeId = String(entry.change_id || '').trim();
    if (!changeId) {
      errors.push(`accepted diff entries[${index}] missing change_id`);
    }
    const responsibleEngineer = String(entry.responsible_engineer || '').trim();
    if (!responsibleEngineer) {
      errors.push(`accepted diff ${changeId || `entries[${index}]`} missing responsible_engineer`);
    }
    const reviewer = String(entry.reviewer || '').trim();
    if (!reviewer) {
      errors.push(`accepted diff ${changeId || `entries[${index}]`} missing reviewer`);
    }
    const signedAt = String(entry.signed_at || '').trim();
    if (!DATE_RE.test(signedAt)) {
      errors.push(`accepted diff ${changeId || `entries[${index}]`} has invalid signed_at: ${signedAt || '(missing)'}`);
    }

    const affectedFiles = Array.isArray(entry.affected_files)
      ? entry.affected_files
          .map((candidate) => normalizeToRelativePath(repoRoot, candidate))
          .filter(Boolean)
      : [];
    if (affectedFiles.length === 0) {
      errors.push(
        `accepted diff ${changeId || `entries[${index}]`} must declare affected_files for change traceability`
      );
    }
    acceptedDiffEntries.push({
      changeId: changeId || `entries[${index}]`,
      affectedFiles
    });

    const justificationPath = resolveDiffJustificationPath(repoRoot, entry);
    if (!justificationPath || !isFile(justificationPath)) {
      errors.push(
        `accepted diff ${changeId || `entries[${index}]`} missing spec diff justification file: ${toPosix(justificationPath || '(missing)')}`
      );
      continue;
    }

    let justificationContent = '';
    try {
      justificationContent = fs.readFileSync(justificationPath, 'utf8');
    } catch (error) {
      errors.push(
        `failed to read spec diff justification ${toPosix(justificationPath)}: ${error.message}`
      );
      continue;
    }

    for (const heading of REQUIRED_DIFF_JUSTIFICATION_HEADINGS) {
      if (!justificationContent.includes(heading)) {
        errors.push(
          `accepted diff ${changeId || `entries[${index}]`} missing heading "${heading}" in ${toPosix(justificationPath)}`
        );
      }
    }

    if (/<[^>]+>/.test(justificationContent)) {
      errors.push(
        `accepted diff ${changeId || `entries[${index}]`} contains unresolved placeholders in ${toPosix(justificationPath)}`
      );
    }
  }
  return acceptedDiffEntries;
}

function matchesAffectedPath(changedPath, affectedPath) {
  const normalizedChangedPath = toPosix(String(changedPath || '').trim()).replace(/^\/+/, '');
  const normalizedAffectedPath = toPosix(String(affectedPath || '').trim()).replace(/^\/+/, '');
  if (!normalizedAffectedPath) {
    return false;
  }
  if (normalizedAffectedPath.endsWith('/')) {
    return normalizedChangedPath.startsWith(normalizedAffectedPath);
  }
  return normalizedChangedPath === normalizedAffectedPath;
}

function validateGovernedBaselineDiffCoverage({
  changedFiles,
  acceptedDiffEntries,
  errors
}) {
  const governedChangedFiles = changedFiles.filter((filePath) => isGovernedBaselineFile(filePath));
  if (governedChangedFiles.length === 0) {
    return;
  }

  if (!Array.isArray(acceptedDiffEntries) || acceptedDiffEntries.length === 0) {
    errors.push(
      `governed snapshot/baseline files changed without accepted diff record: ${governedChangedFiles.join(', ')}`
    );
    return;
  }

  for (const changedFile of governedChangedFiles) {
    const covered = acceptedDiffEntries.some((entry) =>
      Array.isArray(entry.affectedFiles)
      && entry.affectedFiles.some((affectedPath) => matchesAffectedPath(changedFile, affectedPath))
    );
    if (!covered) {
      errors.push(
        `governed snapshot/baseline change requires accepted diff affected_files coverage: ${changedFile}`
      );
    }
  }
}

function validateReviewRecord({
  reviewRecord,
  taskStatusByTaskId,
  acStatusByAcId,
  errors
}) {
  if (!reviewRecord || typeof reviewRecord !== 'object') {
    errors.push('refactor review record must be a JSON object');
    return;
  }
  if (!Array.isArray(reviewRecord.reviews)) {
    errors.push('refactor review record must provide a reviews array');
    return;
  }

  const reviewByTaskId = new Map();
  for (let index = 0; index < reviewRecord.reviews.length; index += 1) {
    const review = reviewRecord.reviews[index] || {};
    const taskId = Number(review.task_id);
    if (!Number.isInteger(taskId) || taskId <= 0) {
      errors.push(`reviews[${index}] has invalid task_id: ${review.task_id}`);
      continue;
    }
    if (reviewByTaskId.has(taskId)) {
      errors.push(`duplicate review record for Task ${taskId}`);
      continue;
    }

    const bestPracticeStatus = String(review.best_practice_status || '').trim();
    if (!REVIEW_STATUS_SET.has(bestPracticeStatus)) {
      errors.push(
        `reviews[${index}] has invalid best_practice_status: ${bestPracticeStatus || '(missing)'}`
      );
    }
    const reviewer = String(review.reviewer || '').trim();
    if (!reviewer) {
      errors.push(`reviews[${index}] missing reviewer`);
    }
    const reviewedAt = String(review.reviewed_at || '').trim();
    if (!DATE_RE.test(reviewedAt)) {
      errors.push(`reviews[${index}] has invalid reviewed_at: ${reviewedAt || '(missing)'}`);
    }

    if (Object.prototype.hasOwnProperty.call(review, 'related_ac')) {
      if (!Array.isArray(review.related_ac)) {
        errors.push(`reviews[${index}] related_ac must be an array`);
      } else {
        for (const acId of review.related_ac) {
          if (!Number.isInteger(acId) || acId <= 0) {
            errors.push(`reviews[${index}] contains invalid related_ac id: ${acId}`);
            continue;
          }
          if (!acStatusByAcId.has(acId)) {
            errors.push(`reviews[${index}] references unknown AC ${acId}`);
          }
        }
      }
    }

    reviewByTaskId.set(taskId, review);
  }

  for (const [taskId, isChecked] of taskStatusByTaskId.entries()) {
    if (!isChecked) {
      continue;
    }
    const review = reviewByTaskId.get(taskId);
    if (!review) {
      errors.push(`checked Task ${taskId} is missing review record`);
      continue;
    }

    if (String(review.best_practice_status || '').trim() !== 'pass') {
      errors.push(`checked Task ${taskId} must have best_practice_status=pass`);
    }
    if (review.minimal_change_fallback !== false) {
      errors.push(`checked Task ${taskId} cannot use minimal_change_fallback`);
    }

    if (!Array.isArray(review.related_ac) || review.related_ac.length === 0) {
      errors.push(`checked Task ${taskId} must map to at least one AC via related_ac`);
      continue;
    }

    const hasCheckedAc = review.related_ac.some((acId) => acStatusByAcId.get(acId) === true);
    if (!hasCheckedAc) {
      errors.push(`checked Task ${taskId} related_ac must include at least one checked AC`);
    }
  }
}

function runRefactorGovernanceCheck(options = {}) {
  const errors = [];
  const repoRoot = options.repoRoot || path.resolve(__dirname, '../..');
  const specPath = options.specPath || path.join(
    repoRoot,
    '_bmad-output/implementation-artifacts/tech-spec-platform-tenant-domain-structure-refactor.md'
  );
  const milestonesPath = options.milestonesPath || path.join(
    repoRoot,
    '_bmad-output/implementation-artifacts/refactor-milestones.yaml'
  );
  const diffRegisterPath = options.diffRegisterPath || path.join(
    repoRoot,
    '_bmad-output/implementation-artifacts/spec-diff-register.json'
  );
  const reviewRecordPath = options.reviewRecordPath || path.join(
    repoRoot,
    '_bmad-output/implementation-artifacts/refactor-review-record.json'
  );

  const specContent = readText(specPath, errors);
  const milestonesContent = readText(milestonesPath, errors);
  const diffRegister = readJson(diffRegisterPath, errors);
  const reviewRecord = readJson(reviewRecordPath, errors);

  if (!parseScopeFreezeEnabled(milestonesContent)) {
    errors.push('scope_freeze.enabled must be true in refactor milestones');
  }

  const milestones = parseMilestonesFromYaml(milestonesContent);
  const taskStatusByTaskId = parseTaskStatusFromSpec(specContent);
  const acStatusByAcId = parseAcStatusFromSpec(specContent);
  const changedFiles = collectChangedFiles({
    repoRoot,
    changedFiles: options.changedFiles,
    errors
  });

  validateMilestoneProgression({
    milestones,
    taskStatusByTaskId,
    errors
  });

  const acceptedDiffEntries = validateDiffRegister({
    repoRoot,
    diffRegister,
    errors
  });
  validateGovernedBaselineDiffCoverage({
    changedFiles,
    acceptedDiffEntries,
    errors
  });
  validateReviewRecord({
    reviewRecord,
    taskStatusByTaskId,
    acStatusByAcId,
    errors
  });

  return {
    ok: errors.length === 0,
    milestones_checked: milestones.length,
    tasks_indexed: taskStatusByTaskId.size,
    acceptance_criteria_indexed: acStatusByAcId.size,
    accepted_diffs_checked: Array.isArray(diffRegister && diffRegister.entries)
      ? diffRegister.entries.filter((entry) => entry && entry.status === 'accepted').length
      : 0,
    reviewed_tasks_checked: Array.isArray(reviewRecord && reviewRecord.reviews)
      ? reviewRecord.reviews.length
      : 0,
    errors
  };
}

function main() {
  const report = runRefactorGovernanceCheck();
  if (!report.ok) {
    console.error('[check-refactor-governance] governance check failed.');
    for (const issue of report.errors) {
      console.error(` - ${issue}`);
    }
    process.exit(1);
  }

  console.log(
    `[check-refactor-governance] passed (milestones=${report.milestones_checked}, tasks=${report.tasks_indexed}, ac=${report.acceptance_criteria_indexed}, accepted_diffs=${report.accepted_diffs_checked}, reviewed_tasks=${report.reviewed_tasks_checked}).`
  );
}

if (require.main === module) {
  main();
}

module.exports = {
  runRefactorGovernanceCheck,
  _internals: {
    parseTaskStatusFromSpec,
    parseAcStatusFromSpec,
    parseMilestonesFromYaml,
    parseScopeFreezeEnabled,
    normalizeToRelativePath,
    parseChangedFilesFromEnv,
    parseChangedFilesFromGitStatus,
    collectChangedFiles,
    isGovernedBaselineFile,
    validateMilestoneProgression,
    validateDiffRegister,
    validateGovernedBaselineDiffCoverage,
    matchesAffectedPath,
    validateReviewRecord,
    resolveDiffJustificationPath
  }
};
