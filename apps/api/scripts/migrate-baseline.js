#!/usr/bin/env node
const { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } = require('node:fs');
const { dirname, resolve } = require('node:path');
const { randomUUID } = require('node:crypto');
const { DataSource } = require('typeorm');
const { readConfig } = require('../src/config/env');
const { log } = require('../src/common/logger');

const SCHEMA_MIGRATION_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  version VARCHAR(255) NOT NULL,
  description VARCHAR(255) NOT NULL,
  executed_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_schema_migrations_version (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`;

const MIGRATION_LOCK_NAME = 'neweast_schema_migrations_lock';

const parseArgs = (argv) => {
  const mode = argv.includes('--down') ? 'down' : 'up';
  const versionArg = argv.find((arg) => arg.startsWith('--version='));
  const version = versionArg ? versionArg.split('=')[1] : '';
  return {
    mode,
    version: String(version || '').trim() || null
  };
};

const normalizeVersion = (value) => String(value || '').trim();

const resolveRollbackVersion = ({ existingRows, targetVersion }) => {
  const appliedDesc = [...(Array.isArray(existingRows) ? existingRows : [])].sort(
    (a, b) => Number(b.id) - Number(a.id)
  );
  const latestAppliedVersion = normalizeVersion(appliedDesc[0]?.version);
  if (!latestAppliedVersion) {
    return '';
  }

  const normalizedTargetVersion = normalizeVersion(targetVersion);
  if (!normalizedTargetVersion) {
    return latestAppliedVersion;
  }

  const isApplied = appliedDesc.some((row) => normalizeVersion(row.version) === normalizedTargetVersion);
  if (!isApplied) {
    throw new Error(`Version ${normalizedTargetVersion} is not currently applied`);
  }

  if (normalizedTargetVersion !== latestAppliedVersion) {
    throw new Error(
      `Only latest applied migration can be rolled back. Requested ${normalizedTargetVersion}, latest is ${latestAppliedVersion}`
    );
  }

  return normalizedTargetVersion;
};

const splitStatements = (sqlContent) =>
  sqlContent
    .split(';')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);

const versionFromMigrationFile = (fileName) =>
  fileName
    .replace(/\.up\.sql$/i, '')
    .replace(/\.sql$/i, '')
    .trim();

const resolveMigrationFiles = (migrationDir) => {
  const allSqlFiles = readdirSync(migrationDir)
    .filter((name) => name.endsWith('.sql'))
    .sort();

  const upFiles = allSqlFiles.filter((name) => !name.endsWith('.down.sql'));

  return {
    allSqlFiles,
    upFiles
  };
};

const DDL_STATEMENT_PREFIXES = [
  'CREATE TABLE',
  'ALTER TABLE',
  'DROP TABLE',
  'CREATE INDEX',
  'DROP INDEX',
  'TRUNCATE TABLE',
  'RENAME TABLE'
];

const isDdlStatement = (statement) => {
  const normalized = String(statement || '').trim().toUpperCase();
  return DDL_STATEMENT_PREFIXES.some((prefix) => normalized.startsWith(prefix));
};

const shouldRunStatementsInTransaction = (statements) =>
  !(Array.isArray(statements) ? statements : []).some((statement) =>
    isDdlStatement(statement)
  );

const isRecoverableMigrationError = (statement, error) => {
  const errorCode = String(error?.code || '').toUpperCase();
  const errorNo = Number(error?.errno || 0);
  const normalizedStatement = String(statement || '').trim().toUpperCase();

  const duplicateOrMissingCodes = new Set([
    'ER_TABLE_EXISTS_ERROR',
    'ER_DUP_FIELDNAME',
    'ER_DUP_KEYNAME',
    'ER_CANT_DROP_FIELD_OR_KEY',
    'ER_BAD_TABLE_ERROR'
  ]);
  const duplicateOrMissingErrnos = new Set([1050, 1060, 1061, 1091, 1051]);

  if (!duplicateOrMissingCodes.has(errorCode) && !duplicateOrMissingErrnos.has(errorNo)) {
    return false;
  }

  return (
    normalizedStatement.startsWith('CREATE TABLE') ||
    normalizedStatement.startsWith('CREATE INDEX') ||
    normalizedStatement.startsWith('DROP TABLE') ||
    normalizedStatement.startsWith('DROP INDEX') ||
    normalizedStatement.startsWith('ALTER TABLE')
  );
};

const executeStatements = async ({ queryRunner, statements, requestId, migrationTag }) => {
  for (const statement of statements) {
    try {
      await queryRunner.query(statement);
    } catch (error) {
      if (isRecoverableMigrationError(statement, error)) {
        log('warn', 'Ignoring recoverable migration SQL error', {
          request_id: requestId,
          migration: migrationTag,
          error_code: String(error.code || ''),
          detail: error.message
        });
        continue;
      }
      throw error;
    }
  }
};

const runWithTransaction = async (appDataSource, runner) => {
  const queryRunner = appDataSource.createQueryRunner();
  await queryRunner.connect();
  await queryRunner.startTransaction();
  try {
    const result = await runner(queryRunner);
    await queryRunner.commitTransaction();
    return result;
  } catch (error) {
    await queryRunner.rollbackTransaction();
    throw error;
  } finally {
    await queryRunner.release();
  }
};

const runWithQueryRunner = async (appDataSource, runner) => {
  const queryRunner = appDataSource.createQueryRunner();
  await queryRunner.connect();
  try {
    return await runner(queryRunner);
  } finally {
    await queryRunner.release();
  }
};

const executeMigrationStatements = async ({
  appDataSource,
  statements,
  requestId,
  migrationTag,
  afterExecute
}) => {
  const runInTransaction = shouldRunStatementsInTransaction(statements);
  const runner = async (queryRunner) => {
    await executeStatements({
      queryRunner,
      statements,
      requestId,
      migrationTag
    });
    if (typeof afterExecute === 'function') {
      await afterExecute(queryRunner);
    }
  };

  if (runInTransaction) {
    await runWithTransaction(appDataSource, runner);
    return;
  }

  log('warn', 'Executing migration without transaction because MySQL DDL is non-atomic', {
    request_id: requestId,
    migration: migrationTag
  });
  await runWithQueryRunner(appDataSource, runner);
};

const acquireMigrationLock = async (appDataSource) => {
  const rows = await appDataSource.query('SELECT GET_LOCK(?, 30) AS lock_acquired', [
    MIGRATION_LOCK_NAME
  ]);
  const acquired = Number(rows?.[0]?.lock_acquired || 0) === 1;
  if (!acquired) {
    throw new Error('Could not acquire migration lock within 30 seconds');
  }
};

const releaseMigrationLock = async (appDataSource) => {
  try {
    await appDataSource.query('SELECT RELEASE_LOCK(?)', [MIGRATION_LOCK_NAME]);
  } catch (_error) {
  }
};

const run = async () => {
  const requestId = `migration-${randomUUID()}`;
  const root = resolve(__dirname, '../../..');
  const migrationDir = resolve(root, 'apps/api/migrations');
  const stateFile = resolve(root, 'artifacts/migrations/state.json');
  const { mode, version: targetVersion } = parseArgs(process.argv.slice(2));

  if (!existsSync(migrationDir)) {
    throw new Error(`Migration directory missing: ${migrationDir}`);
  }

  const { allSqlFiles, upFiles } = resolveMigrationFiles(migrationDir);
  if (allSqlFiles.length === 0) {
    throw new Error(`No SQL migration files found in ${migrationDir}`);
  }

  const config = readConfig();

  log('info', 'Starting SQL migrations via TypeORM DataSource', {
    request_id: requestId,
    db_host: config.DB_HOST,
    db_name: config.DB_NAME,
    mode,
    target_version: targetVersion,
    migrations: upFiles.length
  });

  const appDataSource = new DataSource({
    type: 'mysql',
    host: config.DB_HOST,
    port: config.DB_PORT,
    username: config.DB_USER,
    password: config.DB_PASSWORD,
    database: config.DB_NAME
  });

  await appDataSource.initialize();

  const appliedMigrations = [];
  const skippedMigrations = [];
  const rolledBackMigrations = [];

  try {
    await appDataSource.query(SCHEMA_MIGRATION_TABLE_SQL);
    await acquireMigrationLock(appDataSource);

    const existingRows = await appDataSource.query(
      'SELECT id, version FROM schema_migrations ORDER BY id ASC'
    );
    const existingVersions = new Set(existingRows.map((row) => String(row.version)));

    if (mode === 'up') {
      for (const migrationFile of upFiles) {
        const version = versionFromMigrationFile(migrationFile);
        const description = `Applied by migrate-baseline: ${migrationFile}`;

        if (existingVersions.has(version)) {
          skippedMigrations.push(version);
          continue;
        }

        const absolutePath = resolve(migrationDir, migrationFile);
        const sqlContent = readFileSync(absolutePath, 'utf8');
        const statements = splitStatements(sqlContent);

        await executeMigrationStatements({
          appDataSource,
          statements,
          requestId,
          migrationTag: `${version}:up`,
          afterExecute: async (queryRunner) => {
            await queryRunner.query(
              `INSERT INTO schema_migrations(version, description)
               VALUES (?, ?)
               ON DUPLICATE KEY UPDATE description = VALUES(description)`,
              [version, description]
            );
          }
        });

        appliedMigrations.push(version);
        existingVersions.add(version);
      }
    } else {
      const rollbackVersion = resolveRollbackVersion({
        existingRows,
        targetVersion
      });

      if (!rollbackVersion) {
        log('info', 'No applied migrations to rollback', {
          request_id: requestId,
          mode
        });
      } else {
        const rollbackFile = `${rollbackVersion}.down.sql`;
        const rollbackPath = resolve(migrationDir, rollbackFile);

        if (!existsSync(rollbackPath)) {
          throw new Error(`Rollback file missing for version ${rollbackVersion}: ${rollbackFile}`);
        }

        const rollbackSql = readFileSync(rollbackPath, 'utf8');
        const rollbackStatements = splitStatements(rollbackSql);

        await executeMigrationStatements({
          appDataSource,
          statements: rollbackStatements,
          requestId,
          migrationTag: `${rollbackVersion}:down`,
          afterExecute: async (queryRunner) => {
            await queryRunner.query('DELETE FROM schema_migrations WHERE version = ?', [
              rollbackVersion
            ]);
          }
        });

        rolledBackMigrations.push(rollbackVersion);
      }
    }
  } finally {
    await releaseMigrationLock(appDataSource);
    await appDataSource.destroy();
  }

  mkdirSync(dirname(stateFile), { recursive: true });

  const history = {
    applied_at: new Date().toISOString(),
    request_id: requestId,
    mode,
    target_version: targetVersion,
    runner: 'TypeORM DataSource SQL migration runner',
    migration_dir: migrationDir,
    applied_migrations: appliedMigrations,
    skipped_migrations: skippedMigrations,
    rolled_back_migrations: rolledBackMigrations
  };

  writeFileSync(stateFile, JSON.stringify(history, null, 2));

  log('info', 'SQL migrations completed', {
    request_id: requestId,
    mode,
    applied_count: appliedMigrations.length,
    skipped_count: skippedMigrations.length,
    rolled_back_count: rolledBackMigrations.length,
    state_file: stateFile
  });
};

if (require.main === module) {
  run().catch((error) => {
    const requestId = `migration-${randomUUID()}`;
    log('error', 'SQL migration execution failed', {
      request_id: requestId,
      detail: error.message
    });
    process.stderr.write(`${error.message}\n`);
    process.exit(1);
  });
}

module.exports = {
  parseArgs,
  resolveRollbackVersion,
  splitStatements,
  versionFromMigrationFile,
  resolveMigrationFiles,
  isRecoverableMigrationError,
  shouldRunStatementsInTransaction
};
