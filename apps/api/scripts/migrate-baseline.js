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

const splitStatements = (sqlContent) =>
  sqlContent
    .split(';')
    .map((statement) => statement.trim())
    .filter((statement) => statement.length > 0);

const run = async () => {
  const requestId = `migration-${randomUUID()}`;
  const root = resolve(__dirname, '../../..');
  const migrationDir = resolve(root, 'apps/api/migrations');
  const stateFile = resolve(root, 'artifacts/migrations/state.json');

  if (!existsSync(migrationDir)) {
    throw new Error(`Migration directory missing: ${migrationDir}`);
  }

  const migrationFiles = readdirSync(migrationDir)
    .filter((name) => name.endsWith('.sql'))
    .sort();

  if (migrationFiles.length === 0) {
    throw new Error(`No SQL migration files found in ${migrationDir}`);
  }

  const config = readConfig();

  log('info', 'Starting SQL migrations via TypeORM DataSource', {
    request_id: requestId,
    db_host: config.DB_HOST,
    db_name: config.DB_NAME,
    migrations: migrationFiles.length
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

  try {
    await appDataSource.query(SCHEMA_MIGRATION_TABLE_SQL);

    const existingRows = await appDataSource.query(
      'SELECT version FROM schema_migrations ORDER BY id ASC'
    );
    const existingVersions = new Set(existingRows.map((row) => row.version));

    for (const migrationFile of migrationFiles) {
      const version = migrationFile.replace(/\.sql$/, '');
      const description = `Applied by migrate-baseline: ${migrationFile}`;

      if (existingVersions.has(version)) {
        skippedMigrations.push(version);
        continue;
      }

      const absolutePath = resolve(migrationDir, migrationFile);
      const sqlContent = readFileSync(absolutePath, 'utf8');
      const statements = splitStatements(sqlContent);

      for (const statement of statements) {
        await appDataSource.query(statement);
      }

      await appDataSource.query(
        `INSERT INTO schema_migrations(version, description)
         VALUES (?, ?)
         ON DUPLICATE KEY UPDATE description = VALUES(description)`,
        [version, description]
      );

      appliedMigrations.push(version);
      existingVersions.add(version);
    }
  } finally {
    await appDataSource.destroy();
  }

  mkdirSync(dirname(stateFile), { recursive: true });

  const history = {
    applied_at: new Date().toISOString(),
    request_id: requestId,
    runner: 'TypeORM DataSource SQL migration runner',
    migration_dir: migrationDir,
    applied_migrations: appliedMigrations,
    skipped_migrations: skippedMigrations
  };

  writeFileSync(stateFile, JSON.stringify(history, null, 2));

  log('info', 'SQL migrations completed', {
    request_id: requestId,
    applied_count: appliedMigrations.length,
    skipped_count: skippedMigrations.length,
    state_file: stateFile
  });
};

run().catch((error) => {
  const requestId = `migration-${randomUUID()}`;
  log('error', 'SQL migration execution failed', {
    request_id: requestId,
    detail: error.message
  });
  process.stderr.write(`${error.message}\n`);
  process.exit(1);
});
