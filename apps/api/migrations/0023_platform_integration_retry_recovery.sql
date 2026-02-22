CREATE TABLE IF NOT EXISTS platform_integration_retry_recovery_queue (
  recovery_id VARCHAR(64) NOT NULL,
  integration_id VARCHAR(64) NOT NULL,
  contract_type ENUM('openapi', 'event') NOT NULL,
  contract_version VARCHAR(64) NOT NULL,
  request_id VARCHAR(128) NOT NULL,
  traceparent VARCHAR(128) NULL,
  idempotency_key VARCHAR(128) NOT NULL DEFAULT '',
  attempt_count INT UNSIGNED NOT NULL DEFAULT 0,
  max_attempts TINYINT UNSIGNED NOT NULL DEFAULT 5,
  next_retry_at TIMESTAMP(3) NULL,
  last_attempt_at TIMESTAMP(3) NULL,
  status ENUM('pending', 'retrying', 'succeeded', 'failed', 'dlq', 'replayed')
    NOT NULL DEFAULT 'pending',
  failure_code VARCHAR(128) NULL,
  failure_detail TEXT NULL,
  last_http_status SMALLINT UNSIGNED NULL,
  retryable TINYINT(1) NOT NULL DEFAULT 1,
  payload_snapshot JSON NOT NULL,
  response_snapshot JSON NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (recovery_id),
  UNIQUE KEY uk_platform_integration_recovery_dedup (
    integration_id,
    contract_type,
    contract_version,
    request_id,
    idempotency_key
  ),
  KEY idx_platform_integration_recovery_status_next_retry_at (status, next_retry_at),
  KEY idx_platform_integration_recovery_integration_status (integration_id, status),
  KEY idx_platform_integration_recovery_request_id (request_id),
  CONSTRAINT fk_platform_integration_recovery_integration
    FOREIGN KEY (integration_id) REFERENCES platform_integration_catalog (integration_id),
  CONSTRAINT fk_platform_integration_recovery_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES users (id),
  CONSTRAINT fk_platform_integration_recovery_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
