CREATE TABLE IF NOT EXISTS platform_integration_contract_versions (
  contract_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  integration_id VARCHAR(64) NOT NULL,
  contract_type ENUM('openapi', 'event') NOT NULL,
  contract_version VARCHAR(64) NOT NULL,
  schema_ref VARCHAR(512) NOT NULL,
  schema_checksum CHAR(64) NOT NULL,
  status ENUM('candidate', 'active', 'deprecated', 'retired') NOT NULL DEFAULT 'candidate',
  is_backward_compatible TINYINT(1) NOT NULL DEFAULT 0,
  compatibility_notes TEXT NULL,
  created_by_user_id VARCHAR(64) NULL,
  updated_by_user_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (contract_id),
  UNIQUE KEY uk_platform_integration_contract_version (
    integration_id,
    contract_type,
    contract_version
  ),
  KEY idx_platform_integration_contract_status (status),
  KEY idx_platform_integration_contract_active_lookup (
    integration_id,
    contract_type,
    status,
    updated_at,
    contract_id
  ),
  CONSTRAINT fk_platform_integration_contract_versions_integration
    FOREIGN KEY (integration_id) REFERENCES platform_integration_catalog (integration_id),
  CONSTRAINT fk_platform_integration_contract_versions_created_by_user
    FOREIGN KEY (created_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_platform_integration_contract_versions_updated_by_user
    FOREIGN KEY (updated_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS platform_integration_contract_compatibility_checks (
  check_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  integration_id VARCHAR(64) NOT NULL,
  contract_type ENUM('openapi', 'event') NOT NULL,
  baseline_version VARCHAR(64) NOT NULL,
  candidate_version VARCHAR(64) NOT NULL,
  evaluation_result ENUM('compatible', 'incompatible') NOT NULL,
  breaking_change_count INT UNSIGNED NOT NULL DEFAULT 0,
  diff_summary JSON NULL,
  request_id VARCHAR(128) NOT NULL,
  checked_by_user_id VARCHAR(64) NULL,
  checked_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (check_id),
  KEY idx_platform_integration_contract_checks_lookup (
    integration_id,
    contract_type,
    baseline_version,
    candidate_version,
    checked_at,
    check_id
  ),
  KEY idx_platform_integration_contract_checks_result (evaluation_result),
  CONSTRAINT fk_platform_integration_contract_checks_integration
    FOREIGN KEY (integration_id) REFERENCES platform_integration_catalog (integration_id),
  CONSTRAINT fk_platform_integration_contract_checks_checked_by_user
    FOREIGN KEY (checked_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_platform_integration_contract_checks_baseline_version
    FOREIGN KEY (integration_id, contract_type, baseline_version)
      REFERENCES platform_integration_contract_versions (
        integration_id,
        contract_type,
        contract_version
      ),
  CONSTRAINT fk_platform_integration_contract_checks_candidate_version
    FOREIGN KEY (integration_id, contract_type, candidate_version)
      REFERENCES platform_integration_contract_versions (
        integration_id,
        contract_type,
        contract_version
      )
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
