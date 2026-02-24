CREATE TABLE IF NOT EXISTS platform_integration_freeze_control (
  freeze_id VARCHAR(64) NOT NULL,
  status ENUM('active', 'released') NOT NULL DEFAULT 'active',
  freeze_reason VARCHAR(256) NOT NULL,
  rollback_reason VARCHAR(256) NULL,
  frozen_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  released_at TIMESTAMP(3) NULL,
  frozen_by_user_id VARCHAR(64) NULL,
  released_by_user_id VARCHAR(64) NULL,
  request_id VARCHAR(128) NOT NULL,
  traceparent VARCHAR(128) NULL,
  active_window_slot TINYINT
    GENERATED ALWAYS AS (CASE WHEN status = 'active' THEN 1 ELSE NULL END) STORED,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3)
    ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (freeze_id),
  UNIQUE KEY uk_platform_integration_freeze_active_window (active_window_slot),
  KEY idx_platform_integration_freeze_status_frozen_at (status, frozen_at),
  KEY idx_platform_integration_freeze_request_id (request_id),
  KEY idx_platform_integration_freeze_released_at (released_at),
  CONSTRAINT fk_platform_integration_freeze_frozen_by_user
    FOREIGN KEY (frozen_by_user_id) REFERENCES iam_users (id),
  CONSTRAINT fk_platform_integration_freeze_released_by_user
    FOREIGN KEY (released_by_user_id) REFERENCES iam_users (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
