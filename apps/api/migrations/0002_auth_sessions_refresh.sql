CREATE TABLE IF NOT EXISTS auth_sessions (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  session_id CHAR(36) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  session_version INT UNSIGNED NOT NULL DEFAULT 1,
  status ENUM('active', 'revoked') NOT NULL DEFAULT 'active',
  revoked_reason VARCHAR(128) NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_auth_sessions_session_id (session_id),
  KEY idx_auth_sessions_user_id (user_id),
  KEY idx_auth_sessions_status (status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS refresh_tokens (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  token_hash CHAR(64) NOT NULL,
  session_id CHAR(36) NOT NULL,
  user_id VARCHAR(64) NOT NULL,
  status ENUM('active', 'rotated', 'revoked') NOT NULL DEFAULT 'active',
  rotated_from_token_hash CHAR(64) NULL,
  rotated_to_token_hash CHAR(64) NULL,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uk_refresh_tokens_token_hash (token_hash),
  KEY idx_refresh_tokens_session_id (session_id),
  KEY idx_refresh_tokens_user_id (user_id),
  KEY idx_refresh_tokens_status (status),
  KEY idx_refresh_tokens_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
