CREATE TABLE IF NOT EXISTS tenant_session_conversations (
  conversation_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  account_wechat_id VARCHAR(128) NOT NULL,
  account_wechat_id_normalized VARCHAR(128) NOT NULL,
  conversation_type VARCHAR(16) NOT NULL,
  conversation_name VARCHAR(128) NOT NULL,
  conversation_name_normalized VARCHAR(128) NOT NULL,
  last_message_time TIMESTAMP(3) NULL,
  last_message_preview VARCHAR(512) NULL,
  external_updated_at TIMESTAMP(3) NULL,
  sync_source VARCHAR(32) NOT NULL DEFAULT 'external',
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  updated_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (conversation_id),
  UNIQUE KEY uk_tenant_session_conversations_tenant_account_type_name (
    tenant_id,
    account_wechat_id,
    conversation_type,
    conversation_name_normalized
  ),
  KEY idx_tenant_session_conv_tenant_account_last_message_time (
    tenant_id,
    account_wechat_id,
    last_message_time
  ),
  CONSTRAINT chk_tenant_session_conversations_type
    CHECK (conversation_type IN ('direct', 'group')),
  CONSTRAINT fk_tenant_session_conversations_account_wechat
    FOREIGN KEY (tenant_id, account_wechat_id)
    REFERENCES tenant_accounts (tenant_id, wechat_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_session_history_messages (
  message_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  conversation_id VARCHAR(64) NOT NULL,
  sender_name VARCHAR(128) NOT NULL,
  sender_name_normalized VARCHAR(128) NOT NULL,
  is_self TINYINT NULL,
  message_type VARCHAR(32) NOT NULL,
  message_payload_json JSON NOT NULL,
  message_preview VARCHAR(512) NULL,
  message_time TIMESTAMP(3) NOT NULL,
  source_event_id VARCHAR(128) NULL,
  ingest_source VARCHAR(32) NOT NULL DEFAULT 'external',
  ingested_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (message_id),
  UNIQUE KEY uk_tenant_session_history_messages_source_event (
    tenant_id,
    conversation_id,
    source_event_id
  ),
  KEY idx_tenant_session_history_messages_conversation_time (
    tenant_id,
    conversation_id,
    message_time
  ),
  CONSTRAINT chk_tenant_session_history_messages_is_self
    CHECK (is_self IN (0, 1) OR is_self IS NULL),
  CONSTRAINT fk_tenant_session_history_messages_conversation_id
    FOREIGN KEY (conversation_id)
    REFERENCES tenant_session_conversations (conversation_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS tenant_session_outbound_messages (
  outbound_message_id VARCHAR(64) NOT NULL,
  tenant_id VARCHAR(64) NOT NULL,
  account_wechat_id VARCHAR(128) NOT NULL,
  account_nickname VARCHAR(128) NOT NULL,
  conversation_id VARCHAR(64) NOT NULL,
  conversation_name VARCHAR(128) NOT NULL,
  message_type VARCHAR(32) NOT NULL,
  message_payload_json JSON NOT NULL,
  message_preview VARCHAR(512) NULL,
  send_time TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  enqueue_status VARCHAR(16) NOT NULL DEFAULT 'pending',
  provider_message_id VARCHAR(128) NULL,
  error_code VARCHAR(64) NULL,
  error_message VARCHAR(512) NULL,
  status_updated_at TIMESTAMP(3) NULL,
  client_message_id VARCHAR(64) NULL,
  created_at TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (outbound_message_id),
  UNIQUE KEY uk_tenant_session_outbound_messages_client (
    tenant_id,
    account_wechat_id,
    client_message_id
  ),
  KEY idx_tenant_session_outbound_messages_status_time (
    tenant_id,
    enqueue_status,
    send_time
  ),
  KEY idx_tenant_session_outbound_messages_conversation_time (
    tenant_id,
    conversation_id,
    send_time
  ),
  CONSTRAINT chk_tenant_session_outbound_messages_status
    CHECK (enqueue_status IN ('pending','processing','retrying','sent','failed','dead_letter','cancelled')),
  CONSTRAINT fk_tenant_session_outbound_messages_conversation_id
    FOREIGN KEY (conversation_id)
    REFERENCES tenant_session_conversations (conversation_id)
    ON DELETE CASCADE,
  CONSTRAINT fk_tenant_session_outbound_messages_account_wechat
    FOREIGN KEY (tenant_id, account_wechat_id)
    REFERENCES tenant_accounts (tenant_id, wechat_id)
    ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
