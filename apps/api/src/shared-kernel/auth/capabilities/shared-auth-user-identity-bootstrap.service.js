'use strict';

const createSharedAuthUserIdentityBootstrapCapabilities = ({
  authStore,
  errors,
  sensitiveConfigProvider,
  sensitiveConfigDecryptionKeys,
  sensitiveConfigDecryptionKey,
  DEFAULT_PASSWORD_CONFIG_KEY,
  decryptSensitiveConfigValue,
  validatePasswordPolicy,
  resolveProvisioningConfigFailureReason,
  addAuditEvent,
  hashPassword,
  assertStoreMethod,
  isDataTooLongRoleFactError,
  normalizePhone,
  maskPhone
} = {}) => {
  const resolveDefaultProvisioningPassword = async ({
    requestId,
    operatorUserId,
    operatorSessionId
  }) => {
    if (
      !sensitiveConfigProvider
      || typeof sensitiveConfigProvider.getEncryptedConfig !== 'function'
    ) {
      addAuditEvent({
        type: 'auth.user.provision.config_failed',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'default password config provider unavailable',
        metadata: {
          config_key: DEFAULT_PASSWORD_CONFIG_KEY,
          failure_reason: 'config-provider-unavailable'
        }
      });
      throw errors.provisioningConfigUnavailable();
    }

    try {
      const encryptedDefaultPassword = await sensitiveConfigProvider.getEncryptedConfig(
        DEFAULT_PASSWORD_CONFIG_KEY
      );
      const plainTextDefaultPassword = decryptSensitiveConfigValue({
        encryptedValue: encryptedDefaultPassword,
        decryptionKeys: sensitiveConfigDecryptionKeys,
        decryptionKey: sensitiveConfigDecryptionKey
      });
      validatePasswordPolicy(plainTextDefaultPassword);
      return plainTextDefaultPassword;
    } catch (error) {
      const failureReason = resolveProvisioningConfigFailureReason(error);
      addAuditEvent({
        type: 'auth.user.provision.config_failed',
        requestId,
        userId: operatorUserId || 'unknown',
        sessionId: operatorSessionId || 'unknown',
        detail: 'default password resolution failed',
        metadata: {
          config_key: DEFAULT_PASSWORD_CONFIG_KEY,
          failure_reason: failureReason
        }
      });
      throw errors.provisioningConfigUnavailable();
    }
  };

  const getOrCreateProvisionUserByPhone = async ({
    requestId,
    phone,
    operatorUserId,
    operatorSessionId
  }) => {
    const existingUser = await authStore.findUserByPhone(phone);
    if (existingUser) {
      return {
        user: existingUser,
        createdUser: false
      };
    }

    assertStoreMethod(authStore, 'createUserByPhone', 'authStore');
    const defaultPassword = await resolveDefaultProvisioningPassword({
      requestId,
      operatorUserId,
      operatorSessionId
    });
    let createdUser = null;
    try {
      createdUser = await authStore.createUserByPhone({
        phone,
        passwordHash: hashPassword(defaultPassword),
        status: 'active'
      });
    } catch (error) {
      if (isDataTooLongRoleFactError(error)) {
        throw errors.invalidPayload();
      }
      throw error;
    }
    if (createdUser) {
      return {
        user: createdUser,
        createdUser: true
      };
    }

    const reusedUser = await authStore.findUserByPhone(phone);
    if (reusedUser) {
      return {
        user: reusedUser,
        createdUser: false
      };
    }

    throw errors.provisionConflict();
  };

  const getOrCreateUserIdentityByPhone = async ({
    requestId,
    phone,
    operatorUserId = 'unknown',
    operatorSessionId = 'unknown'
  }) => {
    const normalizedPhone = normalizePhone(phone);
    if (!normalizedPhone) {
      throw errors.invalidPayload();
    }

    const resolvedUser = await getOrCreateProvisionUserByPhone({
      requestId,
      phone: normalizedPhone,
      operatorUserId,
      operatorSessionId
    });

    addAuditEvent({
      type: resolvedUser.createdUser
        ? 'auth.user.bootstrap.created'
        : 'auth.user.bootstrap.reused',
      requestId,
      userId: resolvedUser.user.id,
      sessionId: operatorSessionId,
      detail: resolvedUser.createdUser
        ? 'owner user created with default password policy'
        : 'owner user identity reused without credential mutation',
      metadata: {
        operator_user_id: operatorUserId,
        phone_masked: maskPhone(normalizedPhone),
        credential_initialized: resolvedUser.createdUser,
        first_login_force_password_change: false
      }
    });

    return {
      user_id: resolvedUser.user.id,
      phone: resolvedUser.user.phone,
      created_user: resolvedUser.createdUser,
      reused_existing_user: !resolvedUser.createdUser,
      credential_initialized: resolvedUser.createdUser,
      first_login_force_password_change: false
    };
  };

  return {
    getOrCreateProvisionUserByPhone,
    getOrCreateUserIdentityByPhone
  };
};

module.exports = {
  createSharedAuthUserIdentityBootstrapCapabilities
};
