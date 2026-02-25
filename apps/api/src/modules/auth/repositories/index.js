const { createAuthUserRepository } = require('./user-repository');
const { createAuthSessionRepository } = require('./session-repository');
const { createAuthDomainAccessRepository } = require('./domain-access-repository');
const {
  createAuthTenantUsershipRepository
} = require('./tenant-membership-repository');
const { createAuthPermissionRepository } = require('./permission-repository');

const createAuthRepositories = ({ authStore } = {}) =>
  Object.freeze({
    userRepository: createAuthUserRepository({ authStore }),
    sessionRepository: createAuthSessionRepository({ authStore }),
    domainAccessRepository: createAuthDomainAccessRepository({ authStore }),
    tenantUsershipRepository: createAuthTenantUsershipRepository({ authStore }),
    permissionRepository: createAuthPermissionRepository({ authStore })
  });

module.exports = {
  createAuthRepositories,
  createAuthUserRepository,
  createAuthSessionRepository,
  createAuthDomainAccessRepository,
  createAuthTenantUsershipRepository,
  createAuthPermissionRepository
};
