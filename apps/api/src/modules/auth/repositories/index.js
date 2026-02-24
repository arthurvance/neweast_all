const { createAuthUserRepository } = require('./user-repository');
const { createAuthSessionRepository } = require('./session-repository');
const { createAuthDomainAccessRepository } = require('./domain-access-repository');
const {
  createAuthTenantMembershipRepository
} = require('./tenant-membership-repository');
const { createAuthPermissionRepository } = require('./permission-repository');

const createAuthRepositories = ({ authStore } = {}) =>
  Object.freeze({
    userRepository: createAuthUserRepository({ authStore }),
    sessionRepository: createAuthSessionRepository({ authStore }),
    domainAccessRepository: createAuthDomainAccessRepository({ authStore }),
    tenantMembershipRepository: createAuthTenantMembershipRepository({ authStore }),
    permissionRepository: createAuthPermissionRepository({ authStore })
  });

module.exports = {
  createAuthRepositories,
  createAuthUserRepository,
  createAuthSessionRepository,
  createAuthDomainAccessRepository,
  createAuthTenantMembershipRepository,
  createAuthPermissionRepository
};
