'use strict';

const {
  TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE,
  TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
} = require('../../../../../modules/auth/permission-catalog');

const createTenantMemoryAuthStoreRepositorySessionAccessGovernance = ({
  domainsByUserId,
  isTenantUsershipActiveForAuth,
  tenantsByUserId,
  listTenantUsershipRoleBindingsForMembershipId,
  listTenantRolePermissionGrantsForRoleId,
  normalizePlatformRoleCatalogRoleId,
  findPlatformRoleCatalogRecordStateByRoleId,
  normalizePlatformRoleCatalogScope,
  normalizePlatformRoleCatalogTenantId,
  normalizePlatformRoleCatalogStatus,
  isActiveLikeStatus
} = {}) => ({
  ensureTenantDomainAccessForUser: async (userId) => {
    const normalizedUserId = String(userId);
    const userDomains = domainsByUserId.get(normalizedUserId) || new Set();
    if (userDomains.has('tenant')) {
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: false };
    }

    const hasActiveTenantUsership = (tenantsByUserId.get(normalizedUserId) || []).some(
      (tenant) => isTenantUsershipActiveForAuth(tenant)
    );
    if (!hasActiveTenantUsership) {
      domainsByUserId.set(normalizedUserId, userDomains);
      return { inserted: false };
    }

    userDomains.add('tenant');
    domainsByUserId.set(normalizedUserId, userDomains);
    return { inserted: true };
  },

  listTenantOptionsByUserId: async (userId) =>
    (tenantsByUserId.get(String(userId)) || [])
      .filter((tenant) => isTenantUsershipActiveForAuth(tenant))
      .map((tenant) => ({ ...tenant })),

  hasAnyTenantRelationshipByUserId: async (userId) =>
    (tenantsByUserId.get(String(userId)) || []).length > 0,

  findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedTenantId) {
      return null;
    }

    const tenant = (tenantsByUserId.get(String(userId)) || []).find(
      (item) =>
        String(item.tenantId) === normalizedTenantId
        && isTenantUsershipActiveForAuth(item)
    );
    if (!tenant) {
      return null;
    }
    const membershipId = String(
      tenant.membershipId || tenant.membership_id || ''
    ).trim();
    const roleIds = typeof listTenantUsershipRoleBindingsForMembershipId === 'function'
      ? listTenantUsershipRoleBindingsForMembershipId({
        membershipId,
        tenantId: normalizedTenantId
      })
      : [];
    const permissionCodeSet = new Set();
    for (const roleIdCandidate of Array.isArray(roleIds) ? roleIds : []) {
      const normalizedRoleId = typeof normalizePlatformRoleCatalogRoleId === 'function'
        ? normalizePlatformRoleCatalogRoleId(roleIdCandidate)
        : String(roleIdCandidate || '').trim().toLowerCase();
      if (!normalizedRoleId) {
        continue;
      }
      const catalogEntryState = typeof findPlatformRoleCatalogRecordStateByRoleId === 'function'
        ? findPlatformRoleCatalogRecordStateByRoleId(normalizedRoleId)
        : null;
      const catalogEntry = catalogEntryState?.record;
      if (!catalogEntry) {
        continue;
      }
      const roleScope = typeof normalizePlatformRoleCatalogScope === 'function'
        ? normalizePlatformRoleCatalogScope(catalogEntry.scope)
        : String(catalogEntry.scope || '').trim().toLowerCase();
      const roleTenantId = typeof normalizePlatformRoleCatalogTenantId === 'function'
        ? normalizePlatformRoleCatalogTenantId(catalogEntry.tenantId)
        : String(catalogEntry.tenantId || '').trim();
      const roleStatus = typeof normalizePlatformRoleCatalogStatus === 'function'
        ? normalizePlatformRoleCatalogStatus(catalogEntry.status)
        : String(catalogEntry.status || '').trim().toLowerCase();
      const roleActive = typeof isActiveLikeStatus === 'function'
        ? isActiveLikeStatus(roleStatus)
        : roleStatus === 'active' || roleStatus === 'enabled';
      if (
        roleScope !== 'tenant'
        || roleTenantId !== normalizedTenantId
        || !roleActive
      ) {
        continue;
      }
      const grants = typeof listTenantRolePermissionGrantsForRoleId === 'function'
        ? listTenantRolePermissionGrantsForRoleId(normalizedRoleId)
        : [];
      for (const permissionCode of Array.isArray(grants) ? grants : []) {
        const normalizedPermissionCode = String(permissionCode || '').trim().toLowerCase();
        if (normalizedPermissionCode) {
          permissionCodeSet.add(normalizedPermissionCode);
        }
      }
    }

    const permissionSource = tenant.permission || null;
    const context = {
      scopeLabel: permissionSource?.scopeLabel || `组织权限（${tenant.tenantName || tenant.tenantId}）`,
      canViewUserManagement: Boolean(permissionSource?.canViewUserManagement),
      canOperateUserManagement: Boolean(permissionSource?.canOperateUserManagement),
      canViewAccountManagement: Boolean(permissionSource?.canViewAccountManagement),
      canOperateAccountManagement: Boolean(permissionSource?.canOperateAccountManagement),
      canViewCustomerManagement: Boolean(permissionSource?.canViewCustomerManagement),
      canOperateCustomerManagement: Boolean(permissionSource?.canOperateCustomerManagement),
      canViewCustomerScopeMy: Boolean(permissionSource?.canViewCustomerScopeMy),
      canOperateCustomerScopeMy: Boolean(permissionSource?.canOperateCustomerScopeMy),
      canViewCustomerScopeAssist: Boolean(permissionSource?.canViewCustomerScopeAssist),
      canOperateCustomerScopeAssist: Boolean(permissionSource?.canOperateCustomerScopeAssist),
      canViewCustomerScopeAll: Boolean(permissionSource?.canViewCustomerScopeAll),
      canOperateCustomerScopeAll: Boolean(permissionSource?.canOperateCustomerScopeAll),
      canViewRoleManagement: Boolean(permissionSource?.canViewRoleManagement),
      canOperateRoleManagement: Boolean(permissionSource?.canOperateRoleManagement)
    };
    if (context.canViewUserManagement) {
      permissionCodeSet.add(TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateUserManagement) {
      permissionCodeSet.add(TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE);
      permissionCodeSet.add(TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (context.canViewAccountManagement) {
      permissionCodeSet.add(TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateAccountManagement) {
      permissionCodeSet.add(TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE);
      permissionCodeSet.add(TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (context.canViewCustomerManagement) {
      permissionCodeSet.add(TENANT_CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateCustomerManagement) {
      permissionCodeSet.add(TENANT_CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE);
    }
    if (context.canViewCustomerScopeMy) {
      permissionCodeSet.add(TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateCustomerScopeMy) {
      permissionCodeSet.add(TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE);
    }
    if (context.canViewCustomerScopeAssist) {
      permissionCodeSet.add(TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateCustomerScopeAssist) {
      permissionCodeSet.add(TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE);
    }
    if (context.canViewCustomerScopeAll) {
      permissionCodeSet.add(TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateCustomerScopeAll) {
      permissionCodeSet.add(TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE);
    }
    if (
      context.canViewCustomerScopeMy
      || context.canViewCustomerScopeAssist
      || context.canViewCustomerScopeAll
    ) {
      permissionCodeSet.add(TENANT_CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (
      context.canOperateCustomerScopeMy
      || context.canOperateCustomerScopeAssist
      || context.canOperateCustomerScopeAll
    ) {
      permissionCodeSet.add(TENANT_CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE);
    }
    if (context.canViewRoleManagement) {
      permissionCodeSet.add(TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (context.canOperateRoleManagement) {
      permissionCodeSet.add(TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE);
      permissionCodeSet.add(TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    context.canViewAccountManagement = permissionCodeSet.has(
      TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    context.canOperateAccountManagement = permissionCodeSet.has(
      TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    context.canViewCustomerManagement = permissionCodeSet.has(
      TENANT_CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE
    );
    context.canOperateCustomerManagement = permissionCodeSet.has(
      TENANT_CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE
    );
    context.canViewCustomerScopeMy = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE
    );
    context.canOperateCustomerScopeMy = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE
    );
    context.canViewCustomerScopeAssist = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE
    );
    context.canOperateCustomerScopeAssist = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE
    );
    context.canViewCustomerScopeAll = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE
    );
    context.canOperateCustomerScopeAll = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE
    );
    Object.defineProperty(context, 'permission_code_set', {
      value: permissionCodeSet,
      enumerable: false,
      configurable: true
    });
    Object.defineProperty(context, 'permissionCodeSet', {
      value: permissionCodeSet,
      enumerable: false,
      configurable: true
    });
    return context;
  },
});

module.exports = {
  createTenantMemoryAuthStoreRepositorySessionAccessGovernance
};
