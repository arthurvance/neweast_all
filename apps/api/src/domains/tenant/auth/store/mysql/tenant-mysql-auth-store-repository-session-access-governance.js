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
  TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_MY_VIEW_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_MY_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_ASSIST_VIEW_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_ASSIST_OPERATE_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_ALL_VIEW_PERMISSION_CODE,
  TENANT_SESSION_SCOPE_ALL_OPERATE_PERMISSION_CODE
} = require('../../../../../modules/auth/permission-catalog');

const createTenantMysqlAuthStoreRepositorySessionAccessGovernance = ({
  dbClient,
  runTenantUsershipQuery,
  toBoolean
} = {}) => ({
  ensureTenantDomainAccessForUser: async (userId) => {
    const normalizedUserId = String(userId || '').trim();
    if (!normalizedUserId) {
      return { inserted: false };
    }
    const tenantCountRows = await runTenantUsershipQuery({
      sqlWithOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        LEFT JOIN tenants o ON o.id = ut.tenant_id
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
          AND o.status IN ('active', 'enabled')
      `,
      sqlWithoutOrgGuard: `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships ut
        WHERE ut.user_id = ?
          AND ut.status IN ('active', 'enabled')
      `,
      params: [normalizedUserId]
    });
    const tenantCount = Number(tenantCountRows?.[0]?.tenant_count || 0);
    return {
      inserted: false,
      has_active_tenant_membership: tenantCount > 0
    };
  },

  findTenantPermissionByUserAndTenantId: async ({ userId, tenantId }) => {
    const normalizedUserId = String(userId);
    const normalizedTenantId = String(tenantId || '').trim();
    if (!normalizedTenantId) {
      return null;
    }

    const rows = await runTenantUsershipQuery({
      sqlWithOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 membership_id,
                 can_view_user_management,
                 can_operate_user_management,
                 can_view_role_management,
                 can_operate_role_management
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          WHERE ut.user_id = ?
            AND ut.tenant_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
          LIMIT 1
        `,
      sqlWithoutOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 membership_id,
                 can_view_user_management,
                 can_operate_user_management,
                 can_view_role_management,
                 can_operate_role_management
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.tenant_id = ?
            AND ut.status IN ('active', 'enabled')
          LIMIT 1
        `,
      params: [normalizedUserId, normalizedTenantId]
    });
    const row = rows?.[0];
    if (!row) {
      return null;
    }
    const permissionCodeSet = new Set();
    const membershipId = String(row.membership_id || '').trim();

    const hasLegacyViewUserManagement = toBoolean(row.can_view_user_management);
    const hasLegacyOperateUserManagement = toBoolean(row.can_operate_user_management);
    const hasLegacyViewRoleManagement = toBoolean(row.can_view_role_management);
    const hasLegacyOperateRoleManagement = toBoolean(row.can_operate_role_management);

    if (hasLegacyViewUserManagement) {
      permissionCodeSet.add(TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (hasLegacyOperateUserManagement) {
      permissionCodeSet.add(TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE);
      permissionCodeSet.add(TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE);
    }
    if (hasLegacyViewRoleManagement) {
      permissionCodeSet.add(TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (hasLegacyOperateRoleManagement) {
      permissionCodeSet.add(TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE);
      permissionCodeSet.add(TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE);
    }

    if (membershipId) {
      const grantRows = await dbClient.query(
        `
          SELECT trg.permission_code
          FROM tenant_membership_roles tmr
          JOIN tenant_role_permission_grants trg
            ON trg.role_id = tmr.role_id
          JOIN platform_roles pr
            ON pr.role_id = tmr.role_id
          WHERE tmr.membership_id = ?
            AND pr.scope = 'tenant'
            AND pr.tenant_id = ?
            AND pr.status IN ('active', 'enabled')
          ORDER BY trg.permission_code ASC
        `,
        [membershipId, normalizedTenantId]
      );
      for (const grantRow of Array.isArray(grantRows) ? grantRows : []) {
        const permissionCode = String(grantRow?.permission_code || '').trim().toLowerCase();
        if (permissionCode) {
          permissionCodeSet.add(permissionCode);
        }
      }
    }

    const canViewUserManagement = permissionCodeSet.has(
      TENANT_USER_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    const canOperateUserManagement = permissionCodeSet.has(
      TENANT_USER_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    const canViewAccountManagement = permissionCodeSet.has(
      TENANT_ACCOUNT_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    const canOperateAccountManagement = permissionCodeSet.has(
      TENANT_ACCOUNT_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    const canViewCustomerScopeMy = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE
    );
    const canOperateCustomerScopeMy = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_MY_OPERATE_PERMISSION_CODE
    );
    const canViewCustomerScopeAssist = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE
    );
    const canOperateCustomerScopeAssist = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ASSIST_OPERATE_PERMISSION_CODE
    );
    const canViewCustomerScopeAll = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE
    );
    const canOperateCustomerScopeAll = permissionCodeSet.has(
      TENANT_CUSTOMER_SCOPE_ALL_OPERATE_PERMISSION_CODE
    );
    if (
      canViewCustomerScopeMy
      || canViewCustomerScopeAssist
      || canViewCustomerScopeAll
    ) {
      permissionCodeSet.add(TENANT_CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (
      canOperateCustomerScopeMy
      || canOperateCustomerScopeAssist
      || canOperateCustomerScopeAll
    ) {
      permissionCodeSet.add(TENANT_CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE);
    }
    const canViewCustomerManagement = permissionCodeSet.has(
      TENANT_CUSTOMER_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || canViewCustomerScopeMy
      || canViewCustomerScopeAssist
      || canViewCustomerScopeAll;
    const canOperateCustomerManagement = permissionCodeSet.has(
      TENANT_CUSTOMER_MANAGEMENT_OPERATE_PERMISSION_CODE
    ) || canOperateCustomerScopeMy
      || canOperateCustomerScopeAssist
      || canOperateCustomerScopeAll;
    const canViewSessionScopeMy = permissionCodeSet.has(
      TENANT_SESSION_SCOPE_MY_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_SESSION_SCOPE_MY_OPERATE_PERMISSION_CODE
    );
    const canOperateSessionScopeMy = permissionCodeSet.has(
      TENANT_SESSION_SCOPE_MY_OPERATE_PERMISSION_CODE
    );
    const canViewSessionScopeAssist = permissionCodeSet.has(
      TENANT_SESSION_SCOPE_ASSIST_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_SESSION_SCOPE_ASSIST_OPERATE_PERMISSION_CODE
    );
    const canOperateSessionScopeAssist = permissionCodeSet.has(
      TENANT_SESSION_SCOPE_ASSIST_OPERATE_PERMISSION_CODE
    );
    const canViewSessionScopeAll = permissionCodeSet.has(
      TENANT_SESSION_SCOPE_ALL_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_SESSION_SCOPE_ALL_OPERATE_PERMISSION_CODE
    );
    const canOperateSessionScopeAll = permissionCodeSet.has(
      TENANT_SESSION_SCOPE_ALL_OPERATE_PERMISSION_CODE
    );
    if (
      canViewSessionScopeMy
      || canViewSessionScopeAssist
      || canViewSessionScopeAll
    ) {
      permissionCodeSet.add(TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE);
    }
    if (
      canOperateSessionScopeMy
      || canOperateSessionScopeAssist
      || canOperateSessionScopeAll
    ) {
      permissionCodeSet.add(TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE);
    }
    const canViewSessionManagement = permissionCodeSet.has(
      TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE
    ) || canViewSessionScopeMy
      || canViewSessionScopeAssist
      || canViewSessionScopeAll;
    const canOperateSessionManagement = permissionCodeSet.has(
      TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE
    ) || canOperateSessionScopeMy
      || canOperateSessionScopeAssist
      || canOperateSessionScopeAll;
    const canViewRoleManagement = permissionCodeSet.has(
      TENANT_ROLE_MANAGEMENT_VIEW_PERMISSION_CODE
    ) || permissionCodeSet.has(
      TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
    );
    const canOperateRoleManagement = permissionCodeSet.has(
      TENANT_ROLE_MANAGEMENT_OPERATE_PERMISSION_CODE
    );

    const context = {
      scopeLabel: `组织权限（${String(row.tenant_name || normalizedTenantId)}）`,
      canViewUserManagement,
      canOperateUserManagement,
      canViewAccountManagement,
      canOperateAccountManagement,
      canViewCustomerManagement,
      canOperateCustomerManagement,
      canViewCustomerScopeMy,
      canOperateCustomerScopeMy,
      canViewCustomerScopeAssist,
      canOperateCustomerScopeAssist,
      canViewCustomerScopeAll,
      canOperateCustomerScopeAll,
      canViewSessionManagement,
      canOperateSessionManagement,
      canViewSessionScopeMy,
      canOperateSessionScopeMy,
      canViewSessionScopeAssist,
      canOperateSessionScopeAssist,
      canViewSessionScopeAll,
      canOperateSessionScopeAll,
      canViewRoleManagement,
      canOperateRoleManagement
    };
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

  listTenantOptionsByUserId: async (userId) => {
    const normalizedUserId = String(userId);
    const rows = await runTenantUsershipQuery({
      sqlWithOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 u.phone AS owner_phone,
                 (
                   SELECT ut_owner.display_name
                   FROM tenant_memberships ut_owner
                   WHERE ut_owner.user_id = o.owner_user_id
                     AND ut_owner.tenant_id = o.id
                     AND ut_owner.display_name IS NOT NULL
                     AND TRIM(ut_owner.display_name) <> ''
                   ORDER BY ut_owner.joined_at DESC, ut_owner.membership_id DESC
                   LIMIT 1
                 ) AS owner_name
          FROM tenant_memberships ut
          LEFT JOIN tenants o ON o.id = ut.tenant_id
          LEFT JOIN iam_users u ON u.id = o.owner_user_id
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
            AND o.status IN ('active', 'enabled')
          ORDER BY tenant_id ASC
        `,
      sqlWithoutOrgGuard: `
          SELECT tenant_id,
                 tenant_name,
                 NULL AS owner_phone,
                 NULL AS owner_name
          FROM tenant_memberships ut
          WHERE ut.user_id = ?
            AND ut.status IN ('active', 'enabled')
          ORDER BY tenant_id ASC
        `,
      params: [normalizedUserId]
    });

    return (Array.isArray(rows) ? rows : [])
      .map((row) => {
        const ownerName = row.owner_name ? String(row.owner_name).trim() : null;
        const ownerPhone = row.owner_phone ? String(row.owner_phone).trim() : null;
        return {
          tenantId: String(row.tenant_id || '').trim(),
          tenantName: row.tenant_name ? String(row.tenant_name) : null,
          ...(ownerName ? { ownerName } : {}),
          ...(ownerPhone ? { ownerPhone } : {})
        };
      })
      .filter((row) => row.tenantId.length > 0);
  },

  hasAnyTenantRelationshipByUserId: async (userId) => {
    const normalizedUserId = String(userId);
    const rows = await dbClient.query(
      `
        SELECT COUNT(*) AS tenant_count
        FROM tenant_memberships
        WHERE user_id = ?
      `,
      [normalizedUserId]
    );
    return Number(rows?.[0]?.tenant_count || 0) > 0;
  },
});

module.exports = {
  createTenantMysqlAuthStoreRepositorySessionAccessGovernance
};
