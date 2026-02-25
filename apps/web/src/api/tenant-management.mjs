import { buildIdempotencyKey } from '../shared-kernel/http/idempotency-key.mjs';
import {
  createApiRequest,
  toProblemMessage,
  toSearch
} from '../shared-kernel/http/request-json.mjs';

export { toProblemMessage };

export const normalizeRoleIds = (rawRoleIds = []) => {
  const deduped = new Set();
  for (const roleId of Array.isArray(rawRoleIds) ? rawRoleIds : []) {
    const normalizedRoleId = String(roleId || '').trim().toLowerCase();
    if (normalizedRoleId) {
      deduped.add(normalizedRoleId);
    }
  }
  return [...deduped];
};

export const createTenantManagementApi = ({ accessToken }) => {
  const withToken = createApiRequest({ accessToken });
  const withMemberId = (membershipId) =>
    encodeURIComponent(String(membershipId || '').trim());
  const withRoleId = (roleId) =>
    encodeURIComponent(String(roleId || '').trim().toLowerCase());

  return {
    listUsers: async ({ page = 1, pageSize = 20 } = {}) =>
      withToken({
        path: `/tenant/users${toSearch({
          page,
          page_size: pageSize
        })}`,
        method: 'GET'
      }),

    createUser: async ({ phone }) =>
      withToken({
        path: '/tenant/users',
        method: 'POST',
        payload: {
          phone: String(phone || '').trim()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-create')
      }),

    getMember: async (membershipId) =>
      withToken({
        path: `/tenant/users/${withMemberId(membershipId)}`,
        method: 'GET'
      }),

    updateUserStatus: async ({ membershipId, status, reason = null }) => {
      const payload = {
        status: String(status || '').trim().toLowerCase()
      };
      if (reason) {
        payload.reason = String(reason).trim();
      }
      return withToken({
        path: `/tenant/users/${withMemberId(membershipId)}/status`,
        method: 'PATCH',
        payload,
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-status')
      });
    },

    updateUserProfile: async ({
      membershipId,
      display_name,
      department_name = null
    }) =>
      withToken({
        path: `/tenant/users/${withMemberId(membershipId)}/profile`,
        method: 'PATCH',
        payload: {
          display_name: String(display_name || '').trim(),
          department_name: department_name == null ? null : String(department_name).trim()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-profile')
      }),

    getUserRoles: async (membershipId) =>
      withToken({
        path: `/tenant/users/${withMemberId(membershipId)}/roles`,
        method: 'GET'
      }),

    replaceUserRoles: async ({ membershipId, role_ids = [] }) =>
      withToken({
        path: `/tenant/users/${withMemberId(membershipId)}/roles`,
        method: 'PUT',
        payload: {
          role_ids: normalizeRoleIds(role_ids)
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-roles')
      }),

    listRoles: async () =>
      withToken({
        path: '/tenant/roles',
        method: 'GET'
      }),

    createRole: async (payload = {}) => {
      const normalizedPayload = {
        code: String(payload.code || '').trim(),
        name: String(payload.name || '').trim(),
        status: String(payload.status || 'active').trim().toLowerCase()
      };
      const normalizedRoleId = String(
        payload.role_id || payload.roleId || ''
      ).trim().toLowerCase();
      if (normalizedRoleId) {
        normalizedPayload.role_id = normalizedRoleId;
      }
      return withToken({
        path: '/tenant/roles',
        method: 'POST',
        payload: normalizedPayload,
        idempotencyKey: buildIdempotencyKey('ui-tenant-roles-create')
      });
    },

    updateRole: async ({ roleId, payload = {} }) =>
      withToken({
        path: `/tenant/roles/${withRoleId(roleId)}`,
        method: 'PATCH',
        payload: {
          code: String(payload.code || '').trim(),
          name: String(payload.name || '').trim(),
          status: String(payload.status || 'active').trim().toLowerCase()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-roles-update')
      }),

    deleteRole: async (roleId) =>
      withToken({
        path: `/tenant/roles/${withRoleId(roleId)}`,
        method: 'DELETE',
        idempotencyKey: buildIdempotencyKey('ui-tenant-roles-delete')
      }),

    getRolePermissions: async (roleId) =>
      withToken({
        path: `/tenant/roles/${withRoleId(roleId)}/permissions`,
        method: 'GET'
      }),

    replaceRolePermissions: async ({ roleId, permissionCodes = [] }) =>
      withToken({
        path: `/tenant/roles/${withRoleId(roleId)}/permissions`,
        method: 'PUT',
        payload: {
          permission_codes: [...new Set(
            (Array.isArray(permissionCodes) ? permissionCodes : [])
              .map((permissionCode) => String(permissionCode || '').trim())
              .filter((permissionCode) => permissionCode.startsWith('tenant.'))
          )]
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-roles-permissions')
      })
  };
};
