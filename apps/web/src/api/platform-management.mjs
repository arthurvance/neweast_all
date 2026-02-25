import { buildIdempotencyKey } from '../shared-kernel/http/idempotency-key.mjs';
import {
  createApiRequest,
  toProblemMessage,
  toSearch
} from '../shared-kernel/http/request-json.mjs';

export { toProblemMessage };

export const createPlatformManagementApi = ({ accessToken }) => {
  const withToken = createApiRequest({ accessToken });

  return {
    listOrgs: async ({
      page = 1,
      pageSize = 20,
      orgName = null,
      owner = null,
      status = null,
      createdAtStart = null,
      createdAtEnd = null
    } = {}) =>
      withToken({
        path: `/platform/orgs${toSearch({
          page,
          page_size: pageSize,
          org_name: orgName,
          owner,
          status,
          created_at_start: createdAtStart,
          created_at_end: createdAtEnd
        })}`,
        method: 'GET'
      }),

    createOrg: async ({
      orgName,
      initialOwnerName,
      initialOwnerPhone
    } = {}) =>
      withToken({
        path: '/platform/orgs',
        method: 'POST',
        payload: {
          org_name: orgName,
          initial_owner_name: initialOwnerName,
          initial_owner_phone: initialOwnerPhone
        },
        idempotencyKey: buildIdempotencyKey('ui-platform-orgs-create')
      }),

    listUsers: async ({
      page = 1,
      pageSize = 20,
      status = null,
      keyword = null,
      phone = null,
      name = null,
      createdAtStart = null,
      createdAtEnd = null
    } = {}) =>
      withToken({
        path: `/platform/users${toSearch({
          page,
          page_size: pageSize,
          status,
          keyword,
          phone,
          name,
          created_at_start: createdAtStart,
          created_at_end: createdAtEnd
        })}`,
        method: 'GET'
      }),

    getUser: async (userId) =>
      withToken({
        path: `/platform/users/${encodeURIComponent(String(userId || '').trim())}`,
        method: 'GET'
      }),

    createUser: async ({
      phone,
      name,
      department = null,
      roleIds = []
    }) =>
      withToken({
        path: '/platform/users',
        method: 'POST',
        payload: {
          phone,
          name,
          department,
          role_ids: Array.isArray(roleIds) ? roleIds : []
        },
        idempotencyKey: buildIdempotencyKey('ui-platform-users-create')
      }),

    updateUser: async ({
      userId,
      name,
      department = null,
      roleIds = undefined
    } = {}) => {
      const payload = {
        name,
        department
      };
      if (Array.isArray(roleIds)) {
        payload.role_ids = roleIds;
      }
      return withToken({
        path: `/platform/users/${encodeURIComponent(String(userId || '').trim())}`,
        method: 'PATCH',
        payload,
        idempotencyKey: buildIdempotencyKey('ui-platform-users-update')
      });
    },

    updateUserStatus: async ({ user_id, status, reason = null }) => {
      const payload = {
        user_id,
        status
      };
      if (reason) {
        payload.reason = reason;
      }
      return withToken({
        path: '/platform/users/status',
        method: 'POST',
        payload,
        idempotencyKey: buildIdempotencyKey('ui-platform-users-status')
      });
    },

    softDeleteUser: async (userId) =>
      withToken({
        path: `/platform/users/${encodeURIComponent(String(userId || '').trim())}`,
        method: 'DELETE',
        idempotencyKey: buildIdempotencyKey('ui-platform-users-delete')
      }),

    listRoles: async () =>
      withToken({
        path: '/platform/roles',
        method: 'GET'
      }),

    createRole: async (payload = {}) =>
      withToken({
        path: '/platform/roles',
        method: 'POST',
        payload,
        idempotencyKey: buildIdempotencyKey('ui-platform-roles-create')
      }),

    updateRole: async ({ roleId, payload = {} }) =>
      withToken({
        path: `/platform/roles/${encodeURIComponent(String(roleId || '').trim().toLowerCase())}`,
        method: 'PATCH',
        payload,
        idempotencyKey: buildIdempotencyKey('ui-platform-roles-update')
      }),

    deleteRole: async (roleId) =>
      withToken({
        path: `/platform/roles/${encodeURIComponent(String(roleId || '').trim().toLowerCase())}`,
        method: 'DELETE',
        idempotencyKey: buildIdempotencyKey('ui-platform-roles-delete')
      }),

    getRolePermissions: async (roleId) =>
      withToken({
        path: `/platform/roles/${encodeURIComponent(String(roleId || '').trim().toLowerCase())}/permissions`,
        method: 'GET'
      }),

    replaceRolePermissions: async ({ roleId, permissionCodes = [] }) =>
      withToken({
        path: `/platform/roles/${encodeURIComponent(String(roleId || '').trim().toLowerCase())}/permissions`,
        method: 'PUT',
        payload: {
          permission_codes: permissionCodes
        },
        idempotencyKey: buildIdempotencyKey('ui-platform-roles-permissions')
      }),

    replaceRoleFacts: async ({ userId, roleIds = [] }) =>
      withToken({
        path: '/auth/platform/role-facts/replace',
        method: 'POST',
        payload: {
          user_id: String(userId || '').trim(),
          roles: roleIds.map((roleId) => ({
            role_id: String(roleId || '').trim().toLowerCase(),
            status: 'active'
          }))
        },
        idempotencyKey: buildIdempotencyKey('ui-platform-role-facts-replace')
      })
  };
};
