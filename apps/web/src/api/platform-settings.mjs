const API_BASE_URL = String(import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const RETRY_SUFFIX = '请稍后重试';

const readJsonSafely = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (
    contentType.includes('application/json')
    || contentType.includes('application/problem+json')
  ) {
    try {
      return await response.json();
    } catch (_error) {
      return {};
    }
  }

  const text = await response.text();
  return {
    detail: text || '请求失败'
  };
};

const buildIdempotencyKey = (prefix = 'ui-platform-settings') => {
  const randomPart = Math.random().toString(16).slice(2);
  return `${prefix}-${Date.now()}-${randomPart}`;
};

const requestJson = async ({
  path,
  method = 'GET',
  payload,
  accessToken,
  idempotencyKey = null
}) => {
  const headers = {
    Accept: 'application/json, application/problem+json'
  };

  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }
  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (idempotencyKey) {
    headers['Idempotency-Key'] = String(idempotencyKey);
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    body: payload === undefined ? undefined : JSON.stringify(payload)
  });

  const body = await readJsonSafely(response);
  if (response.ok) {
    return body;
  }

  const error = new Error(body?.detail || '请求失败');
  error.status = response.status;
  error.payload = body || {};
  throw error;
};

const toSearch = (query = {}) => {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) {
    if (
      value === null
      || value === undefined
      || value === ''
    ) {
      continue;
    }
    searchParams.set(key, String(value));
  }
  const search = searchParams.toString();
  return search ? `?${search}` : '';
};

export const toProblemMessage = (error, fallback = '操作失败') => {
  const detail = String(error?.payload?.detail || error?.message || fallback || '').trim();
  if (!detail) {
    return `${fallback}，${RETRY_SUFFIX}`;
  }
  if (detail.includes(RETRY_SUFFIX)) {
    return detail;
  }
  return `${detail}，${RETRY_SUFFIX}`;
};

export const createPlatformSettingsApi = ({ accessToken }) => {
  const withToken = (options) => requestJson({ ...options, accessToken });

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
