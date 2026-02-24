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

const buildIdempotencyKey = (prefix = 'ui-tenant-management') => {
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
  const withToken = (options) => requestJson({ ...options, accessToken });
  const withMemberId = (membershipId) =>
    encodeURIComponent(String(membershipId || '').trim());
  const withRoleId = (roleId) =>
    encodeURIComponent(String(roleId || '').trim().toLowerCase());

  return {
    listMembers: async ({ page = 1, pageSize = 20 } = {}) =>
      withToken({
        path: `/tenant/members${toSearch({
          page,
          page_size: pageSize
        })}`,
        method: 'GET'
      }),

    createMember: async ({ phone }) =>
      withToken({
        path: '/tenant/members',
        method: 'POST',
        payload: {
          phone: String(phone || '').trim()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-create')
      }),

    getMember: async (membershipId) =>
      withToken({
        path: `/tenant/members/${withMemberId(membershipId)}`,
        method: 'GET'
      }),

    updateMemberStatus: async ({ membershipId, status, reason = null }) => {
      const payload = {
        status: String(status || '').trim().toLowerCase()
      };
      if (reason) {
        payload.reason = String(reason).trim();
      }
      return withToken({
        path: `/tenant/members/${withMemberId(membershipId)}/status`,
        method: 'PATCH',
        payload,
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-status')
      });
    },

    updateMemberProfile: async ({
      membershipId,
      display_name,
      department_name = null
    }) =>
      withToken({
        path: `/tenant/members/${withMemberId(membershipId)}/profile`,
        method: 'PATCH',
        payload: {
          display_name: String(display_name || '').trim(),
          department_name: department_name == null ? null : String(department_name).trim()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-members-profile')
      }),

    getMemberRoles: async (membershipId) =>
      withToken({
        path: `/tenant/members/${withMemberId(membershipId)}/roles`,
        method: 'GET'
      }),

    replaceMemberRoles: async ({ membershipId, role_ids = [] }) =>
      withToken({
        path: `/tenant/members/${withMemberId(membershipId)}/roles`,
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

    createRole: async (payload = {}) =>
      withToken({
        path: '/tenant/roles',
        method: 'POST',
        payload: {
          role_id: String(payload.role_id || '').trim().toLowerCase(),
          code: String(payload.code || '').trim(),
          name: String(payload.name || '').trim(),
          status: String(payload.status || 'active').trim().toLowerCase()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-roles-create')
      }),

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
