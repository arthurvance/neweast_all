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
  const withAccountId = (accountId) =>
    encodeURIComponent(String(accountId || '').trim());
  const withCustomerId = (customerId) =>
    encodeURIComponent(String(customerId || '').trim());
  const withConversationId = (conversationId) =>
    encodeURIComponent(String(conversationId || '').trim());
  const normalizeQueryIdList = (source = []) =>
    [...new Set(
      (Array.isArray(source) ? source : [])
        .map((value) => String(value || '').trim())
        .filter(Boolean)
    )];

  return {
    listUsers: async ({ page = 1, pageSize = 20, status = undefined } = {}) =>
      withToken({
        path: `/tenant/users${toSearch({
          page,
          page_size: pageSize,
          status
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

    listAccounts: async (query = {}) =>
      withToken({
        path: `/tenant/accounts${toSearch({
          page: query.page,
          page_size: query.pageSize,
          wechat_id: query.wechat_id,
          nickname: query.nickname,
          owner_keyword: query.owner_keyword,
          assistant_keyword: query.assistant_keyword,
          status: query.status,
          created_time_start: query.created_time_start,
          created_time_end: query.created_time_end
        })}`,
        method: 'GET'
      }),

    getAccountDetail: async (accountId) =>
      withToken({
        path: `/tenant/accounts/${withAccountId(accountId)}`,
        method: 'GET'
      }),

    createAccount: async (payload = {}) =>
      withToken({
        path: '/tenant/accounts',
        method: 'POST',
        payload: {
          wechat_id: String(payload.wechat_id || '').trim(),
          nickname: String(payload.nickname || '').trim(),
          owner_membership_id: String(payload.owner_membership_id || '').trim(),
          assistant_membership_ids: [...new Set(
            (Array.isArray(payload.assistant_membership_ids) ? payload.assistant_membership_ids : [])
              .map((membershipId) => String(membershipId || '').trim())
              .filter(Boolean)
          )]
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-accounts-create')
      }),

    updateAccount: async ({ accountId, payload = {} }) =>
      withToken({
        path: `/tenant/accounts/${withAccountId(accountId)}`,
        method: 'PATCH',
        payload: {
          wechat_id: String(payload.wechat_id || '').trim(),
          nickname: String(payload.nickname || '').trim(),
          owner_membership_id: String(payload.owner_membership_id || '').trim(),
          assistant_membership_ids: [...new Set(
            (Array.isArray(payload.assistant_membership_ids) ? payload.assistant_membership_ids : [])
              .map((membershipId) => String(membershipId || '').trim())
              .filter(Boolean)
          )]
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-accounts-update')
      }),

    updateAccountStatus: async ({ accountId, status }) =>
      withToken({
        path: `/tenant/accounts/${withAccountId(accountId)}/status`,
        method: 'PATCH',
        payload: {
          status: String(status || '').trim().toLowerCase()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-accounts-status')
      }),

    listSessionAccounts: async (query = {}) =>
      withToken({
        path: `/tenant/sessions/account-options${toSearch({
          scope: String(query.scope || '').trim().toLowerCase()
        })}`,
        method: 'GET'
      }),

    listSessions: async (query = {}) =>
      withToken({
        path: `/tenant/sessions/chats${toSearch({
          page: query.page,
          page_size: query.pageSize,
          scope: query.scope,
          account_wechat_id:
            query.account_wechat_id
            ?? query.accountWechatId
            ?? query.account_id
            ?? query.accountId,
          keyword: query.keyword
        })}`,
        method: 'GET'
      }),

    getSessionMessages: async ({
      conversationId,
      sessionId,
      account_wechat_id,
      accountWechatId,
      account_id,
      accountId,
      scope = 'my',
      cursor = undefined,
      limit = 50
    } = {}) =>
      withToken({
        path: `/tenant/sessions/chats/${withConversationId(
          conversationId ?? sessionId
        )}/messages${toSearch({
          scope,
          account_wechat_id:
            account_wechat_id
            ?? accountWechatId
            ?? account_id
            ?? accountId,
          cursor,
          limit
        })}`,
        method: 'GET'
      }),

    sendSessionMessage: async ({ payload = {} } = {}) =>
      withToken({
        path: '/tenant/sessions/messages',
        method: 'POST',
        payload: {
          account_wechat_id: String((
            payload.account_wechat_id
            ?? payload.accountWechatId
            ?? payload.account_id
            ?? payload.accountId
            ?? ''
          )).trim(),
          account_nickname: String((
            payload.account_nickname
            ?? payload.accountNickname
            ?? ''
          )).trim(),
          conversation_id: String((
            payload.conversation_id
            ?? payload.conversationId
            ?? payload.session_id
            ?? payload.sessionId
            ?? ''
          )).trim(),
          conversation_name: String((
            payload.conversation_name
            ?? payload.conversationName
            ?? ''
          )).trim(),
          message_type: String(
            payload.message_type
            ?? payload.messageType
            ?? 'text'
          ).trim().toLowerCase(),
          message_payload_json: payload.message_payload_json
            ?? payload.messagePayloadJson
            ?? { text: String(payload.content || '').trim() },
          client_message_id: String((
            payload.client_message_id
            ?? payload.clientMessageId
            ?? ''
          )).trim() || undefined
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-sessions-send-message')
      }),

    listCustomers: async (query = {}) =>
      withToken({
        path: `/tenant/customers${toSearch({
          page: query.page,
          page_size: query.pageSize,
          scope: query.scope,
          wechat_id: query.wechat_id,
          account_ids: normalizeQueryIdList(query.account_ids).join(','),
          nickname: query.nickname,
          source: query.source,
          real_name: query.real_name,
          phone: query.phone,
          status: query.status,
          created_time_start: query.created_time_start,
          created_time_end: query.created_time_end
        })}`,
        method: 'GET'
      }),

    createCustomer: async (payload = {}) =>
      withToken({
        path: '/tenant/customers',
        method: 'POST',
        payload: {
          account_id: String(payload.account_id || '').trim(),
          wechat_id: String(payload.wechat_id || '').trim(),
          nickname: String(payload.nickname || '').trim(),
          source: String(payload.source || '').trim().toLowerCase(),
          real_name: payload.real_name == null ? null : String(payload.real_name).trim(),
          school: payload.school == null ? null : String(payload.school).trim(),
          class_name: payload.class_name == null ? null : String(payload.class_name).trim(),
          relation: payload.relation == null ? null : String(payload.relation).trim(),
          phone: payload.phone == null ? null : String(payload.phone).trim(),
          address: payload.address == null ? null : String(payload.address).trim()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-customers-create')
      }),

    getCustomerDetail: async (customerId) =>
      withToken({
        path: `/tenant/customers/${withCustomerId(customerId)}`,
        method: 'GET'
      }),

    updateCustomerBasic: async ({ customerId, payload = {} }) =>
      withToken({
        path: `/tenant/customers/${withCustomerId(customerId)}/basic`,
        method: 'PATCH',
        payload: {
          source: String(payload.source || '').trim().toLowerCase()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-customers-basic')
      }),

    updateCustomerRealname: async ({ customerId, payload = {} }) =>
      withToken({
        path: `/tenant/customers/${withCustomerId(customerId)}/realname`,
        method: 'PATCH',
        payload: {
          real_name: payload.real_name == null ? null : String(payload.real_name).trim(),
          school: payload.school == null ? null : String(payload.school).trim(),
          class_name: payload.class_name == null ? null : String(payload.class_name).trim(),
          relation: payload.relation == null ? null : String(payload.relation).trim(),
          phone: payload.phone == null ? null : String(payload.phone).trim(),
          address: payload.address == null ? null : String(payload.address).trim()
        },
        idempotencyKey: buildIdempotencyKey('ui-tenant-customers-realname')
      }),

    listCustomerOperationLogs: async (customerId) =>
      withToken({
        path: `/tenant/customers/${withCustomerId(customerId)}/operation-logs`,
        method: 'GET'
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
