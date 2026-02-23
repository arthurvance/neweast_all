import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Space,
  Tree,
  Typography,
  message
} from 'antd';
import CustomCardTable from '../../components/CustomCardTable';
import CustomFilter from '../../components/CustomFilter';
import CustomForm from '../../components/CustomForm';
import {
  createTenantGovernanceApi,
  normalizeRoleIds,
  toProblemMessage
} from '../../api/tenant-governance.mjs';

const { Text } = Typography;

const MEMBER_STATUS_OPTIONS = [
  { label: '全部状态', value: '' },
  { label: 'active', value: 'active' },
  { label: 'disabled', value: 'disabled' },
  { label: 'left', value: 'left' }
];

const ROLE_STATUS_OPTIONS = [
  { label: '全部状态', value: '' },
  { label: 'active', value: 'active' },
  { label: 'disabled', value: 'disabled' }
];

const toPermissionTreeData = (availablePermissionCodes = []) => {
  const modules = new Map();
  for (const permissionCode of availablePermissionCodes) {
    const normalizedCode = String(permissionCode || '').trim();
    if (!normalizedCode.startsWith('tenant.')) {
      continue;
    }
    const sections = normalizedCode.split('.');
    const moduleName = sections[1] || 'misc';
    const moduleKey = `tenant.${moduleName}`;
    const moduleNode = modules.get(moduleKey) || {
      key: moduleKey,
      title: moduleName,
      selectable: false,
      children: []
    };
    moduleNode.children.push({
      key: normalizedCode,
      title: sections.slice(2).join('.') || normalizedCode
    });
    modules.set(moduleKey, moduleNode);
  }

  return [...modules.values()]
    .map((node) => ({
      ...node,
      children: [...node.children].sort((left, right) => String(left.key).localeCompare(String(right.key)))
    }))
    .sort((left, right) => String(left.key).localeCompare(String(right.key)));
};

const statusToggleLabel = (status) => {
  const normalized = String(status || '').trim().toLowerCase();
  return normalized === 'active' ? '禁用' : '启用';
};

const statusToggleValue = (status) => {
  const normalized = String(status || '').trim().toLowerCase();
  return normalized === 'active' ? 'disabled' : 'active';
};

const filterMembersOnClient = (members = [], filters = {}) => {
  const keyword = String(filters.keyword || '').trim().toLowerCase();
  const status = String(filters.status || '').trim().toLowerCase();
  return members.filter((member) => {
    const memberStatus = String(member.status || '').trim().toLowerCase();
    if (status && status !== memberStatus) {
      return false;
    }
    if (!keyword) {
      return true;
    }
    return [
      member.membership_id,
      member.user_id,
      member.phone,
      member.display_name,
      member.department_name
    ]
      .map((value) => String(value || '').toLowerCase())
      .some((value) => value.includes(keyword));
  });
};

const hasActiveMemberFilters = (filters = {}) => {
  const keyword = String(filters.keyword || '').trim();
  const status = String(filters.status || '').trim();
  return Boolean(keyword || status);
};

const formatProblemText = (error, fallback) => {
  const text = toProblemMessage(error, fallback);
  const errorCode = String(error?.payload?.error_code || '').trim();
  if (!errorCode || text.includes(errorCode)) {
    return text;
  }
  return `${text}（${errorCode}）`;
};

export default function TenantGovernanceWorkbench({
  accessToken,
  onTenantPermissionContextRefresh
}) {
  const api = useMemo(
    () => createTenantGovernanceApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [activeModule, setActiveModule] = useState('members');

  const [memberFilterForm] = Form.useForm();
  const [memberCreateForm] = Form.useForm();
  const [memberStatusForm] = Form.useForm();
  const [memberProfileForm] = Form.useForm();
  const [memberAssignForm] = Form.useForm();
  const [roleFilterForm] = Form.useForm();
  const [roleEditForm] = Form.useForm();

  const [memberFilters, setMemberFilters] = useState({ keyword: '', status: '' });
  const [memberTableRefreshToken, setMemberTableRefreshToken] = useState(0);
  const [memberCreateOpen, setMemberCreateOpen] = useState(false);
  const [memberCreateSubmitting, setMemberCreateSubmitting] = useState(false);
  const [memberStatusOpen, setMemberStatusOpen] = useState(false);
  const [memberStatusSubmitting, setMemberStatusSubmitting] = useState(false);
  const [memberStatusTarget, setMemberStatusTarget] = useState(null);
  const [memberProfileOpen, setMemberProfileOpen] = useState(false);
  const [memberProfileSubmitting, setMemberProfileSubmitting] = useState(false);
  const [memberProfileTarget, setMemberProfileTarget] = useState(null);
  const [memberAssignOpen, setMemberAssignOpen] = useState(false);
  const [memberAssignSubmitting, setMemberAssignSubmitting] = useState(false);
  const [memberAssignTarget, setMemberAssignTarget] = useState(null);
  const [memberDetailOpen, setMemberDetailOpen] = useState(false);
  const [memberDetailLoading, setMemberDetailLoading] = useState(false);
  const [memberDetail, setMemberDetail] = useState(null);
  const [latestMemberActionById, setLatestMemberActionById] = useState({});

  const [roleFilters, setRoleFilters] = useState({ keyword: '', status: '' });
  const [roleList, setRoleList] = useState([]);
  const [roleListLoading, setRoleListLoading] = useState(false);
  const [roleEditOpen, setRoleEditOpen] = useState(false);
  const [roleEditSubmitting, setRoleEditSubmitting] = useState(false);
  const [roleEditMode, setRoleEditMode] = useState('create');
  const [roleEditTarget, setRoleEditTarget] = useState(null);
  const [roleDetailOpen, setRoleDetailOpen] = useState(false);
  const [roleDetail, setRoleDetail] = useState(null);
  const [permissionCodesAvailable, setPermissionCodesAvailable] = useState([]);
  const [permissionCodesChecked, setPermissionCodesChecked] = useState([]);
  const [permissionLoading, setPermissionLoading] = useState(false);
  const [permissionSaving, setPermissionSaving] = useState(false);

  const notifySuccess = useCallback((text) => {
    const normalizedText = String(text || '').trim();
    if (!normalizedText) {
      return;
    }
    messageApi.success(normalizedText);
  }, [messageApi]);

  const notifyError = useCallback((error, fallback) => {
    messageApi.error(formatProblemText(error, fallback));
  }, [messageApi]);

  const refreshMemberTable = useCallback(() => {
    setMemberTableRefreshToken((previous) => previous + 1);
  }, []);

  const loadRoles = useCallback(async () => {
    setRoleListLoading(true);
    try {
      const payload = await api.listRoles();
      const roles = Array.isArray(payload?.roles) ? payload.roles : [];
      setRoleList(roles.map((role) => ({ ...role, key: role.role_id })));
    } catch (error) {
      notifyError(error, '加载组织角色列表失败');
    } finally {
      setRoleListLoading(false);
    }
  }, [api, notifyError]);

  useEffect(() => {
    if (!accessToken) {
      return;
    }
    void loadRoles();
  }, [accessToken, loadRoles]);

  const openMemberDetail = useCallback(
    async (membershipId, latestActionOverride = null) => {
      const normalizedMembershipId = String(membershipId || '').trim();
      if (!normalizedMembershipId) {
        return;
      }
      setMemberDetailOpen(true);
      setMemberDetailLoading(true);
      try {
        const [detailPayload, rolePayload] = await Promise.all([
          api.getMember(normalizedMembershipId),
          api.getMemberRoles(normalizedMembershipId)
        ]);
        const latestAction =
          latestActionOverride
          || latestMemberActionById[normalizedMembershipId]
          || null;
        setMemberDetail({
          ...detailPayload,
          role_ids: Array.isArray(rolePayload?.role_ids) ? rolePayload.role_ids : [],
          latest_action: latestAction
        });
      } catch (error) {
        setMemberDetail(null);
        notifyError(error, '加载组织成员详情失败');
      } finally {
        setMemberDetailLoading(false);
      }
    },
    [api, latestMemberActionById, notifyError]
  );

  const openMemberStatusModal = useCallback((record) => {
    setMemberStatusTarget(record);
    setMemberStatusOpen(true);
    memberStatusForm.setFieldsValue({
      status: statusToggleValue(record?.status),
      reason: ''
    });
  }, [memberStatusForm]);

  const openMemberProfileModal = useCallback((record) => {
    setMemberProfileTarget(record);
    setMemberProfileOpen(true);
    memberProfileForm.setFieldsValue({
      display_name: record?.display_name || '',
      department_name: record?.department_name || ''
    });
  }, [memberProfileForm]);

  const openMemberAssignModal = useCallback(
    async (record) => {
      const normalizedMembershipId = String(record?.membership_id || '').trim();
      if (!normalizedMembershipId) {
        return;
      }
      if (roleList.length <= 0) {
        await loadRoles();
      }
      setMemberAssignTarget(record);
      setMemberAssignOpen(true);
      try {
        const payload = await api.getMemberRoles(normalizedMembershipId);
        memberAssignForm.setFieldsValue({
          membership_id: normalizedMembershipId,
          role_ids_text: Array.isArray(payload?.role_ids) ? payload.role_ids.join(',') : ''
        });
      } catch (error) {
        memberAssignForm.setFieldsValue({
          membership_id: normalizedMembershipId,
          role_ids_text: ''
        });
        notifyError(error, '加载成员角色绑定失败');
      }
    },
    [api, loadRoles, memberAssignForm, notifyError, roleList.length]
  );

  const handleCreateMember = useCallback(async () => {
    try {
      const values = await memberCreateForm.validateFields();
      setMemberCreateSubmitting(true);
      const payload = await api.createMember({
        phone: values.phone
      });
      const latestAction = {
        action: 'create',
        request_id: payload.request_id,
        result: payload.created_user ? 'created' : 'reused'
      };
      setLatestMemberActionById((previous) => ({
        ...previous,
        [payload.membership_id]: latestAction
      }));
      notifySuccess(`组织成员创建成功（request_id: ${payload.request_id}）`);
      setMemberCreateOpen(false);
      memberCreateForm.resetFields();
      refreshMemberTable();
      void openMemberDetail(payload.membership_id, latestAction);
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '创建组织成员失败');
    } finally {
      setMemberCreateSubmitting(false);
    }
  }, [
    api,
    memberCreateForm,
    notifyError,
    notifySuccess,
    openMemberDetail,
    refreshMemberTable
  ]);

  const handleSubmitMemberStatus = useCallback(async () => {
    if (!memberStatusTarget?.membership_id) {
      return;
    }
    try {
      const values = await memberStatusForm.validateFields();
      setMemberStatusSubmitting(true);
      const payload = await api.updateMemberStatus({
        membershipId: memberStatusTarget.membership_id,
        status: values.status,
        reason: values.reason || null
      });
      const latestAction = {
        action: 'status',
        request_id: payload.request_id,
        result: `${payload.previous_status} -> ${payload.current_status}`
      };
      setLatestMemberActionById((previous) => ({
        ...previous,
        [payload.membership_id]: latestAction
      }));
      notifySuccess(`成员状态更新成功（request_id: ${payload.request_id}）`);
      setMemberStatusOpen(false);
      setMemberStatusTarget(null);
      memberStatusForm.resetFields();
      refreshMemberTable();
      void openMemberDetail(payload.membership_id, latestAction);
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '更新成员状态失败');
    } finally {
      setMemberStatusSubmitting(false);
    }
  }, [
    api,
    memberStatusForm,
    memberStatusTarget,
    notifyError,
    notifySuccess,
    openMemberDetail,
    refreshMemberTable
  ]);

  const handleSubmitMemberProfile = useCallback(async () => {
    if (!memberProfileTarget?.membership_id) {
      return;
    }
    try {
      const values = await memberProfileForm.validateFields();
      setMemberProfileSubmitting(true);
      const payload = await api.updateMemberProfile({
        membershipId: memberProfileTarget.membership_id,
        display_name: values.display_name,
        department_name: values.department_name || null
      });
      const latestAction = {
        action: 'profile',
        request_id: payload.request_id,
        result: 'updated'
      };
      setLatestMemberActionById((previous) => ({
        ...previous,
        [payload.membership_id]: latestAction
      }));
      notifySuccess(`成员资料更新成功（request_id: ${payload.request_id}）`);
      setMemberProfileOpen(false);
      setMemberProfileTarget(null);
      memberProfileForm.resetFields();
      refreshMemberTable();
      void openMemberDetail(payload.membership_id, latestAction);
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '更新成员资料失败');
    } finally {
      setMemberProfileSubmitting(false);
    }
  }, [
    api,
    memberProfileForm,
    memberProfileTarget,
    notifyError,
    notifySuccess,
    openMemberDetail,
    refreshMemberTable
  ]);

  const handleSubmitMemberRoles = useCallback(async () => {
    if (!memberAssignTarget?.membership_id) {
      return;
    }
    try {
      const values = await memberAssignForm.validateFields();
      const normalizedRoleIds = normalizeRoleIds(
        String(values.role_ids_text || '')
          .split(',')
          .map((value) => String(value || '').trim())
      );
      if (normalizedRoleIds.length < 1 || normalizedRoleIds.length > 5) {
        messageApi.error('角色分配必须为 1 到 5 个角色，请稍后重试');
        return;
      }

      setMemberAssignSubmitting(true);
      const payload = await api.replaceMemberRoles({
        membershipId: memberAssignTarget.membership_id,
        role_ids: normalizedRoleIds
      });
      const latestAction = {
        action: 'roles',
        request_id: payload.request_id,
        result: normalizedRoleIds.join(',')
      };
      setLatestMemberActionById((previous) => ({
        ...previous,
        [payload.membership_id]: latestAction
      }));
      notifySuccess(`成员角色分配成功（request_id: ${payload.request_id}）`);
      setMemberAssignOpen(false);
      setMemberAssignTarget(null);
      refreshMemberTable();
      void openMemberDetail(payload.membership_id, latestAction);

      if (typeof onTenantPermissionContextRefresh === 'function') {
        try {
          await onTenantPermissionContextRefresh();
        } catch (refreshError) {
          if (!refreshError?.uiMessageHandled) {
            notifyError(refreshError, '权限上下文刷新失败');
          }
        }
      }
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '成员角色分配失败');
    } finally {
      setMemberAssignSubmitting(false);
    }
  }, [
    api,
    memberAssignForm,
    memberAssignTarget,
    messageApi,
    notifyError,
    notifySuccess,
    onTenantPermissionContextRefresh,
    openMemberDetail,
    refreshMemberTable
  ]);

  const memberTableRequest = useCallback(
    async (params) => {
      const page = Math.max(1, Number(params?.current || 1));
      const pageSize = Math.max(1, Number(params?.pageSize || 10));
      const filtersActive = hasActiveMemberFilters(memberFilters);

      if (filtersActive) {
        const scanBatchSize = Math.min(200, Math.max(pageSize, 50));
        const allMembers = [];
        let scanPage = 1;
        let hasMorePages = true;
        while (hasMorePages && scanPage <= 500) {
          const payload = await api.listMembers({
            page: scanPage,
            pageSize: scanBatchSize
          });
          const members = Array.isArray(payload?.members) ? payload.members : [];
          allMembers.push(...members);
          hasMorePages = members.length === scanBatchSize;
          scanPage += 1;
        }

        const filteredMembers = filterMembersOnClient(allMembers, memberFilters);
        const offset = (page - 1) * pageSize;
        return {
          data: filteredMembers
            .slice(offset, offset + pageSize)
            .map((member) => ({ ...member, key: member.membership_id })),
          total: filteredMembers.length,
          success: true
        };
      }

      const payload = await api.listMembers({
        page,
        pageSize
      });
      const sourceMembers = Array.isArray(payload?.members) ? payload.members : [];
      const currentOffset = (page - 1) * pageSize;
      let total = currentOffset + sourceMembers.length;
      if (sourceMembers.length === pageSize) {
        const lookAheadPayload = await api.listMembers({
          page: page + 1,
          pageSize: 1
        });
        const hasNextPage =
          Array.isArray(lookAheadPayload?.members)
          && lookAheadPayload.members.length > 0;
        if (hasNextPage) {
          total += 1;
        }
      }

      return {
        data: sourceMembers.map((member) => ({ ...member, key: member.membership_id })),
        total,
        success: true
      };
    },
    [api, memberFilters, memberTableRefreshToken]
  );

  const memberColumns = useMemo(
    () => [
      {
        title: 'membership_id',
        dataIndex: 'membership_id',
        key: 'membership_id',
        width: 230
      },
      {
        title: 'user_id',
        dataIndex: 'user_id',
        key: 'user_id',
        width: 220
      },
      {
        title: 'phone',
        dataIndex: 'phone',
        key: 'phone',
        width: 160
      },
      {
        title: 'status',
        dataIndex: 'status',
        key: 'status',
        width: 120
      },
      {
        title: 'display_name',
        dataIndex: 'display_name',
        key: 'display_name',
        width: 160,
        render: (value) => value || '-'
      },
      {
        title: 'department_name',
        dataIndex: 'department_name',
        key: 'department_name',
        width: 180,
        render: (value) => value || '-'
      },
      {
        title: '操作',
        key: 'actions',
        render: (_value, record) => (
          <Space>
            <Button
              data-testid={`tenant-member-detail-${record.membership_id}`}
              size="small"
              type="link"
              onClick={() => {
                void openMemberDetail(record.membership_id);
              }}
            >
              详情
            </Button>
            <Button
              data-testid={`tenant-member-status-${record.membership_id}`}
              size="small"
              type="link"
              onClick={() => openMemberStatusModal(record)}
            >
              {statusToggleLabel(record.status)}
            </Button>
            <Button
              data-testid={`tenant-member-profile-${record.membership_id}`}
              size="small"
              type="link"
              onClick={() => openMemberProfileModal(record)}
            >
              资料
            </Button>
            <Button
              data-testid={`tenant-member-roles-${record.membership_id}`}
              size="small"
              type="link"
              onClick={() => {
                void openMemberAssignModal(record);
              }}
            >
              分配角色
            </Button>
          </Space>
        )
      }
    ],
    [
      openMemberAssignModal,
      openMemberDetail,
      openMemberProfileModal,
      openMemberStatusModal
    ]
  );

  const filteredRoleList = useMemo(() => {
    const keyword = String(roleFilters.keyword || '').trim().toLowerCase();
    const statusFilter = String(roleFilters.status || '').trim().toLowerCase();
    return roleList.filter((role) => {
      const roleStatus = String(role.status || '').trim().toLowerCase();
      if (statusFilter && roleStatus !== statusFilter) {
        return false;
      }
      if (!keyword) {
        return true;
      }
      return (
        String(role.role_id || '').toLowerCase().includes(keyword)
        || String(role.code || '').toLowerCase().includes(keyword)
        || String(role.name || '').toLowerCase().includes(keyword)
      );
    });
  }, [roleFilters, roleList]);

  const loadRolePermissions = useCallback(
    async (roleId) => {
      const normalizedRoleId = String(roleId || '').trim().toLowerCase();
      if (!normalizedRoleId) {
        return;
      }
      setPermissionLoading(true);
      try {
        const payload = await api.getRolePermissions(normalizedRoleId);
        setPermissionCodesAvailable(payload.available_permission_codes || []);
        setPermissionCodesChecked(payload.permission_codes || []);
      } catch (error) {
        setPermissionCodesAvailable([]);
        setPermissionCodesChecked([]);
        notifyError(error, '加载角色权限树失败');
      } finally {
        setPermissionLoading(false);
      }
    },
    [api, notifyError]
  );

  const openRoleDetail = useCallback(
    async (roleRecord) => {
      setRoleDetail(roleRecord);
      setRoleDetailOpen(true);
      await loadRolePermissions(roleRecord.role_id);
    },
    [loadRolePermissions]
  );

  const openCreateRoleModal = useCallback(() => {
    setRoleEditMode('create');
    setRoleEditTarget(null);
    setRoleEditOpen(true);
    roleEditForm.setFieldsValue({
      role_id: '',
      code: '',
      name: '',
      status: 'active'
    });
  }, [roleEditForm]);

  const openEditRoleModal = useCallback(
    (roleRecord) => {
      setRoleEditMode('edit');
      setRoleEditTarget(roleRecord);
      setRoleEditOpen(true);
      roleEditForm.setFieldsValue({
        role_id: roleRecord.role_id,
        code: roleRecord.code,
        name: roleRecord.name,
        status: roleRecord.status
      });
    },
    [roleEditForm]
  );

  const handleSubmitRoleEdit = useCallback(async () => {
    try {
      const values = await roleEditForm.validateFields();
      setRoleEditSubmitting(true);
      if (roleEditMode === 'create') {
        const payload = await api.createRole({
          role_id: values.role_id,
          code: values.code,
          name: values.name,
          status: values.status
        });
        notifySuccess(`组织角色创建成功（request_id: ${payload.request_id}）`);
      } else {
        const payload = await api.updateRole({
          roleId: roleEditTarget?.role_id,
          payload: {
            code: values.code,
            name: values.name,
            status: values.status
          }
        });
        notifySuccess(`组织角色更新成功（request_id: ${payload.request_id}）`);
      }
      setRoleEditOpen(false);
      setRoleEditTarget(null);
      roleEditForm.resetFields();
      await loadRoles();
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, roleEditMode === 'create' ? '创建组织角色失败' : '更新组织角色失败');
    } finally {
      setRoleEditSubmitting(false);
    }
  }, [
    api,
    loadRoles,
    notifyError,
    notifySuccess,
    roleEditForm,
    roleEditMode,
    roleEditTarget
  ]);

  const handleDeleteRole = useCallback(
    async (roleId) => {
      try {
        const payload = await api.deleteRole(roleId);
        notifySuccess(`组织角色删除成功（request_id: ${payload.request_id}）`);
        await loadRoles();
      } catch (error) {
        notifyError(error, '删除组织角色失败');
      }
    },
    [api, loadRoles, notifyError, notifySuccess]
  );

  const permissionLeafSet = useMemo(
    () => new Set(permissionCodesAvailable.map((code) => String(code || '').trim())),
    [permissionCodesAvailable]
  );

  const handleSaveRolePermissions = useCallback(async () => {
    if (!roleDetail?.role_id) {
      return;
    }
    const nextPermissionCodes = permissionCodesChecked.filter((permissionCode) =>
      permissionLeafSet.has(String(permissionCode || '').trim())
    );
    setPermissionSaving(true);
    try {
      const payload = await api.replaceRolePermissions({
        roleId: roleDetail.role_id,
        permissionCodes: nextPermissionCodes
      });
      setPermissionCodesAvailable(payload.available_permission_codes || []);
      setPermissionCodesChecked(payload.permission_codes || []);
      notifySuccess(`权限树保存成功（request_id: ${payload.request_id}）`);
    } catch (error) {
      notifyError(error, '保存权限树失败');
    } finally {
      setPermissionSaving(false);
    }
  }, [
    api,
    notifyError,
    notifySuccess,
    permissionCodesChecked,
    permissionLeafSet,
    roleDetail
  ]);

  const roleColumns = useMemo(
    () => [
      {
        title: 'role_id',
        dataIndex: 'role_id',
        key: 'role_id',
        width: 220
      },
      {
        title: 'code',
        dataIndex: 'code',
        key: 'code',
        width: 220
      },
      {
        title: 'name',
        dataIndex: 'name',
        key: 'name',
        width: 220
      },
      {
        title: 'status',
        dataIndex: 'status',
        key: 'status',
        width: 120
      },
      {
        title: 'is_system',
        dataIndex: 'is_system',
        key: 'is_system',
        width: 120,
        render: (value) => (value ? 'true' : 'false')
      },
      {
        title: '操作',
        key: 'actions',
        render: (_value, record) => (
          <Space>
            <Button
              data-testid={`tenant-role-detail-${record.role_id}`}
              size="small"
              type="link"
              onClick={() => {
                void openRoleDetail(record);
              }}
            >
              详情
            </Button>
            <Button
              data-testid={`tenant-role-edit-${record.role_id}`}
              size="small"
              type="link"
              onClick={() => openEditRoleModal(record)}
            >
              编辑
            </Button>
            <Popconfirm
              title="确认删除该组织角色吗？"
              onConfirm={() => {
                void handleDeleteRole(record.role_id);
              }}
            >
              <Button
                data-testid={`tenant-role-delete-${record.role_id}`}
                size="small"
                type="link"
                danger
              >
                删除
              </Button>
            </Popconfirm>
          </Space>
        )
      }
    ],
    [handleDeleteRole, openEditRoleModal, openRoleDetail]
  );

  if (!accessToken) {
    return (
      <section data-testid="tenant-governance-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载组织治理工作台。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="tenant-governance-workbench" style={{ display: 'grid', gap: 12 }}>
      {messageContextHolder}

      <Space>
        <Button
          data-testid="tenant-tab-members"
          type={activeModule === 'members' ? 'primary' : 'default'}
          onClick={() => setActiveModule('members')}
        >
          组织成员管理
        </Button>
        <Button
          data-testid="tenant-tab-roles"
          type={activeModule === 'roles' ? 'primary' : 'default'}
          onClick={() => setActiveModule('roles')}
        >
          组织角色管理
        </Button>
      </Space>

      {activeModule === 'members' ? (
        <section data-testid="tenant-members-module" style={{ display: 'grid', gap: 12 }}>
          <CustomFilter
            form={memberFilterForm}
            defaultCollapsed={false}
            collapsible={false}
            onFinish={(values) => {
              setMemberFilters({
                keyword: String(values.keyword || '').trim(),
                status: String(values.status || '').trim()
              });
              refreshMemberTable();
            }}
            onReset={() => {
              setMemberFilters({ keyword: '', status: '' });
              refreshMemberTable();
            }}
          >
            <Form.Item label="keyword" name="keyword">
              <Input data-testid="tenant-member-filter-keyword" placeholder="membership_id / user_id / phone" allowClear />
            </Form.Item>
            <Form.Item label="status" name="status">
              <Select
                data-testid="tenant-member-filter-status"
                options={MEMBER_STATUS_OPTIONS}
              />
            </Form.Item>
          </CustomFilter>

          <CustomCardTable
            title="组织成员列表"
            rowKey="membership_id"
            columns={memberColumns}
            request={memberTableRequest}
            extra={(
              <Button
                data-testid="tenant-member-create-open"
                type="primary"
                onClick={() => {
                  memberCreateForm.resetFields();
                  setMemberCreateOpen(true);
                }}
              >
                新增成员
              </Button>
            )}
          />

          <Modal
            open={memberCreateOpen}
            title="新增组织成员"
            onCancel={() => {
              setMemberCreateOpen(false);
            }}
            onOk={() => {
              void handleCreateMember();
            }}
            confirmLoading={memberCreateSubmitting}
            okButtonProps={{
              disabled: memberCreateSubmitting,
              'data-testid': 'tenant-member-create-confirm'
            }}
            cancelButtonProps={{
              disabled: memberCreateSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={memberCreateForm}
              layout="vertical"
              submitter={false}
            >
              <CustomForm.Item
                label="手机号"
                name="phone"
                rules={[
                  {
                    required: true,
                    message: '请输入 11 位手机号'
                  },
                  {
                    pattern: /^1\d{10}$/,
                    message: '请输入正确的 11 位手机号'
                  }
                ]}
              >
                <Input data-testid="tenant-member-create-phone" maxLength={11} />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Modal
            open={memberStatusOpen}
            title={`${statusToggleLabel(memberStatusTarget?.status)}组织成员`}
            onCancel={() => {
              setMemberStatusOpen(false);
              setMemberStatusTarget(null);
            }}
            onOk={() => {
              void handleSubmitMemberStatus();
            }}
            confirmLoading={memberStatusSubmitting}
            okButtonProps={{
              disabled: memberStatusSubmitting,
              'data-testid': 'tenant-member-status-confirm'
            }}
            cancelButtonProps={{
              disabled: memberStatusSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={memberStatusForm}
              layout="vertical"
              submitter={false}
            >
              <CustomForm.Item
                label="status"
                name="status"
                rules={[{ required: true, message: '请选择 status' }]}
              >
                <Select
                  data-testid="tenant-member-status-value"
                  options={[
                    { label: 'active', value: 'active' },
                    { label: 'disabled', value: 'disabled' },
                    { label: 'left', value: 'left' }
                  ]}
                />
              </CustomForm.Item>
              <CustomForm.Item
                label="reason（可选）"
                name="reason"
                rules={[
                  {
                    max: 256,
                    message: 'reason 长度不能超过 256'
                  }
                ]}
              >
                <Input.TextArea
                  data-testid="tenant-member-status-reason"
                  rows={3}
                  placeholder="manual-governance"
                />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Modal
            open={memberProfileOpen}
            title="维护成员资料"
            onCancel={() => {
              setMemberProfileOpen(false);
              setMemberProfileTarget(null);
            }}
            onOk={() => {
              void handleSubmitMemberProfile();
            }}
            confirmLoading={memberProfileSubmitting}
            okButtonProps={{
              disabled: memberProfileSubmitting,
              'data-testid': 'tenant-member-profile-confirm'
            }}
            cancelButtonProps={{
              disabled: memberProfileSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={memberProfileForm}
              layout="vertical"
              submitter={false}
            >
              <CustomForm.Item
                label="display_name"
                name="display_name"
                rules={[
                  { required: true, message: '请输入 display_name' },
                  { max: 64, message: 'display_name 长度不能超过 64' }
                ]}
              >
                <Input data-testid="tenant-member-profile-display-name" />
              </CustomForm.Item>
              <CustomForm.Item
                label="department_name"
                name="department_name"
                rules={[
                  { max: 128, message: 'department_name 长度不能超过 128' }
                ]}
              >
                <Input data-testid="tenant-member-profile-department-name" />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Modal
            open={memberAssignOpen}
            title="分配组织角色（1-5）"
            onCancel={() => {
              setMemberAssignOpen(false);
              setMemberAssignTarget(null);
            }}
            onOk={() => {
              void handleSubmitMemberRoles();
            }}
            confirmLoading={memberAssignSubmitting}
            okButtonProps={{
              disabled: memberAssignSubmitting,
              'data-testid': 'tenant-member-roles-confirm'
            }}
            cancelButtonProps={{
              disabled: memberAssignSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={memberAssignForm}
              layout="vertical"
              submitter={false}
            >
              <CustomForm.Item
                label="membership_id"
                name="membership_id"
              >
                <Input data-testid="tenant-member-roles-membership-id" disabled />
              </CustomForm.Item>
              <CustomForm.Item
                label="role_ids（逗号分隔）"
                name="role_ids_text"
                rules={[
                  { required: true, message: '请输入至少 1 个 role_id' },
                  {
                    validator: (_rule, value) => {
                      const normalizedRoleIds = normalizeRoleIds(
                        String(value || '')
                          .split(',')
                          .map((item) => String(item || '').trim())
                      );
                      if (normalizedRoleIds.length < 1 || normalizedRoleIds.length > 5) {
                        return Promise.reject(new Error('角色分配数量必须在 1 到 5 之间'));
                      }
                      return Promise.resolve();
                    }
                  }
                ]}
              >
                <Input
                  data-testid="tenant-member-roles-input"
                  placeholder="tenant_member_admin,tenant_billing_admin"
                />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Drawer
            open={memberDetailOpen}
            title="组织成员详情"
            size="default"
            onClose={() => {
              setMemberDetailOpen(false);
            }}
            destroyOnClose
          >
            <div data-testid="tenant-member-detail-drawer" style={{ display: 'grid', gap: 8 }}>
              {memberDetailLoading ? (
                <Text>加载中...</Text>
              ) : memberDetail ? (
                <>
                  <Text>membership_id: {memberDetail.membership_id}</Text>
                  <Text>user_id: {memberDetail.user_id}</Text>
                  <Text>status: {memberDetail.status}</Text>
                  <Text>display_name: {memberDetail.display_name || '-'}</Text>
                  <Text>department_name: {memberDetail.department_name || '-'}</Text>
                  <Text>request_id: {memberDetail.request_id}</Text>
                  <Text>role_ids: {(memberDetail.role_ids || []).join(',') || '-'}</Text>
                  {memberDetail.latest_action ? (
                    <Text>
                      latest_action: {memberDetail.latest_action.action} ({memberDetail.latest_action.result}) /
                      request_id={memberDetail.latest_action.request_id}
                    </Text>
                  ) : (
                    <Text type="secondary">latest_action: none</Text>
                  )}
                </>
              ) : (
                <Text type="secondary">暂无详情数据</Text>
              )}
            </div>
          </Drawer>
        </section>
      ) : null}

      {activeModule === 'roles' ? (
        <section data-testid="tenant-roles-module" style={{ display: 'grid', gap: 12 }}>
          <CustomFilter
            form={roleFilterForm}
            defaultCollapsed={false}
            collapsible={false}
            onFinish={(values) => {
              setRoleFilters({
                keyword: String(values.keyword || '').trim(),
                status: String(values.status || '').trim()
              });
            }}
            onReset={() => {
              setRoleFilters({ keyword: '', status: '' });
            }}
          >
            <Form.Item label="keyword" name="keyword">
              <Input data-testid="tenant-role-filter-keyword" placeholder="role_id / code / name" allowClear />
            </Form.Item>
            <Form.Item label="status" name="status">
              <Select
                data-testid="tenant-role-filter-status"
                options={ROLE_STATUS_OPTIONS}
              />
            </Form.Item>
          </CustomFilter>

          <CustomCardTable
            title="组织角色列表"
            rowKey="role_id"
            columns={roleColumns}
            dataSource={filteredRoleList}
            loading={roleListLoading}
            pagination={{
              pageSize: 10,
              showSizeChanger: true
            }}
            extra={(
              <Button
                data-testid="tenant-role-create-open"
                type="primary"
                onClick={openCreateRoleModal}
              >
                新建组织角色
              </Button>
            )}
          />

          <Modal
            open={roleEditOpen}
            title={roleEditMode === 'create' ? '新建组织角色' : '编辑组织角色'}
            onCancel={() => {
              setRoleEditOpen(false);
              setRoleEditTarget(null);
            }}
            onOk={() => {
              void handleSubmitRoleEdit();
            }}
            confirmLoading={roleEditSubmitting}
            okButtonProps={{
              disabled: roleEditSubmitting,
              'data-testid': roleEditMode === 'create' ? 'tenant-role-create-confirm' : 'tenant-role-edit-confirm'
            }}
            cancelButtonProps={{
              disabled: roleEditSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={roleEditForm}
              layout="vertical"
              submitter={false}
            >
              <CustomForm.Item
                label="role_id"
                name="role_id"
                rules={[
                  {
                    required: true,
                    message: '请输入 role_id'
                  }
                ]}
              >
                <Input
                  data-testid="tenant-role-edit-role-id"
                  disabled={roleEditMode !== 'create'}
                  placeholder="tenant_member_admin"
                />
              </CustomForm.Item>
              <CustomForm.Item
                label="code"
                name="code"
                rules={[
                  {
                    required: true,
                    message: '请输入 code'
                  }
                ]}
              >
                <Input data-testid="tenant-role-edit-code" />
              </CustomForm.Item>
              <CustomForm.Item
                label="name"
                name="name"
                rules={[
                  {
                    required: true,
                    message: '请输入 name'
                  }
                ]}
              >
                <Input data-testid="tenant-role-edit-name" />
              </CustomForm.Item>
              <CustomForm.Item
                label="status"
                name="status"
                rules={[
                  {
                    required: true,
                    message: '请选择 status'
                  }
                ]}
              >
                <Select
                  data-testid="tenant-role-edit-status"
                  options={[
                    { label: 'active', value: 'active' },
                    { label: 'disabled', value: 'disabled' }
                  ]}
                />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Drawer
            open={roleDetailOpen}
            title="组织角色详情"
            size="default"
            onClose={() => {
              setRoleDetailOpen(false);
            }}
            destroyOnClose
          >
            <div data-testid="tenant-role-detail-drawer" style={{ display: 'grid', gap: 8 }}>
              {roleDetail?.role_id ? (
                <>
                  <Text>role_id: {roleDetail.role_id}</Text>
                  <Text>code: {roleDetail.code}</Text>
                  <Text>name: {roleDetail.name}</Text>
                  <Text>status: {roleDetail.status}</Text>
                  <Text>is_system: {String(Boolean(roleDetail.is_system))}</Text>
                </>
              ) : (
                <Text type="secondary">暂无角色详情</Text>
              )}

              <div style={{ marginTop: 12 }}>
                <Text strong>权限树（仅 tenant.* 最终授权）</Text>
                <Tree
                  data-testid="tenant-role-permission-tree"
                  style={{ marginTop: 8 }}
                  checkable
                  treeData={toPermissionTreeData(permissionCodesAvailable)}
                  checkedKeys={permissionCodesChecked}
                  onCheck={(checked) => {
                    const checkedKeys = Array.isArray(checked)
                      ? checked
                      : checked.checked;
                    setPermissionCodesChecked(
                      checkedKeys
                        .map((key) => String(key || '').trim())
                        .filter((key) => permissionLeafSet.has(key))
                    );
                  }}
                />
                {permissionLoading ? (
                  <Text type="secondary">权限树加载中...</Text>
                ) : null}
              </div>

              <div>
                <Button
                  data-testid="tenant-role-permission-save"
                  type="primary"
                  loading={permissionSaving}
                  onClick={() => {
                    void handleSaveRolePermissions();
                  }}
                >
                  保存权限树
                </Button>
              </div>
            </div>
          </Drawer>
        </section>
      ) : null}
    </section>
  );
}
