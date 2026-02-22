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
  Spin,
  Space,
  Tree,
  Typography,
  message
} from 'antd';
import CustomCardTable from '../../components/CustomCardTable';
import CustomFilter from '../../components/CustomFilter';
import CustomForm from '../../components/CustomForm';
import {
  createPlatformGovernanceApi,
  toProblemMessage
} from '../../api/platform-governance.mjs';

const { Text } = Typography;

const EMPTY_PERMISSION_CONTEXT = Object.freeze({
  scope_label: '平台权限（待同步）',
  can_view_member_admin: false,
  can_operate_member_admin: false,
  can_view_billing: false,
  can_operate_billing: false
});

const USER_STATUS_SELECT_OPTIONS = [
  { label: '全部状态', value: '' },
  { label: 'active', value: 'active' },
  { label: 'disabled', value: 'disabled' }
];

const ROLE_STATUS_SELECT_OPTIONS = [
  { label: '全部状态', value: '' },
  { label: 'active', value: 'active' },
  { label: 'disabled', value: 'disabled' }
];

const toPermissionTreeData = (availablePermissionCodes = []) => {
  const modules = new Map();
  for (const permissionCode of availablePermissionCodes) {
    const normalizedCode = String(permissionCode || '').trim();
    if (!normalizedCode.startsWith('platform.')) {
      continue;
    }
    const sections = normalizedCode.split('.');
    const moduleName = sections[1] || 'misc';
    const moduleKey = `platform.${moduleName}`;
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

const normalizeRoleIds = (rawRoleIds = []) => {
  const deduped = new Set();
  for (const roleId of Array.isArray(rawRoleIds) ? rawRoleIds : []) {
    const normalizedRoleId = String(roleId || '').trim().toLowerCase();
    if (normalizedRoleId) {
      deduped.add(normalizedRoleId);
    }
  }
  return [...deduped];
};

const statusToggleLabel = (status) => (status === 'active' ? '禁用' : '启用');
const statusToggleValue = (status) => (status === 'active' ? 'disabled' : 'active');

export default function PlatformGovernanceWorkbench({ accessToken }) {
  const api = useMemo(
    () => createPlatformGovernanceApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [activeModule, setActiveModule] = useState('users');
  const [feedback, setFeedback] = useState(null);

  const [userFilterForm] = Form.useForm();
  const [roleFilterForm] = Form.useForm();
  const [createUserForm] = Form.useForm();
  const [statusActionForm] = Form.useForm();
  const [roleEditForm] = Form.useForm();
  const [assignRoleForm] = Form.useForm();

  const [userFilters, setUserFilters] = useState({ keyword: '', status: '' });
  const [userTableRefreshToken, setUserTableRefreshToken] = useState(0);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [userModalSubmitting, setUserModalSubmitting] = useState(false);
  const [userStatusModalOpen, setUserStatusModalOpen] = useState(false);
  const [userStatusModalSubmitting, setUserStatusModalSubmitting] = useState(false);
  const [userStatusActionTarget, setUserStatusActionTarget] = useState(null);
  const [userDetailOpen, setUserDetailOpen] = useState(false);
  const [userDetailLoading, setUserDetailLoading] = useState(false);
  const [userDetail, setUserDetail] = useState(null);
  const [latestUserActionById, setLatestUserActionById] = useState({});

  const [roleFilters, setRoleFilters] = useState({ keyword: '', status: '' });
  const [roleList, setRoleList] = useState([]);
  const [roleListLoading, setRoleListLoading] = useState(false);
  const [roleEditModalOpen, setRoleEditModalOpen] = useState(false);
  const [roleEditSubmitting, setRoleEditSubmitting] = useState(false);
  const [roleEditMode, setRoleEditMode] = useState('create');
  const [roleEditTarget, setRoleEditTarget] = useState(null);

  const [roleDetailOpen, setRoleDetailOpen] = useState(false);
  const [roleDetail, setRoleDetail] = useState(null);
  const [permissionCodesAvailable, setPermissionCodesAvailable] = useState([]);
  const [permissionCodesChecked, setPermissionCodesChecked] = useState([]);
  const [permissionLoading, setPermissionLoading] = useState(false);
  const [permissionSaving, setPermissionSaving] = useState(false);

  const [assigningRoleFacts, setAssigningRoleFacts] = useState(false);
  const [platformPermissionContext, setPlatformPermissionContext] = useState(
    EMPTY_PERMISSION_CONTEXT
  );

  const notify = useCallback(
    ({ type = 'success', text = '' }) => {
      const normalizedText = String(text || '').trim();
      if (!normalizedText) {
        return;
      }
      setFeedback({
        type,
        text: normalizedText
      });
      if (type === 'error') {
        messageApi.error(normalizedText);
      } else {
        messageApi.success(normalizedText);
      }
    },
    [messageApi]
  );

  const withErrorNotice = useCallback(
    (error, fallback = '操作失败') => {
      notify({
        type: 'error',
        text: toProblemMessage(error, fallback)
      });
    },
    [notify]
  );

  const loadRoles = useCallback(async () => {
    setRoleListLoading(true);
    try {
      const payload = await api.listRoles();
      const roles = Array.isArray(payload?.roles) ? payload.roles : [];
      setRoleList(roles.map((role) => ({ ...role, key: role.role_id })));
    } catch (error) {
      withErrorNotice(error, '加载平台角色列表失败');
    } finally {
      setRoleListLoading(false);
    }
  }, [api, withErrorNotice]);

  useEffect(() => {
    if (!accessToken) {
      return;
    }
    void loadRoles();
  }, [accessToken, loadRoles]);

  const refreshUserTable = useCallback(() => {
    setUserTableRefreshToken((previous) => previous + 1);
  }, []);

  const openUserDetail = useCallback(
    async (userId, latestActionOverride = null) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return;
      }
      setUserDetailOpen(true);
      setUserDetailLoading(true);
      try {
        const payload = await api.getUser(normalizedUserId);
        const latestAction =
          latestActionOverride
          || latestUserActionById[normalizedUserId]
          || null;
        setUserDetail({
          ...payload,
          latest_action: latestAction
        });
      } catch (error) {
        setUserDetail(null);
        withErrorNotice(error, '加载平台用户详情失败');
      } finally {
        setUserDetailLoading(false);
      }
    },
    [api, latestUserActionById, withErrorNotice]
  );

  const openStatusActionModal = useCallback((record) => {
    setUserStatusActionTarget(record);
    setUserStatusModalOpen(true);
    statusActionForm.setFieldsValue({
      reason: ''
    });
  }, [statusActionForm]);

  const handleCreateUser = useCallback(async () => {
    try {
      const values = await createUserForm.validateFields();
      setUserModalSubmitting(true);
      const payload = await api.createUser({
        phone: values.phone
      });
      const latestAction = {
        action: 'create',
        request_id: payload.request_id,
        result: payload.created_user ? 'created' : 'reused'
      };
      setLatestUserActionById((previous) => ({
        ...previous,
        [payload.user_id]: latestAction
      }));
      notify({
        type: 'success',
        text: `平台用户创建成功（request_id: ${payload.request_id}）`
      });
      setUserModalOpen(false);
      createUserForm.resetFields();
      refreshUserTable();
      void openUserDetail(payload.user_id, latestAction);
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      withErrorNotice(error, '创建平台用户失败');
    } finally {
      setUserModalSubmitting(false);
    }
  }, [api, createUserForm, notify, openUserDetail, refreshUserTable, withErrorNotice]);

  const handleSubmitStatusAction = useCallback(async () => {
    if (!userStatusActionTarget) {
      return;
    }
    try {
      const values = await statusActionForm.validateFields();
      setUserStatusModalSubmitting(true);
      const payload = await api.updateUserStatus({
        user_id: userStatusActionTarget.user_id,
        status: statusToggleValue(userStatusActionTarget.status),
        reason: values.reason || null
      });
      const latestAction = {
        action: 'status',
        request_id: payload.request_id,
        result: `${payload.previous_status} -> ${payload.current_status}`
      };
      setLatestUserActionById((previous) => ({
        ...previous,
        [payload.user_id]: latestAction
      }));
      notify({
        type: 'success',
        text: `用户状态更新成功（request_id: ${payload.request_id}）`
      });
      setUserStatusModalOpen(false);
      setUserStatusActionTarget(null);
      statusActionForm.resetFields();
      refreshUserTable();
      void openUserDetail(payload.user_id, latestAction);
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      withErrorNotice(error, '更新用户状态失败');
    } finally {
      setUserStatusModalSubmitting(false);
    }
  }, [
    api,
    notify,
    openUserDetail,
    refreshUserTable,
    statusActionForm,
    userStatusActionTarget,
    withErrorNotice
  ]);

  const handleSoftDeleteUser = useCallback(
    async (userId) => {
      const normalizedUserId = String(userId || '').trim();
      if (!normalizedUserId) {
        return;
      }
      try {
        const payload = await api.softDeleteUser(normalizedUserId);
        setLatestUserActionById((previous) => ({
          ...previous,
          [payload.user_id]: {
            action: 'soft-delete',
            request_id: payload.request_id,
            result: `${payload.previous_status} -> ${payload.current_status}`
          }
        }));
        notify({
          type: 'success',
          text: `平台用户软删除成功（request_id: ${payload.request_id}）`
        });
        refreshUserTable();
      } catch (error) {
        withErrorNotice(error, '软删除平台用户失败');
      }
    },
    [api, notify, refreshUserTable, withErrorNotice]
  );

  const userTableRequest = useCallback(
    async (params) => {
      const payload = await api.listUsers({
        page: params.current,
        pageSize: params.pageSize,
        status: userFilters.status || null,
        keyword: userFilters.keyword || null
      });
      return {
        data: Array.isArray(payload.items) ? payload.items : [],
        total: Number(payload.total || 0),
        success: true
      };
    },
    [api, userFilters.keyword, userFilters.status, userTableRefreshToken]
  );

  const userColumns = useMemo(
    () => [
      {
        title: 'user_id',
        dataIndex: 'user_id',
        key: 'user_id',
        width: 280,
        render: (value) => <span data-testid={`platform-user-id-${value}`}>{value}</span>
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
        title: '操作',
        key: 'actions',
        render: (_value, record) => (
          <Space>
            <Button
              data-testid={`platform-user-detail-${record.user_id}`}
              size="small"
              type="link"
              onClick={() => {
                void openUserDetail(record.user_id);
              }}
            >
              详情
            </Button>
            <Button
              data-testid={`platform-user-status-${record.user_id}`}
              size="small"
              type="link"
              onClick={() => openStatusActionModal(record)}
            >
              {statusToggleLabel(record.status)}
            </Button>
            <Popconfirm
              title="确认软删除该平台用户吗？"
              onConfirm={() => {
                void handleSoftDeleteUser(record.user_id);
              }}
            >
              <Button
                data-testid={`platform-user-delete-${record.user_id}`}
                size="small"
                type="link"
                danger
              >
                软删除
              </Button>
            </Popconfirm>
          </Space>
        )
      }
    ],
    [handleSoftDeleteUser, openStatusActionModal, openUserDetail]
  );

  const roleDetailWithPermission = useMemo(
    () => ({
      ...(roleDetail || {}),
      permission_codes: permissionCodesChecked,
      available_permission_codes: permissionCodesAvailable
    }),
    [permissionCodesAvailable, permissionCodesChecked, roleDetail]
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
        withErrorNotice(error, '加载角色权限树失败');
      } finally {
        setPermissionLoading(false);
      }
    },
    [api, withErrorNotice]
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
    setRoleEditModalOpen(true);
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
      setRoleEditModalOpen(true);
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
          role_id: String(values.role_id || '').trim().toLowerCase(),
          code: String(values.code || '').trim(),
          name: String(values.name || '').trim(),
          status: String(values.status || 'active').trim().toLowerCase()
        });
        notify({
          type: 'success',
          text: `平台角色创建成功（request_id: ${payload.request_id}）`
        });
      } else {
        const payload = await api.updateRole({
          roleId: roleEditTarget?.role_id,
          payload: {
            code: String(values.code || '').trim(),
            name: String(values.name || '').trim(),
            status: String(values.status || 'active').trim().toLowerCase()
          }
        });
        notify({
          type: 'success',
          text: `平台角色更新成功（request_id: ${payload.request_id}）`
        });
      }
      setRoleEditModalOpen(false);
      setRoleEditTarget(null);
      roleEditForm.resetFields();
      await loadRoles();
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      withErrorNotice(error, roleEditMode === 'create' ? '创建平台角色失败' : '更新平台角色失败');
    } finally {
      setRoleEditSubmitting(false);
    }
  }, [api, loadRoles, notify, roleEditForm, roleEditMode, roleEditTarget, withErrorNotice]);

  const handleDeleteRole = useCallback(
    async (roleId) => {
      try {
        const payload = await api.deleteRole(roleId);
        notify({
          type: 'success',
          text: `平台角色删除成功（request_id: ${payload.request_id}）`
        });
        await loadRoles();
      } catch (error) {
        withErrorNotice(error, '删除平台角色失败');
      }
    },
    [api, loadRoles, notify, withErrorNotice]
  );

  const handleSaveRolePermissions = useCallback(async () => {
    if (!roleDetail?.role_id) {
      return;
    }
    const normalizedPermissionCodes = [...new Set(
      permissionCodesChecked
        .map((permissionCode) => String(permissionCode || '').trim())
        .filter((permissionCode) => permissionCode.startsWith('platform.'))
    )];

    setPermissionSaving(true);
    try {
      const payload = await api.replaceRolePermissions({
        roleId: roleDetail.role_id,
        permissionCodes: normalizedPermissionCodes
      });
      setPermissionCodesAvailable(payload.available_permission_codes || []);
      setPermissionCodesChecked(payload.permission_codes || []);
      notify({
        type: 'success',
        text: `权限树保存成功（request_id: ${payload.request_id}）`
      });
    } catch (error) {
      withErrorNotice(error, '保存权限树失败');
    } finally {
      setPermissionSaving(false);
    }
  }, [api, notify, permissionCodesChecked, roleDetail, withErrorNotice]);

  const handleReplaceRoleFacts = useCallback(async () => {
    try {
      const values = await assignRoleForm.validateFields();
      const normalizedRoleIds = normalizeRoleIds(
        String(values.role_ids_text || '')
          .split(',')
          .map((value) => String(value || '').trim())
      );
      if (normalizedRoleIds.length < 1 || normalizedRoleIds.length > 5) {
        notify({
          type: 'error',
          text: '角色分配必须为 1 到 5 个角色，请稍后重试'
        });
        return;
      }

      setAssigningRoleFacts(true);
      const payload = await api.replaceRoleFacts({
        userId: values.user_id,
        roleIds: normalizedRoleIds
      });
      const context = payload.platform_permission_context || EMPTY_PERMISSION_CONTEXT;
      setPlatformPermissionContext({
        ...EMPTY_PERMISSION_CONTEXT,
        ...context
      });
      notify({
        type: 'success',
        text: `角色分配已生效（request_id: ${payload.request_id}）`
      });
      assignRoleForm.setFieldsValue({
        role_ids_text: normalizedRoleIds.join(',')
      });
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      withErrorNotice(error, '平台角色分配失败');
    } finally {
      setAssigningRoleFacts(false);
    }
  }, [api, assignRoleForm, notify, withErrorNotice]);

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
              data-testid={`platform-role-detail-${record.role_id}`}
              size="small"
              type="link"
              onClick={() => {
                void openRoleDetail(record);
              }}
            >
              详情
            </Button>
            <Button
              data-testid={`platform-role-edit-${record.role_id}`}
              size="small"
              type="link"
              disabled={Boolean(record.is_system)}
              onClick={() => openEditRoleModal(record)}
            >
              编辑
            </Button>
            <Popconfirm
              title="确认删除该平台角色吗？"
              onConfirm={() => {
                void handleDeleteRole(record.role_id);
              }}
            >
              <Button
                data-testid={`platform-role-delete-${record.role_id}`}
                size="small"
                type="link"
                danger
                disabled={Boolean(record.is_system)}
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
      <section data-testid="platform-governance-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载平台治理工作台。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="platform-governance-workbench" style={{ display: 'grid', gap: 12 }}>
      {messageContextHolder}

      {feedback ? (
        <Alert
          data-testid="platform-governance-feedback"
          type={feedback.type === 'error' ? 'error' : 'success'}
          message={feedback.text}
          showIcon
        />
      ) : null}

      <Space>
        <Button
          data-testid="platform-tab-users"
          type={activeModule === 'users' ? 'primary' : 'default'}
          onClick={() => setActiveModule('users')}
        >
          平台用户管理
        </Button>
        <Button
          data-testid="platform-tab-roles"
          type={activeModule === 'roles' ? 'primary' : 'default'}
          onClick={() => setActiveModule('roles')}
        >
          平台角色管理
        </Button>
      </Space>

      {activeModule === 'users' ? (
        <section data-testid="platform-users-module" style={{ display: 'grid', gap: 12 }}>
          <CustomFilter
            form={userFilterForm}
            defaultCollapsed={false}
            collapsible={false}
            onFinish={(values) => {
              setUserFilters({
                keyword: String(values.keyword || '').trim(),
                status: String(values.status || '').trim()
              });
              refreshUserTable();
            }}
            onReset={() => {
              setUserFilters({ keyword: '', status: '' });
              refreshUserTable();
            }}
          >
            <Form.Item label="keyword" name="keyword">
              <Input data-testid="platform-user-filter-keyword" placeholder="user_id / phone" allowClear />
            </Form.Item>
            <Form.Item label="status" name="status">
              <Select
                data-testid="platform-user-filter-status"
                options={USER_STATUS_SELECT_OPTIONS}
              />
            </Form.Item>
          </CustomFilter>

          <CustomCardTable
            title="平台用户列表"
            rowKey="user_id"
            columns={userColumns}
            request={userTableRequest}
            extra={(
              <Button
                data-testid="platform-user-create-open"
                type="primary"
                onClick={() => {
                  createUserForm.resetFields();
                  setUserModalOpen(true);
                }}
              >
                新建平台用户
              </Button>
            )}
          />

          <Modal
            open={userModalOpen}
            title="新建平台用户"
            onCancel={() => {
              setUserModalOpen(false);
            }}
            onOk={() => {
              void handleCreateUser();
            }}
            confirmLoading={userModalSubmitting}
            okButtonProps={{
              disabled: userModalSubmitting,
              'data-testid': 'platform-user-create-confirm'
            }}
            cancelButtonProps={{
              disabled: userModalSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={createUserForm}
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
                <Input data-testid="platform-user-create-phone" maxLength={11} />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Modal
            open={userStatusModalOpen}
            title={`${statusToggleLabel(userStatusActionTarget?.status)}平台用户`}
            onCancel={() => {
              setUserStatusModalOpen(false);
              setUserStatusActionTarget(null);
            }}
            onOk={() => {
              void handleSubmitStatusAction();
            }}
            confirmLoading={userStatusModalSubmitting}
            okButtonProps={{
              disabled: userStatusModalSubmitting,
              'data-testid': 'platform-user-status-confirm'
            }}
            cancelButtonProps={{
              disabled: userStatusModalSubmitting
            }}
            destroyOnClose
          >
            <CustomForm
              form={statusActionForm}
              layout="vertical"
              submitter={false}
            >
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
                  data-testid="platform-user-status-reason"
                  rows={3}
                  placeholder="manual-governance"
                />
              </CustomForm.Item>
            </CustomForm>
          </Modal>

          <Drawer
            open={userDetailOpen}
            title="平台用户详情"
            size="default"
            onClose={() => {
              setUserDetailOpen(false);
            }}
            destroyOnClose
          >
            <div data-testid="platform-user-detail-drawer" style={{ display: 'grid', gap: 8 }}>
              {userDetailLoading ? (
                <Text>加载中...</Text>
              ) : userDetail ? (
                <>
                  <Text>user_id: {userDetail.user_id}</Text>
                  <Text>phone: {userDetail.phone}</Text>
                  <Text>status: {userDetail.status}</Text>
                  <Text>request_id: {userDetail.request_id}</Text>
                  {userDetail.latest_action ? (
                    <Text>
                      latest_action: {userDetail.latest_action.action} ({userDetail.latest_action.result}) /
                      request_id={userDetail.latest_action.request_id}
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
        <section data-testid="platform-roles-module" style={{ display: 'grid', gap: 12 }}>
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
              <Input data-testid="platform-role-filter-keyword" placeholder="role_id / code / name" allowClear />
            </Form.Item>
            <Form.Item label="status" name="status">
              <Select
                data-testid="platform-role-filter-status"
                options={ROLE_STATUS_SELECT_OPTIONS}
              />
            </Form.Item>
          </CustomFilter>

          <CustomCardTable
            title="平台角色列表"
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
                data-testid="platform-role-create-open"
                type="primary"
                onClick={openCreateRoleModal}
              >
                新建平台角色
              </Button>
            )}
          />

          <CustomForm
            form={assignRoleForm}
            title="平台角色分配（1-5）"
            layout="vertical"
            submitter={{
              align: 'left',
              searchConfig: {
                submitText: assigningRoleFacts ? '提交中...' : '保存角色分配',
                resetText: '重置'
              },
              submitButtonProps: {
                disabled: assigningRoleFacts,
                'data-testid': 'platform-role-facts-submit'
              },
              resetButtonProps: {
                disabled: assigningRoleFacts
              }
            }}
            onFinish={() => {
              void handleReplaceRoleFacts();
            }}
            onReset={() => {
              assignRoleForm.resetFields();
            }}
          >
            <CustomForm.Item
              label="目标 user_id"
              name="user_id"
              rules={[{ required: true, message: '请输入目标 user_id' }]}
            >
              <Input data-testid="platform-role-facts-user-id" placeholder="platform-user-id" />
            </CustomForm.Item>
            <CustomForm.Item
              label="角色列表（逗号分隔 role_id）"
              name="role_ids_text"
              rules={[{ required: true, message: '请输入至少一个 role_id' }]}
            >
              <Input
                data-testid="platform-role-facts-role-ids"
                placeholder="sys_admin,platform_member_admin"
              />
            </CustomForm.Item>
          </CustomForm>

          <div
            data-testid="platform-permission-context-panel"
            style={{
              border: '1px solid #e5e7eb',
              borderRadius: 8,
              padding: 12,
              display: 'grid',
              gap: 8
            }}
          >
            <Text>权限上下文：{platformPermissionContext.scope_label}</Text>
            <div>
              可见菜单：
              <Space size="small" style={{ marginInlineStart: 8 }}>
                {platformPermissionContext.can_view_member_admin ? (
                  <Text data-testid="platform-menu-member-admin">成员治理</Text>
                ) : null}
                {platformPermissionContext.can_view_billing ? (
                  <Text data-testid="platform-menu-billing">账单治理</Text>
                ) : null}
                {!platformPermissionContext.can_view_member_admin
                && !platformPermissionContext.can_view_billing ? (
                  <Text data-testid="platform-menu-empty" type="secondary">当前无可见菜单</Text>
                  ) : null}
              </Space>
            </div>
            <div>
              操作按钮：
              <Space size="small" style={{ marginInlineStart: 8 }}>
                {platformPermissionContext.can_operate_member_admin ? (
                  <Button
                    data-testid="platform-action-member-admin"
                    size="small"
                    type="default"
                  >
                    成员治理
                  </Button>
                ) : null}
                {platformPermissionContext.can_operate_billing ? (
                  <Button
                    data-testid="platform-action-billing"
                    size="small"
                    type="default"
                  >
                    账单治理
                  </Button>
                ) : null}
                {!platformPermissionContext.can_operate_member_admin
                && !platformPermissionContext.can_operate_billing ? (
                  <Text data-testid="platform-action-empty" type="secondary">当前无可操作按钮</Text>
                  ) : null}
              </Space>
            </div>
          </div>

          <Modal
            open={roleEditModalOpen}
            title={roleEditMode === 'create' ? '新建平台角色' : '编辑平台角色'}
            onCancel={() => {
              setRoleEditModalOpen(false);
              setRoleEditTarget(null);
            }}
            onOk={() => {
              void handleSubmitRoleEdit();
            }}
            confirmLoading={roleEditSubmitting}
            okButtonProps={{
              disabled: roleEditSubmitting,
              'data-testid': roleEditMode === 'create' ? 'platform-role-create-confirm' : 'platform-role-edit-confirm'
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
                  data-testid="platform-role-edit-role-id"
                  disabled={roleEditMode !== 'create'}
                  placeholder="platform_member_admin"
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
                <Input data-testid="platform-role-edit-code" />
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
                <Input data-testid="platform-role-edit-name" />
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
                  data-testid="platform-role-edit-status"
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
            title="平台角色详情"
            size="default"
            onClose={() => {
              setRoleDetailOpen(false);
            }}
            destroyOnClose
          >
            <div data-testid="platform-role-detail-drawer" style={{ display: 'grid', gap: 8 }}>
              {roleDetailWithPermission?.role_id ? (
                <>
                  <Text>role_id: {roleDetailWithPermission.role_id}</Text>
                  <Text>code: {roleDetailWithPermission.code}</Text>
                  <Text>name: {roleDetailWithPermission.name}</Text>
                  <Text>status: {roleDetailWithPermission.status}</Text>
                  <Text>is_system: {String(Boolean(roleDetailWithPermission.is_system))}</Text>
                </>
              ) : (
                <Text type="secondary">暂无角色详情</Text>
              )}

              <div style={{ marginTop: 12 }}>
                <Text strong>权限树（仅 platform.*）</Text>
                {permissionLoading ? (
                  <div style={{ marginTop: 8 }}>
                    <Spin size="small" />
                  </div>
                ) : (
                  <Tree
                    data-testid="platform-role-permission-tree"
                    style={{ marginTop: 8 }}
                    checkable
                    checkStrictly
                    treeData={toPermissionTreeData(permissionCodesAvailable)}
                    checkedKeys={permissionCodesChecked}
                    onCheck={(checked) => {
                      const checkedKeys = Array.isArray(checked)
                        ? checked
                        : checked.checked;
                      setPermissionCodesChecked(
                        checkedKeys
                          .map((key) => String(key || '').trim())
                          .filter((code) => code.startsWith('platform.'))
                      );
                    }}
                  />
                )}
              </div>

              <div>
                <Button
                  data-testid="platform-role-permission-save"
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
