import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  DatePicker,
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
  createPlatformSettingsApi,
  toProblemMessage
} from '../../api/platform-settings.mjs';

const { Text } = Typography;

const EMPTY_PERMISSION_CONTEXT = Object.freeze({
  scope_label: '平台权限（待同步）',
  can_view_member_admin: false,
  can_operate_member_admin: false,
  can_view_billing: false,
  can_operate_billing: false
});

const ROLE_STATUS_SELECT_OPTIONS = [
  { label: '全部', value: '' },
  { label: '启用', value: 'active' },
  { label: '禁用', value: 'disabled' }
];
const ROLE_FILTER_INITIAL_VALUES = Object.freeze({
  code: '',
  name: '',
  status: '',
  created_time: []
});

const SETTINGS_TREE_ROOT_KEY = 'settings';
const SETTINGS_TREE_MENU_ORDER = Object.freeze([
  'settings/users',
  'settings/roles',
  'settings/orgs'
]);
const PLATFORM_PERMISSION_MENU_MAP = Object.freeze({
  member_admin: Object.freeze({
    key: 'settings/users',
    title: '用户管理'
  }),
  system_config: Object.freeze({
    key: 'settings/roles',
    title: '角色管理'
  }),
  billing: Object.freeze({
    key: 'settings/orgs',
    title: '组织管理'
  })
});

const toPermissionActionTitle = (permissionCode) => {
  const sections = String(permissionCode || '').trim().split('.');
  const action = String(sections.slice(2).join('.') || '').trim().toLowerCase();
  if (action === 'view') {
    return '查看';
  }
  if (action === 'operate') {
    return '操作';
  }
  return action || String(permissionCode || '').trim();
};

const toPermissionTreeData = (availablePermissionCodes = []) => {
  const menuNodes = new Map(
    SETTINGS_TREE_MENU_ORDER.map((menuKey) => [
      menuKey,
      {
        key: menuKey,
        title:
          menuKey === 'settings/users'
            ? '用户管理'
            : menuKey === 'settings/roles'
              ? '角色管理'
              : '组织管理',
        selectable: false,
        children: []
      }
    ])
  );

  for (const permissionCode of availablePermissionCodes) {
    const normalizedCode = String(permissionCode || '').trim();
    if (!normalizedCode.startsWith('platform.')) {
      continue;
    }
    const sections = normalizedCode.split('.');
    const moduleName = String(sections[1] || '').trim().toLowerCase();
    const mappedMenu = PLATFORM_PERMISSION_MENU_MAP[moduleName];
    const menuKey = mappedMenu?.key || `settings/${moduleName || 'misc'}`;
    const menuTitle = mappedMenu?.title || (moduleName || '其他');
    const menuNode = menuNodes.get(menuKey) || {
      key: menuKey,
      title: menuTitle,
      selectable: false,
      children: []
    };
    menuNode.children.push({
      key: normalizedCode,
      title: toPermissionActionTitle(normalizedCode)
    });
    menuNodes.set(menuKey, menuNode);
  }

  const orderedNodes = [...menuNodes.values()]
    .map((node) => ({
      ...node,
      children: [...node.children].sort((left, right) => String(left.key).localeCompare(String(right.key)))
    }))
    .sort((left, right) => {
      const leftIndex = SETTINGS_TREE_MENU_ORDER.indexOf(String(left.key));
      const rightIndex = SETTINGS_TREE_MENU_ORDER.indexOf(String(right.key));
      const normalizedLeftIndex = leftIndex === -1 ? Number.POSITIVE_INFINITY : leftIndex;
      const normalizedRightIndex = rightIndex === -1 ? Number.POSITIVE_INFINITY : rightIndex;
      if (normalizedLeftIndex !== normalizedRightIndex) {
        return normalizedLeftIndex - normalizedRightIndex;
      }
      return String(left.key).localeCompare(String(right.key));
    });

  return [
    {
      key: SETTINGS_TREE_ROOT_KEY,
      title: '设置',
      selectable: false,
      children: orderedNodes
    }
  ];
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
const isDisabledStatus = (status) => String(status || '').trim().toLowerCase() === 'disabled';
const statusDisplayLabel = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'active') {
    return '启用';
  }
  if (normalizedStatus === 'disabled') {
    return '禁用';
  }
  return '-';
};
const normalizeDateTimeValue = (value) => {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '-';
  }
  const date = new Date(normalized);
  if (Number.isNaN(date.getTime())) {
    return normalized;
  }
  const year = String(date.getFullYear());
  const month = String(date.getMonth() + 1).padStart(2, '0');
  const day = String(date.getDate()).padStart(2, '0');
  const hours = String(date.getHours()).padStart(2, '0');
  const minutes = String(date.getMinutes()).padStart(2, '0');
  return `${year}-${month}-${day} ${hours}:${minutes}`;
};
const isSysAdminRole = (roleId) =>
  String(roleId || '').trim().toLowerCase() === 'sys_admin';

export default function PlatformRoleManagementPage({ accessToken }) {
  const api = useMemo(
    () => createPlatformSettingsApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [roleFilterForm] = Form.useForm();
  const [roleEditForm] = Form.useForm();
  const [assignRoleForm] = Form.useForm();

  const [roleFilters, setRoleFilters] = useState({
    code: '',
    name: '',
    status: '',
    created_at_start: '',
    created_at_end: ''
  });
  const [roleList, setRoleList] = useState([]);
  const [roleListLoading, setRoleListLoading] = useState(false);
  const [roleEditModalOpen, setRoleEditModalOpen] = useState(false);
  const [roleEditSubmitting, setRoleEditSubmitting] = useState(false);
  const [roleEditMode, setRoleEditMode] = useState('create');
  const [roleEditTarget, setRoleEditTarget] = useState(null);
  const [createRolePermissionCodesAvailable, setCreateRolePermissionCodesAvailable] = useState([]);
  const [createRolePermissionCodesChecked, setCreateRolePermissionCodesChecked] = useState([]);
  const [createRolePermissionLoading, setCreateRolePermissionLoading] = useState(false);

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

  const roleDetailWithPermission = useMemo(
    () => ({
      ...(roleDetail || {}),
      permission_codes: permissionCodesChecked,
      available_permission_codes: permissionCodesAvailable
    }),
    [permissionCodesAvailable, permissionCodesChecked, roleDetail]
  );

  const filteredRoleList = useMemo(() => {
    const codeFilter = String(roleFilters.code || '').trim().toLowerCase();
    const nameFilter = String(roleFilters.name || '').trim();
    const statusFilter = String(roleFilters.status || '').trim().toLowerCase();
    const createdAtStart = String(roleFilters.created_at_start || '').trim();
    const createdAtEnd = String(roleFilters.created_at_end || '').trim();
    const createdAtStartEpoch = createdAtStart
      ? new Date(createdAtStart).getTime()
      : Number.NaN;
    const createdAtEndEpoch = createdAtEnd
      ? new Date(createdAtEnd).getTime()
      : Number.NaN;
    return roleList.filter((role) => {
      const roleCode = String(role.code || '').trim().toLowerCase();
      const roleName = String(role.name || '').trim();
      const roleStatus = String(role.status || '').trim().toLowerCase();
      const roleCreatedAtEpoch = new Date(String(role.created_at || '').trim()).getTime();
      if (codeFilter && roleCode !== codeFilter) {
        return false;
      }
      if (nameFilter && roleName !== nameFilter) {
        return false;
      }
      if (statusFilter && roleStatus !== statusFilter) {
        return false;
      }
      if (Number.isFinite(createdAtStartEpoch)) {
        if (!Number.isFinite(roleCreatedAtEpoch) || roleCreatedAtEpoch < createdAtStartEpoch) {
          return false;
        }
      }
      if (Number.isFinite(createdAtEndEpoch)) {
        if (!Number.isFinite(roleCreatedAtEpoch) || roleCreatedAtEpoch > createdAtEndEpoch) {
          return false;
        }
      }
      return true;
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

  const loadCreateRolePermissionCatalog = useCallback(async () => {
    setCreateRolePermissionLoading(true);
    try {
      const payload = await api.getRolePermissions('sys_admin');
      setCreateRolePermissionCodesAvailable(
        Array.isArray(payload?.available_permission_codes)
          ? payload.available_permission_codes
          : []
      );
    } catch (error) {
      setCreateRolePermissionCodesAvailable([]);
      withErrorNotice(error, '加载角色权限目录失败');
    } finally {
      setCreateRolePermissionLoading(false);
    }
  }, [api, withErrorNotice]);

  const openCreateRoleModal = useCallback(() => {
    setRoleEditMode('create');
    setRoleEditTarget(null);
    setRoleEditModalOpen(true);
    setCreateRolePermissionCodesChecked([]);
    roleEditForm.setFieldsValue({
      code: '',
      name: ''
    });
    void loadCreateRolePermissionCatalog();
  }, [loadCreateRolePermissionCatalog, roleEditForm]);

  const openEditRoleModal = useCallback(
    (roleRecord) => {
      setRoleEditMode('edit');
      setRoleEditTarget(roleRecord);
      setRoleEditModalOpen(true);
      roleEditForm.setFieldsValue({
        code: roleRecord.code,
        name: roleRecord.name
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
          code: String(values.code || '').trim(),
          name: String(values.name || '').trim()
        });
        try {
          await api.replaceRolePermissions({
            roleId: payload.role_id,
            permissionCodes: [...new Set(
              (Array.isArray(createRolePermissionCodesChecked)
                ? createRolePermissionCodesChecked
                : [])
                .map((permissionCode) => String(permissionCode || '').trim())
                .filter((permissionCode) => permissionCode.startsWith('platform.'))
            )]
          });
        } catch (error) {
          notify({
            type: 'error',
            text: `平台角色已创建，但权限保存失败（role_id: ${payload.role_id}）：${toProblemMessage(error, '保存平台角色权限失败')}`
          });
          setRoleEditModalOpen(false);
          setRoleEditTarget(null);
          roleEditForm.resetFields();
          await loadRoles();
          return;
        }
        notify({
          type: 'success',
          text: `平台角色创建成功（request_id: ${payload.request_id}）`
        });
      } else {
        const payload = await api.updateRole({
          roleId: roleEditTarget?.role_id,
          payload: {
            code: String(values.code || '').trim(),
            name: String(values.name || '').trim()
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
  }, [
    api,
    createRolePermissionCodesChecked,
    loadRoles,
    notify,
    roleEditForm,
    roleEditMode,
    roleEditTarget,
    withErrorNotice
  ]);

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

  const handleToggleRoleStatus = useCallback(
    async (record) => {
      const normalizedRoleId = String(record?.role_id || '').trim();
      if (!normalizedRoleId) {
        return;
      }
      const targetStatus = statusToggleValue(record?.status);
      if (isSysAdminRole(normalizedRoleId) && targetStatus === 'disabled') {
        notify({
          type: 'error',
          text: 'sys_admin 角色不允许禁用'
        });
        return;
      }
      try {
        const payload = await api.updateRole({
          roleId: normalizedRoleId,
          payload: {
            status: targetStatus
          }
        });
        notify({
          type: 'success',
          text: `平台角色状态更新成功（request_id: ${payload.request_id}）`
        });
        await loadRoles();
      } catch (error) {
        withErrorNotice(error, '更新平台角色状态失败');
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
        title: '角色ID',
        dataIndex: 'role_id',
        key: 'role_id',
        width: 220,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '角色编码',
        dataIndex: 'code',
        key: 'code',
        width: 220,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '角色名称',
        dataIndex: 'name',
        key: 'name',
        width: 220,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        width: 120,
        render: (value) => statusDisplayLabel(value)
      },
      {
        title: '创建时间',
        dataIndex: 'created_at',
        key: 'created_at',
        width: 180,
        render: (value) => normalizeDateTimeValue(value)
      },
      {
        title: '操作',
        key: 'actions',
        render: (_value, record) => (
          <Space>
            <Button
              data-testid={`platform-role-edit-${record.role_id}`}
              size="small"
              type="link"
              disabled={Boolean(record.is_system) || isSysAdminRole(record.role_id)}
              onClick={(event) => {
                event.stopPropagation();
                openEditRoleModal(record);
              }}
            >
              编辑
            </Button>
            <Button
              data-testid={`platform-role-status-${record.role_id}`}
              size="small"
              type="link"
              disabled={Boolean(isSysAdminRole(record.role_id) && !isDisabledStatus(record.status))}
              onClick={(event) => {
                event.stopPropagation();
                void handleToggleRoleStatus(record);
              }}
            >
              {statusToggleLabel(record.status)}
            </Button>
            {isDisabledStatus(record.status) ? (
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
                  disabled={Boolean(record.is_system) || isSysAdminRole(record.role_id)}
                  onClick={(event) => {
                    event.stopPropagation();
                  }}
                >
                  删除
                </Button>
              </Popconfirm>
            ) : null}
          </Space>
        )
      }
    ],
    [handleDeleteRole, handleToggleRoleStatus, openEditRoleModal]
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
      <section data-testid="platform-roles-module" style={{ display: 'grid', gap: 12 }}>
        <CustomFilter
          form={roleFilterForm}
          initialValues={ROLE_FILTER_INITIAL_VALUES}
          onFinish={(values) => {
            const createdRange = Array.isArray(values.created_time)
              ? values.created_time
              : [];
            const [createdStart, createdEnd] = createdRange;
            setRoleFilters({
              code: String(values.code || '').trim(),
              name: String(values.name || '').trim(),
              status: String(values.status || '').trim(),
              created_at_start:
                createdStart && typeof createdStart.format === 'function'
                  ? createdStart.format('YYYY-MM-DD HH:mm:ss')
                  : '',
              created_at_end:
                createdEnd && typeof createdEnd.format === 'function'
                  ? createdEnd.format('YYYY-MM-DD HH:mm:ss')
                  : ''
            });
          }}
          onReset={() => {
            setRoleFilters({
              code: '',
              name: '',
              status: '',
              created_at_start: '',
              created_at_end: ''
            });
          }}
        >
          <Form.Item label="角色编码" name="code">
            <Input data-testid="platform-role-filter-code" placeholder="请输入角色编码（精确）" allowClear />
          </Form.Item>
          <Form.Item label="角色名称" name="name">
            <Input data-testid="platform-role-filter-name" placeholder="请输入角色名称（精确）" allowClear />
          </Form.Item>
          <Form.Item label="状态" name="status">
            <Select
              data-testid="platform-role-filter-status"
              options={ROLE_STATUS_SELECT_OPTIONS}
            />
          </Form.Item>
          <Form.Item label="创建时间" name="created_time">
            <DatePicker.RangePicker
              data-testid="platform-role-filter-created-time"
              showTime
              placeholder={['开始时间', '结束时间']}
              format="YYYY-MM-DD HH:mm:ss"
            />
          </Form.Item>
        </CustomFilter>

        <CustomCardTable
          title="平台角色列表"
          rowKey="role_id"
          columns={roleColumns}
          dataSource={filteredRoleList}
          loading={roleListLoading}
          onRow={(record) => ({
            onClick: () => {
              void openRoleDetail(record);
            },
            style: { cursor: 'pointer' }
          })}
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
            setCreateRolePermissionCodesChecked([]);
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
              label="角色编码"
              name="code"
              rules={[
                {
                  required: true,
                  message: '请输入角色编码'
                }
              ]}
            >
              <Input data-testid="platform-role-edit-code" placeholder="请输入角色编码" />
            </CustomForm.Item>
            <CustomForm.Item
              label="角色名称"
              name="name"
              rules={[
                {
                  required: true,
                  message: '请输入角色名称'
                }
              ]}
            >
              <Input data-testid="platform-role-edit-name" placeholder="请输入角色名称" />
            </CustomForm.Item>
            {roleEditMode === 'create' ? (
              <>
                <CustomForm.Item label="角色权限">
                  {createRolePermissionLoading ? (
                    <Spin size="small" />
                    ) : (
                      <Tree
                        data-testid="platform-role-create-permission-tree"
                        checkable
                        treeData={toPermissionTreeData(createRolePermissionCodesAvailable)}
                        checkedKeys={createRolePermissionCodesChecked}
                        onCheck={(checked) => {
                          const checkedKeys = Array.isArray(checked)
                            ? checked
                          : checked.checked;
                        setCreateRolePermissionCodesChecked(
                          checkedKeys
                            .map((key) => String(key || '').trim())
                            .filter((code) => code.startsWith('platform.'))
                        );
                      }}
                    />
                  )}
                </CustomForm.Item>
              </>
            ) : null}
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
                <Text>status: {statusDisplayLabel(roleDetailWithPermission.status)}</Text>
                <Text>created_at: {normalizeDateTimeValue(roleDetailWithPermission.created_at)}</Text>
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
    </section>
  );
}
