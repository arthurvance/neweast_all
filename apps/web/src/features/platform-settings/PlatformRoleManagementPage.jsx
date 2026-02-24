import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Popconfirm,
  Select,
  Spin,
  Space,
  Tree,
  message
} from 'antd';
import CustomCardTable from '../../components/CustomCardTable';
import CustomFilter from '../../components/CustomFilter';
import CustomForm from '../../components/CustomForm';
import {
  createPlatformSettingsApi,
  toProblemMessage
} from '../../api/platform-settings.mjs';
import {
  formatDateTimeMinute,
  toDateTimeMinuteEpoch
} from '../../utils/date-time.mjs';

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
  const [roleEditPermissionCodesAvailable, setRoleEditPermissionCodesAvailable] = useState([]);
  const [roleEditPermissionCodesChecked, setRoleEditPermissionCodesChecked] = useState([]);
  const [roleEditPermissionLoading, setRoleEditPermissionLoading] = useState(false);

  const [roleDetailOpen, setRoleDetailOpen] = useState(false);
  const [roleDetail, setRoleDetail] = useState(null);
  const [permissionCodesAvailable, setPermissionCodesAvailable] = useState([]);
  const [permissionCodesChecked, setPermissionCodesChecked] = useState([]);
  const [permissionLoading, setPermissionLoading] = useState(false);

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
      const normalizedRoles = roles.map((role) => ({ ...role, key: role.role_id }));
      setRoleList(normalizedRoles);
      return normalizedRoles;
    } catch (error) {
      withErrorNotice(error, '加载平台角色列表失败');
      return [];
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
    const createdAtStartEpoch = toDateTimeMinuteEpoch(roleFilters.created_at_start);
    const createdAtEndEpoch = toDateTimeMinuteEpoch(roleFilters.created_at_end);
    return roleList.filter((role) => {
      const roleCode = String(role.code || '').trim().toLowerCase();
      const roleName = String(role.name || '').trim();
      const roleStatus = String(role.status || '').trim().toLowerCase();
      const roleCreatedAtEpoch = toDateTimeMinuteEpoch(role.created_at);
      if (codeFilter && roleCode !== codeFilter) {
        return false;
      }
      if (nameFilter && roleName !== nameFilter) {
        return false;
      }
      if (statusFilter && roleStatus !== statusFilter) {
        return false;
      }
      if (createdAtStartEpoch !== null) {
        if (roleCreatedAtEpoch === null || roleCreatedAtEpoch < createdAtStartEpoch) {
          return false;
        }
      }
      if (createdAtEndEpoch !== null) {
        if (roleCreatedAtEpoch === null || roleCreatedAtEpoch > createdAtEndEpoch) {
          return false;
        }
      }
      return true;
    });
  }, [roleFilters, roleList]);

  const validateRoleCodeRequired = useCallback((_rule, value) => {
    if (typeof value !== 'string' || value.trim()) {
      return Promise.resolve();
    }
    return Promise.reject(new Error('请输入角色编码'));
  }, []);

  const validateRoleNameRequired = useCallback((_rule, value) => {
    if (typeof value !== 'string' || value.trim()) {
      return Promise.resolve();
    }
    return Promise.reject(new Error('请输入角色名称'));
  }, []);

  const validateRoleCodeUnique = useCallback((_rule, value) => {
    const normalizedCode = String(value || '').trim().toLowerCase();
    if (!normalizedCode) {
      return Promise.resolve();
    }
    const editingRoleId = String(roleEditTarget?.role_id || '').trim().toLowerCase();
    const duplicated = roleList.some((role) => {
      const roleId = String(role.role_id || '').trim().toLowerCase();
      if (roleEditMode === 'edit' && roleId === editingRoleId) {
        return false;
      }
      return String(role.code || '').trim().toLowerCase() === normalizedCode;
    });
    if (!duplicated) {
      return Promise.resolve();
    }
    return Promise.reject(new Error('角色编码需在组织内唯一'));
  }, [roleEditMode, roleEditTarget, roleList]);

  const validateRoleNameUnique = useCallback((_rule, value) => {
    const normalizedName = String(value || '').trim().toLowerCase();
    if (!normalizedName) {
      return Promise.resolve();
    }
    const editingRoleId = String(roleEditTarget?.role_id || '').trim().toLowerCase();
    const duplicated = roleList.some((role) => {
      const roleId = String(role.role_id || '').trim().toLowerCase();
      if (roleEditMode === 'edit' && roleId === editingRoleId) {
        return false;
      }
      return String(role.name || '').trim().toLowerCase() === normalizedName;
    });
    if (!duplicated) {
      return Promise.resolve();
    }
    return Promise.reject(new Error('角色名称需在组织内唯一'));
  }, [roleEditMode, roleEditTarget, roleList]);

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
    setRoleEditPermissionLoading(true);
    try {
      const payload = await api.getRolePermissions('sys_admin');
      setRoleEditPermissionCodesAvailable(
        Array.isArray(payload?.available_permission_codes)
          ? payload.available_permission_codes
          : []
      );
      setRoleEditPermissionCodesChecked([]);
    } catch (error) {
      setRoleEditPermissionCodesAvailable([]);
      setRoleEditPermissionCodesChecked([]);
      withErrorNotice(error, '加载角色权限目录失败');
    } finally {
      setRoleEditPermissionLoading(false);
    }
  }, [api, withErrorNotice]);

  const loadEditRolePermissionCatalog = useCallback(
    async (roleId) => {
      const normalizedRoleId = String(roleId || '').trim().toLowerCase();
      if (!normalizedRoleId) {
        setRoleEditPermissionCodesAvailable([]);
        setRoleEditPermissionCodesChecked([]);
        return;
      }
      setRoleEditPermissionLoading(true);
      try {
        const payload = await api.getRolePermissions(normalizedRoleId);
        setRoleEditPermissionCodesAvailable(
          Array.isArray(payload?.available_permission_codes)
            ? payload.available_permission_codes
            : []
        );
        setRoleEditPermissionCodesChecked(
          (Array.isArray(payload?.permission_codes) ? payload.permission_codes : [])
            .map((permissionCode) => String(permissionCode || '').trim())
            .filter((permissionCode) => permissionCode.startsWith('platform.'))
        );
      } catch (error) {
        setRoleEditPermissionCodesAvailable([]);
        setRoleEditPermissionCodesChecked([]);
        withErrorNotice(error, '加载角色权限树失败');
      } finally {
        setRoleEditPermissionLoading(false);
      }
    },
    [api, withErrorNotice]
  );

  const openCreateRoleModal = useCallback(() => {
    setRoleEditMode('create');
    setRoleEditTarget(null);
    setRoleEditModalOpen(true);
    setRoleEditPermissionCodesChecked([]);
    roleEditForm.setFieldsValue({
      code: '',
      name: ''
    });
    void loadCreateRolePermissionCatalog();
  }, [loadCreateRolePermissionCatalog, roleEditForm]);

  const openEditRoleModal = useCallback(
    async (roleRecord) => {
      setRoleEditMode('edit');
      setRoleEditTarget(roleRecord);
      setRoleEditModalOpen(true);
      setRoleEditPermissionCodesChecked([]);
      roleEditForm.setFieldsValue({
        code: roleRecord.code,
        name: roleRecord.name
      });
      await loadEditRolePermissionCatalog(roleRecord.role_id);
    },
    [loadEditRolePermissionCatalog, roleEditForm]
  );

  const handleSubmitRoleEdit = useCallback(async () => {
    try {
      const values = await roleEditForm.validateFields();
      const normalizedPermissionCodes = [...new Set(
        (Array.isArray(roleEditPermissionCodesChecked)
          ? roleEditPermissionCodesChecked
          : [])
          .map((permissionCode) => String(permissionCode || '').trim())
          .filter((permissionCode) => permissionCode.startsWith('platform.'))
      )];
      setRoleEditSubmitting(true);
      if (roleEditMode === 'create') {
        const payload = await api.createRole({
          code: String(values.code || '').trim(),
          name: String(values.name || '').trim()
        });
        try {
          await api.replaceRolePermissions({
            roleId: payload.role_id,
            permissionCodes: normalizedPermissionCodes
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
        try {
          await api.replaceRolePermissions({
            roleId: roleEditTarget?.role_id,
            permissionCodes: normalizedPermissionCodes
          });
        } catch (error) {
          notify({
            type: 'error',
            text: `平台角色已更新，但权限保存失败（role_id: ${roleEditTarget?.role_id}）：${toProblemMessage(error, '保存平台角色权限失败')}`
          });
          setRoleEditModalOpen(false);
          setRoleEditTarget(null);
          roleEditForm.resetFields();
          await loadRoles();
          return;
        }
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
    loadRoles,
    notify,
    roleEditPermissionCodesChecked,
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
        const latestRoles = await loadRoles();
        const selectedRoleId = String(roleDetail?.role_id || '').trim().toLowerCase();
        if (selectedRoleId && selectedRoleId === normalizedRoleId.toLowerCase()) {
          const refreshedRole = latestRoles.find(
            (role) => String(role?.role_id || '').trim().toLowerCase() === selectedRoleId
          );
          if (refreshedRole) {
            setRoleDetail(refreshedRole);
          } else {
            setRoleDetail((previous) =>
              previous
                ? { ...previous, status: targetStatus }
                : previous
            );
          }
        }
      } catch (error) {
        withErrorNotice(error, '更新平台角色状态失败');
      }
    },
    [api, loadRoles, notify, roleDetail?.role_id, withErrorNotice]
  );

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
        render: (value) => formatDateTimeMinute(value)
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
                void openEditRoleModal(record);
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
              新建
            </Button>
          )}
        />

        <Modal
          open={roleEditModalOpen}
          title={roleEditMode === 'create' ? '新建平台角色' : '编辑'}
          onCancel={() => {
            setRoleEditModalOpen(false);
            setRoleEditTarget(null);
            setRoleEditPermissionCodesAvailable([]);
            setRoleEditPermissionCodesChecked([]);
          }}
          onOk={() => {
            void handleSubmitRoleEdit();
          }}
          confirmLoading={roleEditSubmitting}
          okButtonProps={{
            disabled: roleEditSubmitting || roleEditPermissionLoading,
            'data-testid': roleEditMode === 'create' ? 'platform-role-create-confirm' : 'platform-role-edit-confirm'
          }}
          cancelButtonProps={{
            disabled: roleEditSubmitting,
            'data-testid': roleEditMode === 'create' ? 'platform-role-create-cancel' : 'platform-role-edit-cancel'
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
                },
                {
                  validator: validateRoleCodeRequired
                },
                {
                  validator: validateRoleCodeUnique
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
                },
                {
                  validator: validateRoleNameRequired
                },
                {
                  validator: validateRoleNameUnique
                }
              ]}
            >
              <Input data-testid="platform-role-edit-name" placeholder="请输入角色名称" />
            </CustomForm.Item>
            <CustomForm.Item label="角色权限">
              {roleEditPermissionLoading ? (
                <Spin size="small" />
              ) : (
                <Tree
                  data-testid={roleEditMode === 'create' ? 'platform-role-create-permission-tree' : 'platform-role-edit-permission-tree'}
                  checkable
                  treeData={toPermissionTreeData(roleEditPermissionCodesAvailable)}
                  checkedKeys={roleEditPermissionCodesChecked}
                  onCheck={(checked) => {
                    const checkedKeys = Array.isArray(checked)
                      ? checked
                      : checked.checked;
                    setRoleEditPermissionCodesChecked(
                      checkedKeys
                        .map((key) => String(key || '').trim())
                        .filter((code) => code.startsWith('platform.'))
                    );
                  }}
                />
              )}
            </CustomForm.Item>
          </CustomForm>
        </Modal>

        <Drawer
          open={roleDetailOpen}
          title={`角色ID：${String(roleDetailWithPermission?.role_id || '-').trim() || '-'}`}
          extra={(
            <Space>
              <Button
                data-testid="platform-role-detail-edit"
                onClick={() => {
                  if (!roleDetailWithPermission?.role_id) {
                    return;
                  }
                  void openEditRoleModal(roleDetailWithPermission);
                }}
                disabled={!roleDetailWithPermission?.role_id || Boolean(roleDetailWithPermission?.is_system) || isSysAdminRole(roleDetailWithPermission?.role_id)}
              >
                编辑
              </Button>
              <Button
                data-testid="platform-role-detail-status-toggle"
                onClick={() => {
                  if (!roleDetailWithPermission?.role_id) {
                    return;
                  }
                  void handleToggleRoleStatus(roleDetailWithPermission);
                }}
                disabled={
                  !roleDetailWithPermission?.role_id
                  || Boolean(isSysAdminRole(roleDetailWithPermission?.role_id) && !isDisabledStatus(roleDetailWithPermission?.status))
                }
              >
                {roleDetailWithPermission?.role_id
                  ? statusToggleLabel(roleDetailWithPermission?.status)
                  : '启用/禁用'}
              </Button>
            </Space>
          )}
          size="large"
          onClose={() => {
            setRoleDetailOpen(false);
          }}
          destroyOnClose
        >
          <div data-testid="platform-role-detail-drawer" style={{ display: 'grid', gap: 8 }}>
            <Descriptions
              bordered
              size="small"
              column={1}
            >
              <Descriptions.Item label="角色编码">
                {String(roleDetailWithPermission?.code || '').trim() || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="角色名称">
                {String(roleDetailWithPermission?.name || '').trim() || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                {statusDisplayLabel(roleDetailWithPermission?.status)}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTimeMinute(roleDetailWithPermission?.created_at)}
              </Descriptions.Item>
              <Descriptions.Item label="角色权限">
                {permissionLoading ? (
                  <div style={{ marginTop: 8 }}>
                    <Spin size="small" />
                  </div>
                ) : (
                  <Tree
                    data-testid="platform-role-permission-tree"
                    style={{ marginTop: 8 }}
                    checkable
                    disabled
                    selectable={false}
                    treeData={toPermissionTreeData(permissionCodesAvailable)}
                    checkedKeys={permissionCodesChecked}
                    defaultExpandAll
                  />
                )}
              </Descriptions.Item>
            </Descriptions>
          </div>
        </Drawer>
      </section>
    </section>
  );
}
