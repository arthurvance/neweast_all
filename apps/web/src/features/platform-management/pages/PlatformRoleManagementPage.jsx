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
import CustomCardTable from '../../../components/CustomCardTable';
import CustomFilter from '../../../components/CustomFilter';
import CustomForm from '../../../components/CustomForm';
import {
  createPlatformManagementApi,
  toProblemMessage
} from '../../../api/platform-management.mjs';
import {
  formatDateTimeMinute,
  toDateTimeMinuteEpoch
} from '../../../utils/date-time.mjs';

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
const PLATFORM_PERMISSION_GROUP_LABEL_MAP = Object.freeze({
  user_management: '用户管理',
  role_management: '角色管理',
  tenant_management: '组织管理'
});
const PLATFORM_PERMISSION_ACTION_LABEL_MAP = Object.freeze({
  view: '查看',
  operate: '操作'
});
const PLATFORM_PERMISSION_LABEL_KEY_MAP = Object.freeze({
  'permission.platform.user_management.view': '查看用户管理',
  'permission.platform.user_management.operate': '操作用户管理',
  'permission.platform.role_management.view': '查看角色管理',
  'permission.platform.role_management.operate': '操作角色管理',
  'permission.platform.tenant_management.view': '查看组织管理',
  'permission.platform.tenant_management.operate': '操作组织管理'
});

const toPermissionCodeParts = (permissionCode) => {
  const normalizedCode = String(permissionCode || '').trim().toLowerCase();
  if (!normalizedCode.startsWith('platform.')) {
    return null;
  }
  const sections = normalizedCode.split('.');
  return {
    code: normalizedCode,
    moduleKey: String(sections[1] || '').trim().toLowerCase(),
    actionKey: String(sections.slice(2).join('.') || '').trim().toLowerCase()
  };
};

const toReadableLabelFromKey = (value) => String(value || '').trim() || '其他';

const normalizePlatformPermissionCatalogItems = ({
  permissionCodes = [],
  permissionCatalogItems = []
} = {}) => {
  const itemByCode = new Map();
  const addItem = ({
    code,
    groupKey = '',
    actionKey = '',
    labelKey = '',
    order = 0
  }) => {
    const parsed = toPermissionCodeParts(code);
    if (!parsed) {
      return;
    }
    if (itemByCode.has(parsed.code)) {
      return;
    }
    const normalizedOrder = Number.isFinite(Number(order)) ? Number(order) : 0;
    itemByCode.set(parsed.code, {
      code: parsed.code,
      group_key: String(groupKey || parsed.moduleKey || '').trim().toLowerCase(),
      action_key: String(actionKey || parsed.actionKey || '').trim().toLowerCase(),
      label_key: String(labelKey || '').trim(),
      order: normalizedOrder
    });
  };

  for (const item of Array.isArray(permissionCatalogItems) ? permissionCatalogItems : []) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) {
      continue;
    }
    addItem({
      code: item.code,
      groupKey: item.group_key,
      actionKey: item.action_key,
      labelKey: item.label_key,
      order: item.order
    });
  }

  let fallbackOrder = 10000;
  for (const permissionCode of Array.isArray(permissionCodes) ? permissionCodes : []) {
    addItem({
      code: permissionCode,
      order: fallbackOrder
    });
    fallbackOrder += 1;
  }

  return [...itemByCode.values()].sort((left, right) => {
    if (left.order !== right.order) {
      return left.order - right.order;
    }
    return String(left.code).localeCompare(String(right.code));
  });
};

const toPlatformPermissionActionLabel = (permissionItem = {}) => {
  const labelKey = String(permissionItem.label_key || '').trim();
  if (labelKey && PLATFORM_PERMISSION_LABEL_KEY_MAP[labelKey]) {
    return PLATFORM_PERMISSION_LABEL_KEY_MAP[labelKey];
  }
  const actionKey = String(permissionItem.action_key || '').trim().toLowerCase();
  if (actionKey && PLATFORM_PERMISSION_ACTION_LABEL_MAP[actionKey]) {
    return PLATFORM_PERMISSION_ACTION_LABEL_MAP[actionKey];
  }
  const parsed = toPermissionCodeParts(permissionItem.code);
  if (parsed?.actionKey && PLATFORM_PERMISSION_ACTION_LABEL_MAP[parsed.actionKey]) {
    return PLATFORM_PERMISSION_ACTION_LABEL_MAP[parsed.actionKey];
  }
  return toReadableLabelFromKey(actionKey || permissionItem.code);
};

const toPlatformPermissionGroupLabel = (groupKey = '') => {
  const normalizedGroupKey = String(groupKey || '').trim().toLowerCase();
  if (normalizedGroupKey && PLATFORM_PERMISSION_GROUP_LABEL_MAP[normalizedGroupKey]) {
    return PLATFORM_PERMISSION_GROUP_LABEL_MAP[normalizedGroupKey];
  }
  return toReadableLabelFromKey(normalizedGroupKey || 'misc');
};

const toPermissionTreeData = (availablePermissions = []) => {
  const groupNodeByKey = new Map();
  for (const permissionItem of Array.isArray(availablePermissions) ? availablePermissions : []) {
    const permissionCode = String(permissionItem?.code || '').trim().toLowerCase();
    if (!permissionCode.startsWith('platform.')) {
      continue;
    }
    const parsed = toPermissionCodeParts(permissionCode);
    const groupKey = String(
      permissionItem?.group_key || parsed?.moduleKey || 'misc'
    ).trim().toLowerCase();
    const menuKey = `settings/${groupKey || 'misc'}`;
    const groupOrder = Number(permissionItem?.order || 0);
    const currentNode = groupNodeByKey.get(menuKey) || {
      key: menuKey,
      title: toPlatformPermissionGroupLabel(groupKey),
      selectable: false,
      order: Number.isFinite(groupOrder) ? groupOrder : 0,
      children: []
    };
    if (Number.isFinite(groupOrder)) {
      currentNode.order = Math.min(currentNode.order, groupOrder);
    }
    currentNode.children.push({
      key: permissionCode,
      title: toPlatformPermissionActionLabel(permissionItem),
      order: Number.isFinite(groupOrder) ? groupOrder : 0
    });
    groupNodeByKey.set(menuKey, currentNode);
  }

  const orderedNodes = [...groupNodeByKey.values()]
    .map((groupNode) => ({
      key: groupNode.key,
      title: groupNode.title,
      selectable: false,
      order: groupNode.order,
      children: [...groupNode.children]
        .sort((left, right) => {
          const leftOrder = Number(left?.order || 0);
          const rightOrder = Number(right?.order || 0);
          if (leftOrder !== rightOrder) {
            return leftOrder - rightOrder;
          }
          return String(left.key).localeCompare(String(right.key));
        })
        .map((childNode) => ({
          key: childNode.key,
          title: childNode.title
        }))
    }))
    .sort((left, right) => {
      const leftOrder = Number(left?.order || 0);
      const rightOrder = Number(right?.order || 0);
      if (leftOrder !== rightOrder) {
        return leftOrder - rightOrder;
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
    () => createPlatformManagementApi({ accessToken }),
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
  const [roleEditPermissionCatalogAvailable, setRoleEditPermissionCatalogAvailable] = useState([]);
  const [roleEditPermissionCodesChecked, setRoleEditPermissionCodesChecked] = useState([]);
  const [roleEditPermissionLoading, setRoleEditPermissionLoading] = useState(false);

  const [roleDetailOpen, setRoleDetailOpen] = useState(false);
  const [roleDetail, setRoleDetail] = useState(null);
  const [permissionCatalogAvailable, setPermissionCatalogAvailable] = useState([]);
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
      available_permission_codes: permissionCodesAvailable,
      available_permissions: permissionCatalogAvailable
    }),
    [permissionCatalogAvailable, permissionCodesAvailable, permissionCodesChecked, roleDetail]
  );

  const roleEditPermissionLeafSet = useMemo(
    () => new Set(
      roleEditPermissionCatalogAvailable
        .map((item) => String(item?.code || '').trim())
        .filter((code) => code.startsWith('platform.'))
    ),
    [roleEditPermissionCatalogAvailable]
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
        const normalizedAvailablePermissions = normalizePlatformPermissionCatalogItems({
          permissionCodes: Array.isArray(payload?.available_permission_codes)
            ? payload.available_permission_codes
            : [],
          permissionCatalogItems: Array.isArray(payload?.available_permissions)
            ? payload.available_permissions
            : []
        });
        const availablePermissionSet = new Set(
          normalizedAvailablePermissions.map((item) => item.code)
        );
        setPermissionCatalogAvailable(normalizedAvailablePermissions);
        setPermissionCodesAvailable(
          normalizedAvailablePermissions.map((item) => item.code)
        );
        setPermissionCodesChecked(
          (Array.isArray(payload?.permission_codes) ? payload.permission_codes : [])
            .map((permissionCode) => String(permissionCode || '').trim())
            .filter((permissionCode) => availablePermissionSet.has(permissionCode))
        );
      } catch (error) {
        setPermissionCatalogAvailable([]);
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
      const normalizedAvailablePermissions = normalizePlatformPermissionCatalogItems({
        permissionCodes: Array.isArray(payload?.available_permission_codes)
          ? payload.available_permission_codes
          : [],
        permissionCatalogItems: Array.isArray(payload?.available_permissions)
          ? payload.available_permissions
          : []
      });
      setRoleEditPermissionCatalogAvailable(normalizedAvailablePermissions);
      setRoleEditPermissionCodesChecked([]);
    } catch (error) {
      setRoleEditPermissionCatalogAvailable([]);
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
        setRoleEditPermissionCatalogAvailable([]);
        setRoleEditPermissionCodesChecked([]);
        return;
      }
      setRoleEditPermissionLoading(true);
      try {
        const payload = await api.getRolePermissions(normalizedRoleId);
        const normalizedAvailablePermissions = normalizePlatformPermissionCatalogItems({
          permissionCodes: Array.isArray(payload?.available_permission_codes)
            ? payload.available_permission_codes
            : [],
          permissionCatalogItems: Array.isArray(payload?.available_permissions)
            ? payload.available_permissions
            : []
        });
        const availablePermissionSet = new Set(
          normalizedAvailablePermissions.map((item) => item.code)
        );
        setRoleEditPermissionCatalogAvailable(normalizedAvailablePermissions);
        setRoleEditPermissionCodesChecked(
          (Array.isArray(payload?.permission_codes) ? payload.permission_codes : [])
            .map((permissionCode) => String(permissionCode || '').trim())
            .filter((permissionCode) => availablePermissionSet.has(permissionCode))
        );
      } catch (error) {
        setRoleEditPermissionCatalogAvailable([]);
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
    setRoleEditPermissionCatalogAvailable([]);
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
      setRoleEditPermissionCatalogAvailable([]);
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
      <section data-testid="platform-management-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载平台治理工作台。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="platform-management-workbench" style={{ display: 'grid', gap: 12 }}>
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
            setRoleEditPermissionCatalogAvailable([]);
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
                  treeData={toPermissionTreeData(roleEditPermissionCatalogAvailable)}
                  checkedKeys={roleEditPermissionCodesChecked}
                  onCheck={(checked) => {
                    const checkedKeys = Array.isArray(checked)
                      ? checked
                      : checked.checked;
                    setRoleEditPermissionCodesChecked(
                      checkedKeys
                        .map((key) => String(key || '').trim())
                        .filter((permissionCode) => roleEditPermissionLeafSet.has(permissionCode))
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
            setRoleDetail(null);
            setPermissionCatalogAvailable([]);
            setPermissionCodesAvailable([]);
            setPermissionCodesChecked([]);
            setPermissionLoading(false);
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
                    treeData={toPermissionTreeData(permissionCatalogAvailable)}
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
