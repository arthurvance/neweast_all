import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
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
  createTenantGovernanceApi,
  toProblemMessage
} from '../../api/tenant-governance.mjs';
import {
  formatDateTimeMinute,
  toDateTimeMinuteEpoch
} from '../../utils/date-time.mjs';

const ROLE_STATUS_OPTIONS = [
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

const isDisabledStatus = (status) =>
  String(status || '').trim().toLowerCase() === 'disabled';
const statusToggleLabel = (status) => (status === 'active' ? '禁用' : '启用');
const statusToggleValue = (status) => (status === 'active' ? 'disabled' : 'active');
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
const ROLE_ID_ADDRESSABLE_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const normalizeRoleIdFromCode = (code) =>
  String(code || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, '_')
    .replace(/_+/g, '_')
    .replace(/^[^a-z0-9]+/, '')
    .replace(/[^a-z0-9]+$/, '')
    .slice(0, 64);

const SETTINGS_TREE_ROOT_KEY = 'settings';
const TENANT_PERMISSION_GROUP_LABEL_MAP = Object.freeze({
  user_management: '用户管理',
  role_management: '角色管理'
});
const TENANT_PERMISSION_ACTION_LABEL_MAP = Object.freeze({
  view: '查看',
  operate: '操作'
});
const TENANT_PERMISSION_LABEL_KEY_MAP = Object.freeze({
  'permission.tenant.user_management.view': '查看用户管理',
  'permission.tenant.user_management.operate': '操作用户管理',
  'permission.tenant.role_management.view': '查看角色管理',
  'permission.tenant.role_management.operate': '操作角色管理'
});

const toPermissionCodeParts = (permissionCode) => {
  const normalizedCode = String(permissionCode || '').trim().toLowerCase();
  if (!normalizedCode.startsWith('tenant.')) {
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

const normalizeTenantPermissionCatalogItems = ({
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

const toTenantPermissionActionLabel = (permissionItem = {}) => {
  const labelKey = String(permissionItem.label_key || '').trim();
  if (labelKey && TENANT_PERMISSION_LABEL_KEY_MAP[labelKey]) {
    return TENANT_PERMISSION_LABEL_KEY_MAP[labelKey];
  }
  const actionKey = String(permissionItem.action_key || '').trim().toLowerCase();
  if (actionKey && TENANT_PERMISSION_ACTION_LABEL_MAP[actionKey]) {
    return TENANT_PERMISSION_ACTION_LABEL_MAP[actionKey];
  }
  const parsed = toPermissionCodeParts(permissionItem.code);
  if (parsed?.actionKey && TENANT_PERMISSION_ACTION_LABEL_MAP[parsed.actionKey]) {
    return TENANT_PERMISSION_ACTION_LABEL_MAP[parsed.actionKey];
  }
  return toReadableLabelFromKey(actionKey || permissionItem.code);
};

const toTenantPermissionGroupLabel = (groupKey = '') => {
  const normalizedGroupKey = String(groupKey || '').trim().toLowerCase();
  if (normalizedGroupKey && TENANT_PERMISSION_GROUP_LABEL_MAP[normalizedGroupKey]) {
    return TENANT_PERMISSION_GROUP_LABEL_MAP[normalizedGroupKey];
  }
  return toReadableLabelFromKey(normalizedGroupKey || 'misc');
};

const toPermissionTreeData = (availablePermissions = []) => {
  const groupNodeByKey = new Map();
  for (const permissionItem of Array.isArray(availablePermissions) ? availablePermissions : []) {
    const permissionCode = String(permissionItem?.code || '').trim().toLowerCase();
    if (!permissionCode.startsWith('tenant.')) {
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
      title: toTenantPermissionGroupLabel(groupKey),
      selectable: false,
      order: Number.isFinite(groupOrder) ? groupOrder : 0,
      children: []
    };
    if (Number.isFinite(groupOrder)) {
      currentNode.order = Math.min(currentNode.order, groupOrder);
    }
    currentNode.children.push({
      key: permissionCode,
      title: toTenantPermissionActionLabel(permissionItem),
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

const formatProblemText = (error, fallback) => {
  const text = toProblemMessage(error, fallback);
  const errorCode = String(error?.payload?.error_code || '').trim();
  if (!errorCode || text.includes(errorCode)) {
    return text;
  }
  return `${text}（${errorCode}）`;
};

export default function TenantRoleManagementPage({ accessToken }) {
  const api = useMemo(
    () => createTenantGovernanceApi({ accessToken }),
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
  const [roleEditOpen, setRoleEditOpen] = useState(false);
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
  const rolePermissionLoadingTargetRef = useRef('');

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

  const loadRoles = useCallback(async () => {
    setRoleListLoading(true);
    try {
      const payload = await api.listRoles();
      const roles = Array.isArray(payload?.roles) ? payload.roles : [];
      const normalizedRoles = roles.map((role) => ({ ...role, key: role.role_id }));
      setRoleList(normalizedRoles);
      return normalizedRoles;
    } catch (error) {
      notifyError(error, '加载组织角色列表失败');
      return [];
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

  const loadRolePermissions = useCallback(
    async (roleId) => {
      const normalizedRoleId = String(roleId || '').trim().toLowerCase();
      if (!normalizedRoleId) {
        return;
      }
      rolePermissionLoadingTargetRef.current = normalizedRoleId;
      setPermissionLoading(true);
      try {
        const payload = await api.getRolePermissions(normalizedRoleId);
        if (rolePermissionLoadingTargetRef.current !== normalizedRoleId) {
          return;
        }
        const normalizedAvailablePermissions = normalizeTenantPermissionCatalogItems({
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
        if (rolePermissionLoadingTargetRef.current !== normalizedRoleId) {
          return;
        }
        setPermissionCatalogAvailable([]);
        setPermissionCodesAvailable([]);
        setPermissionCodesChecked([]);
        notifyError(error, '加载角色权限树失败');
      } finally {
        if (rolePermissionLoadingTargetRef.current === normalizedRoleId) {
          setPermissionLoading(false);
        }
      }
    },
    [api, notifyError]
  );

  const openRoleDetail = useCallback(
    async (roleRecord) => {
      setRoleDetail(roleRecord);
      setRoleDetailOpen(true);
      setPermissionCatalogAvailable([]);
      setPermissionCodesAvailable([]);
      setPermissionCodesChecked([]);
      await loadRolePermissions(roleRecord.role_id);
    },
    [loadRolePermissions]
  );

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
      const roleId = String(role?.role_id || '').trim().toLowerCase();
      if (roleEditMode === 'edit' && roleId === editingRoleId) {
        return false;
      }
      return String(role?.code || '').trim().toLowerCase() === normalizedCode;
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
      const roleId = String(role?.role_id || '').trim().toLowerCase();
      if (roleEditMode === 'edit' && roleId === editingRoleId) {
        return false;
      }
      return String(role?.name || '').trim().toLowerCase() === normalizedName;
    });
    if (!duplicated) {
      return Promise.resolve();
    }
    return Promise.reject(new Error('角色名称需在组织内唯一'));
  }, [roleEditMode, roleEditTarget, roleList]);

  const loadCreateRolePermissionCatalog = useCallback(async () => {
    setRoleEditPermissionLoading(true);
    try {
      const payload = await api.getRolePermissions('tenant_owner');
      const normalizedAvailablePermissions = normalizeTenantPermissionCatalogItems({
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
      notifyError(error, '加载角色权限目录失败');
    } finally {
      setRoleEditPermissionLoading(false);
    }
  }, [api, notifyError]);

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
        const normalizedAvailablePermissions = normalizeTenantPermissionCatalogItems({
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
        notifyError(error, '加载角色权限树失败');
      } finally {
        setRoleEditPermissionLoading(false);
      }
    },
    [api, notifyError]
  );

  const openCreateRoleModal = useCallback(() => {
    setRoleEditMode('create');
    setRoleEditTarget(null);
    setRoleEditOpen(true);
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
      setRoleEditOpen(true);
      setRoleEditPermissionCatalogAvailable([]);
      setRoleEditPermissionCodesChecked([]);
      roleEditForm.setFieldsValue({
        role_id: roleRecord.role_id,
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
          .filter((permissionCode) => permissionCode.startsWith('tenant.'))
      )];
      setRoleEditSubmitting(true);
      if (roleEditMode === 'create') {
        const generatedRoleId = normalizeRoleIdFromCode(values.code);
        if (!ROLE_ID_ADDRESSABLE_PATTERN.test(generatedRoleId)) {
          messageApi.error('角色编码无法转换为有效角色ID，请调整编码后重试');
          setRoleEditSubmitting(false);
          return;
        }
        const payload = await api.createRole({
          role_id: generatedRoleId,
          code: String(values.code || '').trim(),
          name: String(values.name || '').trim(),
          status: 'active'
        });
        try {
          await api.replaceRolePermissions({
            roleId: payload.role_id,
            permissionCodes: normalizedPermissionCodes
          });
        } catch (error) {
          notifyError(error, `组织角色已创建，但权限保存失败（role_id: ${payload.role_id}）`);
          setRoleEditOpen(false);
          setRoleEditTarget(null);
          setRoleEditPermissionCatalogAvailable([]);
          setRoleEditPermissionCodesChecked([]);
          roleEditForm.resetFields();
          await loadRoles();
          return;
        }
        notifySuccess(`组织角色创建成功（request_id: ${payload.request_id}）`);
      } else {
        const payload = await api.updateRole({
          roleId: roleEditTarget?.role_id,
          payload: {
            code: String(values.code || '').trim(),
            name: String(values.name || '').trim(),
            status: String(roleEditTarget?.status || 'active').trim().toLowerCase()
          }
        });
        try {
          await api.replaceRolePermissions({
            roleId: roleEditTarget?.role_id,
            permissionCodes: normalizedPermissionCodes
          });
        } catch (error) {
          notifyError(error, `组织角色已更新，但权限保存失败（role_id: ${roleEditTarget?.role_id}）`);
          setRoleEditOpen(false);
          setRoleEditTarget(null);
          setRoleEditPermissionCatalogAvailable([]);
          setRoleEditPermissionCodesChecked([]);
          roleEditForm.resetFields();
          await loadRoles();
          return;
        }
        notifySuccess(`组织角色更新成功（request_id: ${payload.request_id}）`);
      }
      setRoleEditOpen(false);
      setRoleEditTarget(null);
      setRoleEditPermissionCatalogAvailable([]);
      setRoleEditPermissionCodesChecked([]);
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
    messageApi,
    roleEditForm,
    roleEditMode,
    roleEditPermissionCodesChecked,
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

  const handleToggleRoleStatus = useCallback(
    async (roleRecord) => {
      const normalizedRoleId = String(roleRecord?.role_id || '').trim().toLowerCase();
      if (!normalizedRoleId) {
        return;
      }
      const targetStatus = statusToggleValue(String(roleRecord?.status || '').trim().toLowerCase());
      try {
        const payload = await api.updateRole({
          roleId: normalizedRoleId,
          payload: {
            code: String(roleRecord?.code || '').trim(),
            name: String(roleRecord?.name || '').trim(),
            status: targetStatus
          }
        });
        notifySuccess(`组织角色状态更新成功（request_id: ${payload.request_id}）`);
        const latestRoles = await loadRoles();
        const selectedRoleId = String(roleDetail?.role_id || '').trim().toLowerCase();
        if (selectedRoleId && selectedRoleId === normalizedRoleId) {
          const refreshedRole = latestRoles.find(
            (item) => String(item?.role_id || '').trim().toLowerCase() === selectedRoleId
          );
          if (refreshedRole) {
            setRoleDetail(refreshedRole);
          }
        }
      } catch (error) {
        notifyError(error, '更新组织角色状态失败');
      }
    },
    [api, loadRoles, notifyError, notifySuccess, roleDetail?.role_id]
  );

  const roleEditPermissionLeafSet = useMemo(
    () => new Set(
      roleEditPermissionCatalogAvailable
        .map((item) => String(item?.code || '').trim())
        .filter((code) => code.startsWith('tenant.'))
    ),
    [roleEditPermissionCatalogAvailable]
  );

  const roleDetailWithPermission = useMemo(
    () => ({
      ...(roleDetail || {}),
      permission_codes: permissionCodesChecked,
      available_permission_codes: permissionCodesAvailable,
      available_permissions: permissionCatalogAvailable
    }),
    [permissionCatalogAvailable, permissionCodesAvailable, permissionCodesChecked, roleDetail]
  );

  const filteredRoleList = useMemo(() => {
    const codeFilter = String(roleFilters.code || '').trim().toLowerCase();
    const nameFilter = String(roleFilters.name || '').trim().toLowerCase();
    const statusFilter = String(roleFilters.status || '').trim().toLowerCase();
    const createdAtStart = toDateTimeMinuteEpoch(roleFilters.created_at_start);
    const createdAtEnd = toDateTimeMinuteEpoch(roleFilters.created_at_end);
    return roleList.filter((role) => {
      const roleCode = String(role.code || '').trim().toLowerCase();
      const roleName = String(role.name || '').trim().toLowerCase();
      const roleStatus = String(role.status || '').trim().toLowerCase();
      const roleCreatedAt = toDateTimeMinuteEpoch(role.created_at);
      if (codeFilter && roleCode !== codeFilter) {
        return false;
      }
      if (nameFilter && !roleName.includes(nameFilter)) {
        return false;
      }
      if (statusFilter && roleStatus !== statusFilter) {
        return false;
      }
      if (createdAtStart !== null || createdAtEnd !== null) {
        if (roleCreatedAt === null) {
          return false;
        }
        if (createdAtStart !== null && roleCreatedAt < createdAtStart) {
          return false;
        }
        if (createdAtEnd !== null && roleCreatedAt > createdAtEnd) {
          return false;
        }
      }
      return true;
    });
  }, [roleFilters, roleList]);

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
          <Space
            onClick={(event) => {
              event.stopPropagation();
            }}
            onMouseDown={(event) => {
              event.stopPropagation();
            }}
          >
            <Button
              data-testid={`tenant-role-edit-${record.role_id}`}
              size="small"
              type="link"
              onClick={(event) => {
                event.stopPropagation();
                void openEditRoleModal(record);
              }}
            >
              编辑
            </Button>
            <Button
              data-testid={`tenant-role-status-${record.role_id}`}
              size="small"
              type="link"
              onClick={(event) => {
                event.stopPropagation();
                void handleToggleRoleStatus(record);
              }}
            >
              {statusToggleLabel(String(record?.status || '').trim().toLowerCase())}
            </Button>
            {isDisabledStatus(record.status) ? (
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
      <section data-testid="tenant-roles-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载组织角色管理。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="tenant-roles-module" style={{ display: 'grid', gap: 12 }}>
      {messageContextHolder}

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
          <Input data-testid="tenant-role-filter-code" placeholder="请输入角色编码（精确）" allowClear />
        </Form.Item>
        <Form.Item label="角色名称" name="name">
          <Input data-testid="tenant-role-filter-name" placeholder="请输入角色名称（模糊）" allowClear />
        </Form.Item>
        <Form.Item label="状态" name="status">
          <Select
            data-testid="tenant-role-filter-status"
            options={ROLE_STATUS_OPTIONS}
          />
        </Form.Item>
        <Form.Item label="创建时间" name="created_time">
          <DatePicker.RangePicker
            data-testid="tenant-role-filter-created-time"
            showTime
            placeholder={['开始时间', '结束时间']}
            format="YYYY-MM-DD HH:mm:ss"
          />
        </Form.Item>
      </CustomFilter>

      <CustomCardTable
        title="组织角色列表"
        rowKey="role_id"
        columns={roleColumns}
        dataSource={filteredRoleList}
        loading={roleListLoading}
        onRow={(record) => ({
          onClick: () => {
            void openRoleDetail(record);
          },
          onKeyDown: (event) => {
            if (event.currentTarget !== event.target) {
              return;
            }
            if (event.key === 'Enter' || event.key === ' ') {
              event.preventDefault();
              void openRoleDetail(record);
            }
          },
          tabIndex: 0,
          style: { cursor: 'pointer' }
        })}
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
            新建
          </Button>
        )}
      />

      <Modal
        open={roleEditOpen}
        title={roleEditMode === 'create' ? '新建' : '编辑'}
        onCancel={() => {
          setRoleEditOpen(false);
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
          {roleEditMode === 'edit' ? (
            <CustomForm.Item label="角色ID" name="role_id">
              <Input data-testid="tenant-role-edit-role-id" disabled />
            </CustomForm.Item>
          ) : null}
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
            <Input data-testid="tenant-role-edit-code" placeholder="请输入角色编码" />
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
            <Input data-testid="tenant-role-edit-name" placeholder="请输入角色名称" />
          </CustomForm.Item>
          <CustomForm.Item label="角色权限">
            {roleEditPermissionLoading ? (
              <Spin size="small" />
            ) : (
              <Tree
                data-testid={roleEditMode === 'create' ? 'tenant-role-create-permission-tree' : 'tenant-role-edit-permission-tree'}
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
        size="large"
        onClose={() => {
          rolePermissionLoadingTargetRef.current = '';
          setRoleDetailOpen(false);
          setRoleDetail(null);
          setPermissionCatalogAvailable([]);
          setPermissionCodesAvailable([]);
          setPermissionCodesChecked([]);
          setPermissionLoading(false);
        }}
        destroyOnClose
      >
        <div data-testid="tenant-role-detail-drawer" style={{ display: 'grid', gap: 8 }}>
          <Descriptions
            bordered
            size="small"
            column={1}
          >
            <Descriptions.Item label="角色ID">
              {String(roleDetailWithPermission?.role_id || '').trim() || '-'}
            </Descriptions.Item>
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
                  data-testid="tenant-role-permission-tree"
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
  );
}
