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
import CustomCardTable from '../../../../components/CustomCardTable';
import CustomFilter from '../../../../components/CustomFilter';
import CustomForm from '../../../../components/CustomForm';
import {
  createTenantManagementApi,
  toProblemMessage
} from '../../../../api/tenant-management.mjs';
import {
  formatDateTimeMinute,
  toDateTimeMinuteEpoch
} from '../../../../utils/date-time.mjs';

const ROLE_STATUS_OPTIONS = [
  { label: '全部', value: '' },
  { label: '启用', value: 'active' },
  { label: '禁用', value: 'disabled' }
];
const TENANT_SYS_ADMIN_ROLE_CODE = 'sys_admin';
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
const isTenantSysAdminRole = (roleRecord) => {
  const normalizedCode = String(roleRecord?.code || '').trim().toLowerCase();
  if (normalizedCode === TENANT_SYS_ADMIN_ROLE_CODE) {
    return true;
  }
  const normalizedRoleId = String(
    roleRecord?.role_id || roleRecord?.roleId || ''
  ).trim().toLowerCase();
  return (
    normalizedRoleId === TENANT_SYS_ADMIN_ROLE_CODE
    || normalizedRoleId.startsWith(`${TENANT_SYS_ADMIN_ROLE_CODE}__`)
  );
};

const SESSION_TREE_ROOT_KEY = 'session';
const CUSTOMER_TREE_ROOT_KEY = 'customer';
const ACCOUNT_MATRIX_TREE_ROOT_KEY = 'account';
const SETTINGS_TREE_ROOT_KEY = 'settings';
const TENANT_PERMISSION_MODULE_LABEL_MAP = Object.freeze({
  [SESSION_TREE_ROOT_KEY]: '会话管理',
  [CUSTOMER_TREE_ROOT_KEY]: '客户管理',
  [ACCOUNT_MATRIX_TREE_ROOT_KEY]: '账号矩阵',
  [SETTINGS_TREE_ROOT_KEY]: '设置'
});
const TENANT_PERMISSION_MODULE_ORDER_MAP = Object.freeze({
  [SESSION_TREE_ROOT_KEY]: 0,
  [CUSTOMER_TREE_ROOT_KEY]: 1,
  [ACCOUNT_MATRIX_TREE_ROOT_KEY]: 2,
  [SETTINGS_TREE_ROOT_KEY]: 3
});
const TENANT_PERMISSION_GROUP_MODULE_KEY_MAP = Object.freeze({
  session_management: SESSION_TREE_ROOT_KEY,
  session_scope_my: SESSION_TREE_ROOT_KEY,
  session_scope_assist: SESSION_TREE_ROOT_KEY,
  session_scope_all: SESSION_TREE_ROOT_KEY,
  customer_management: CUSTOMER_TREE_ROOT_KEY,
  customer_scope_my: CUSTOMER_TREE_ROOT_KEY,
  customer_scope_assist: CUSTOMER_TREE_ROOT_KEY,
  customer_scope_all: CUSTOMER_TREE_ROOT_KEY,
  account_management: ACCOUNT_MATRIX_TREE_ROOT_KEY,
  user_management: SETTINGS_TREE_ROOT_KEY,
  role_management: SETTINGS_TREE_ROOT_KEY
});
const TENANT_PERMISSION_GROUP_LABEL_MAP = Object.freeze({
  session_management: '会话中心',
  session_scope_my: '我的会话',
  session_scope_assist: '协管会话',
  session_scope_all: '全部会话',
  customer_management: '客户资料',
  customer_scope_my: '我的客户',
  customer_scope_assist: '协管客户',
  customer_scope_all: '全部客户',
  user_management: '用户管理',
  role_management: '角色管理',
  account_management: '账号管理'
});
const TENANT_PERMISSION_ACTION_LABEL_MAP = Object.freeze({
  view: '查看',
  operate: '操作'
});
const TENANT_PERMISSION_LABEL_KEY_MAP = Object.freeze({
  'permission.tenant.session_management.view': '查看会话中心',
  'permission.tenant.session_management.operate': '操作会话中心',
  'permission.tenant.session_scope_my.view': '查看我的会话',
  'permission.tenant.session_scope_my.operate': '操作我的会话',
  'permission.tenant.session_scope_assist.view': '查看协管会话',
  'permission.tenant.session_scope_assist.operate': '操作协管会话',
  'permission.tenant.session_scope_all.view': '查看全部会话',
  'permission.tenant.session_scope_all.operate': '操作全部会话',
  'permission.tenant.user_management.view': '查看用户管理',
  'permission.tenant.user_management.operate': '操作用户管理',
  'permission.tenant.role_management.view': '查看角色管理',
  'permission.tenant.role_management.operate': '操作角色管理',
  'permission.tenant.account_management.view': '查看账号管理',
  'permission.tenant.account_management.operate': '操作账号管理',
  'permission.tenant.customer_management.view': '查看客户资料',
  'permission.tenant.customer_management.operate': '操作客户资料',
  'permission.tenant.customer_scope_my.view': '查看我的客户',
  'permission.tenant.customer_scope_my.operate': '操作我的客户',
  'permission.tenant.customer_scope_assist.view': '查看协管客户',
  'permission.tenant.customer_scope_assist.operate': '操作协管客户',
  'permission.tenant.customer_scope_all.view': '查看全部客户',
  'permission.tenant.customer_scope_all.operate': '操作全部客户'
});
const HIDDEN_TENANT_PERMISSION_GROUP_KEY_SET = new Set([
  'customer_management',
  'session_management'
]);
const CUSTOMER_SCOPE_GROUP_KEY_SET = new Set([
  'customer_scope_my',
  'customer_scope_assist',
  'customer_scope_all'
]);
const SESSION_SCOPE_GROUP_KEY_SET = new Set([
  'session_scope_my',
  'session_scope_assist',
  'session_scope_all'
]);
const TENANT_CUSTOMER_SCOPE_OPERATE_TO_VIEW_PERMISSION_MAP = new Map([
  ['tenant.customer_scope_my.operate', 'tenant.customer_scope_my.view'],
  ['tenant.customer_scope_assist.operate', 'tenant.customer_scope_assist.view'],
  ['tenant.customer_scope_all.operate', 'tenant.customer_scope_all.view']
]);
const TENANT_SESSION_SCOPE_OPERATE_TO_VIEW_PERMISSION_MAP = new Map([
  ['tenant.session_scope_my.operate', 'tenant.session_scope_my.view'],
  ['tenant.session_scope_assist.operate', 'tenant.session_scope_assist.view'],
  ['tenant.session_scope_all.operate', 'tenant.session_scope_all.view']
]);
const TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE = 'tenant.session_management.view';
const TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE = 'tenant.session_management.operate';
const TENANT_SESSION_SCOPE_VIEW_PERMISSION_CODE_SET = new Set([
  'tenant.session_scope_my.view',
  'tenant.session_scope_assist.view',
  'tenant.session_scope_all.view'
]);
const TENANT_SESSION_SCOPE_OPERATE_PERMISSION_CODE_SET = new Set([
  'tenant.session_scope_my.operate',
  'tenant.session_scope_assist.operate',
  'tenant.session_scope_all.operate'
]);
const HIDDEN_TENANT_PERMISSION_CODE_SET = new Set([
  TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE,
  TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE
]);
const TENANT_SCOPE_OPERATE_TO_VIEW_PERMISSION_MAP = new Map([
  ...TENANT_CUSTOMER_SCOPE_OPERATE_TO_VIEW_PERMISSION_MAP.entries(),
  ...TENANT_SESSION_SCOPE_OPERATE_TO_VIEW_PERMISSION_MAP.entries()
]);

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
  const groupKey = String(permissionItem.group_key || '').trim().toLowerCase();
  const actionKey = String(permissionItem.action_key || '').trim().toLowerCase();
  if (
    SESSION_SCOPE_GROUP_KEY_SET.has(groupKey)
    && actionKey
    && TENANT_PERMISSION_ACTION_LABEL_MAP[actionKey]
  ) {
    return TENANT_PERMISSION_ACTION_LABEL_MAP[actionKey];
  }
  const labelKey = String(permissionItem.label_key || '').trim();
  if (labelKey && TENANT_PERMISSION_LABEL_KEY_MAP[labelKey]) {
    return TENANT_PERMISSION_LABEL_KEY_MAP[labelKey];
  }
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

const toTenantPermissionModuleKey = (groupKey = '') => {
  const normalizedGroupKey = String(groupKey || '').trim().toLowerCase();
  if (
    normalizedGroupKey
    && TENANT_PERMISSION_GROUP_MODULE_KEY_MAP[normalizedGroupKey]
  ) {
    return TENANT_PERMISSION_GROUP_MODULE_KEY_MAP[normalizedGroupKey];
  }
  return SETTINGS_TREE_ROOT_KEY;
};

const toTenantPermissionModuleLabel = (moduleKey = '') => {
  const normalizedModuleKey = String(moduleKey || '').trim().toLowerCase();
  if (
    normalizedModuleKey
    && TENANT_PERMISSION_MODULE_LABEL_MAP[normalizedModuleKey]
  ) {
    return TENANT_PERMISSION_MODULE_LABEL_MAP[normalizedModuleKey];
  }
  return toReadableLabelFromKey(normalizedModuleKey || SETTINGS_TREE_ROOT_KEY);
};

const toTenantPermissionModuleOrder = (moduleKey = '') => {
  const normalizedModuleKey = String(moduleKey || '').trim().toLowerCase();
  const order = TENANT_PERMISSION_MODULE_ORDER_MAP[normalizedModuleKey];
  if (Number.isFinite(Number(order))) {
    return Number(order);
  }
  return Number.MAX_SAFE_INTEGER;
};

const toPermissionTreeData = (availablePermissions = []) => {
  const moduleNodeByKey = new Map();
  for (const permissionItem of Array.isArray(availablePermissions) ? availablePermissions : []) {
    const permissionCode = String(permissionItem?.code || '').trim().toLowerCase();
    if (!permissionCode.startsWith('tenant.')) {
      continue;
    }
    if (HIDDEN_TENANT_PERMISSION_CODE_SET.has(permissionCode)) {
      continue;
    }
    const parsed = toPermissionCodeParts(permissionCode);
    const groupKey = String(
      permissionItem?.group_key || parsed?.moduleKey || 'misc'
    ).trim().toLowerCase();
    if (HIDDEN_TENANT_PERMISSION_GROUP_KEY_SET.has(groupKey)) {
      continue;
    }
    const moduleKey = toTenantPermissionModuleKey(groupKey);
    const groupNodeKey = `${moduleKey}/${groupKey || 'misc'}`;
    const groupOrder = Number(permissionItem?.order || 0);
    const moduleNode = moduleNodeByKey.get(moduleKey) || {
      key: moduleKey,
      title: toTenantPermissionModuleLabel(moduleKey),
      selectable: false,
      order: toTenantPermissionModuleOrder(moduleKey),
      groups: new Map()
    };
    const currentNode = moduleNode.groups.get(groupNodeKey) || {
      key: groupNodeKey,
      groupKey,
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
    moduleNode.groups.set(groupNodeKey, currentNode);
    moduleNodeByKey.set(moduleKey, moduleNode);
  }

  const toSortedLeafNodes = (children = []) =>
    [...children]
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
      }));

  const toTreeGroupNode = (groupNode = {}) => ({
    key: groupNode.key,
    title: groupNode.title,
    selectable: false,
    order: groupNode.order,
    children: toSortedLeafNodes(groupNode.children)
  });

  return [...moduleNodeByKey.values()]
    .map((moduleNode) => {
      const sortedGroupNodes = [...moduleNode.groups.values()].sort((left, right) => {
        const leftOrder = Number(left?.order || 0);
        const rightOrder = Number(right?.order || 0);
        if (leftOrder !== rightOrder) {
          return leftOrder - rightOrder;
        }
        return String(left.key).localeCompare(String(right.key));
      });

      let resolvedGroupNodes = sortedGroupNodes.map((groupNode) => toTreeGroupNode(groupNode));
      if (moduleNode.key === CUSTOMER_TREE_ROOT_KEY) {
        const customerScopeGroups = sortedGroupNodes.filter((groupNode) =>
          CUSTOMER_SCOPE_GROUP_KEY_SET.has(String(groupNode?.groupKey || '').trim().toLowerCase())
        );
        if (customerScopeGroups.length > 0) {
          const customerScopeGroupKeySet = new Set(
            customerScopeGroups.map((groupNode) => String(groupNode.key || '').trim())
          );
          const nonScopeGroups = sortedGroupNodes
            .filter((groupNode) => !customerScopeGroupKeySet.has(String(groupNode.key || '').trim()))
            .map((groupNode) => toTreeGroupNode(groupNode));
          const customerProfileOrder = customerScopeGroups
            .map((groupNode) => Number(groupNode?.order || 0))
            .reduce((minOrder, currentOrder) => Math.min(minOrder, currentOrder), Number.MAX_SAFE_INTEGER);
          resolvedGroupNodes = [
            {
              key: `${CUSTOMER_TREE_ROOT_KEY}/customer_management`,
              title: toTenantPermissionGroupLabel('customer_management'),
              selectable: false,
              order: Number.isFinite(customerProfileOrder) ? customerProfileOrder : 0,
              children: customerScopeGroups.map((groupNode) => toTreeGroupNode(groupNode))
            },
            ...nonScopeGroups
          ];
        }
      }
      if (moduleNode.key === SESSION_TREE_ROOT_KEY) {
        const sessionScopeGroups = sortedGroupNodes.filter((groupNode) =>
          SESSION_SCOPE_GROUP_KEY_SET.has(String(groupNode?.groupKey || '').trim().toLowerCase())
        );
        if (sessionScopeGroups.length > 0) {
          const sessionScopeGroupKeySet = new Set(
            sessionScopeGroups.map((groupNode) => String(groupNode.key || '').trim())
          );
          const nonSessionGroups = sortedGroupNodes
            .filter((groupNode) => !sessionScopeGroupKeySet.has(String(groupNode.key || '').trim()))
            .map((groupNode) => toTreeGroupNode(groupNode));
          const sessionCenterOrder = sessionScopeGroups
            .map((groupNode) => Number(groupNode?.order || 0))
            .reduce((minOrder, currentOrder) => Math.min(minOrder, currentOrder), Number.MAX_SAFE_INTEGER);
          resolvedGroupNodes = [
            {
              key: `${SESSION_TREE_ROOT_KEY}/session_management`,
              title: toTenantPermissionGroupLabel('session_management'),
              selectable: false,
              order: Number.isFinite(sessionCenterOrder) ? sessionCenterOrder : 0,
              children: sessionScopeGroups.map((groupNode) => toTreeGroupNode(groupNode))
            },
            ...nonSessionGroups
          ];
        }
      }

      return {
        key: moduleNode.key,
        title: moduleNode.title,
        selectable: false,
        order: moduleNode.order,
        children: resolvedGroupNodes
      };
    })
    .sort((left, right) => {
      const leftOrder = Number(left?.order ?? Number.MAX_SAFE_INTEGER);
      const rightOrder = Number(right?.order ?? Number.MAX_SAFE_INTEGER);
      if (leftOrder !== rightOrder) {
        return leftOrder - rightOrder;
      }
      return String(left.key).localeCompare(String(right.key));
    });
};

const selectPermissionCatalogProbeRoleId = (roles = []) => {
  const normalizedRoles = (Array.isArray(roles) ? roles : [])
    .map((role) => {
      if (!role || typeof role !== 'object' || Array.isArray(role)) {
        return null;
      }
      const roleId = String(role.role_id || role.roleId || '').trim().toLowerCase();
      if (!roleId) {
        return null;
      }
      return {
        roleId,
        code: String(role.code || '').trim().toLowerCase(),
        status: String(role.status || '').trim().toLowerCase()
      };
    })
    .filter(Boolean);
  const sysAdminRole = normalizedRoles.find(
    (role) => role.code === 'sys_admin' && role.status === 'active'
  );
  if (sysAdminRole?.roleId) {
    return sysAdminRole.roleId;
  }
  const firstActiveRole = normalizedRoles.find((role) => role.status === 'active');
  if (firstActiveRole?.roleId) {
    return firstActiveRole.roleId;
  }
  return normalizedRoles[0]?.roleId || '';
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
    () => createTenantManagementApi({ accessToken }),
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
      const fallbackRoleListPayload = await api.listRoles();
      const fallbackRoles = Array.isArray(fallbackRoleListPayload?.roles)
        ? fallbackRoleListPayload.roles
        : [];
      const probeRoleId = selectPermissionCatalogProbeRoleId(
        (Array.isArray(roleList) && roleList.length > 0) ? roleList : fallbackRoles
      );
      if (!probeRoleId) {
        throw new Error('tenant-role-permission-catalog-probe-role-missing');
      }
      const payload = await api.getRolePermissions(probeRoleId);
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
  }, [api, notifyError, roleList]);

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
      if (isTenantSysAdminRole(roleRecord)) {
        messageApi.warning('系统管理员角色不支持编辑');
        return;
      }
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
    [loadEditRolePermissionCatalog, messageApi, roleEditForm]
  );

  const handleSubmitRoleEdit = useCallback(async () => {
    try {
      const values = await roleEditForm.validateFields();
      let normalizedPermissionCodes = [...new Set(
        (Array.isArray(roleEditPermissionCodesChecked)
          ? roleEditPermissionCodesChecked
          : [])
          .map((permissionCode) => String(permissionCode || '').trim())
          .filter((permissionCode) => permissionCode.startsWith('tenant.'))
      )];
      const normalizedPermissionCodeSet = new Set(normalizedPermissionCodes);
      for (const [operatePermissionCode, viewPermissionCode] of
        TENANT_SCOPE_OPERATE_TO_VIEW_PERMISSION_MAP.entries()) {
        if (
          normalizedPermissionCodeSet.has(operatePermissionCode)
          && !normalizedPermissionCodeSet.has(viewPermissionCode)
        ) {
          messageApi.error('范围操作权限必须搭配同范围查看权限');
          return;
        }
      }
      const hasAnySessionScopeViewPermission = [...normalizedPermissionCodeSet].some(
        (permissionCode) => TENANT_SESSION_SCOPE_VIEW_PERMISSION_CODE_SET.has(permissionCode)
      );
      const hasAnySessionScopeOperatePermission = [...normalizedPermissionCodeSet].some(
        (permissionCode) => TENANT_SESSION_SCOPE_OPERATE_PERMISSION_CODE_SET.has(permissionCode)
      );
      if (hasAnySessionScopeViewPermission || hasAnySessionScopeOperatePermission) {
        normalizedPermissionCodeSet.add(TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE);
      }
      if (hasAnySessionScopeOperatePermission) {
        normalizedPermissionCodeSet.add(TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE);
      }
      if (normalizedPermissionCodeSet.has(TENANT_SESSION_MANAGEMENT_OPERATE_PERMISSION_CODE)) {
        normalizedPermissionCodeSet.add(TENANT_SESSION_MANAGEMENT_VIEW_PERMISSION_CODE);
      }
      normalizedPermissionCodes = [...normalizedPermissionCodeSet];
      setRoleEditSubmitting(true);
      if (roleEditMode === 'create') {
        const payload = await api.createRole({
          code: String(values.code || '').trim(),
          name: String(values.name || '').trim(),
          status: 'active'
        });
        const createdRoleId = String(
          payload?.role_id || payload?.roleId || ''
        ).trim().toLowerCase();
        if (!createdRoleId) {
          notifyError(new Error('tenant-role-create-missing-role-id'), '组织角色创建成功，但返回的 role_id 无效');
          setRoleEditOpen(false);
          setRoleEditTarget(null);
          setRoleEditPermissionCatalogAvailable([]);
          setRoleEditPermissionCodesChecked([]);
          roleEditForm.resetFields();
          await loadRoles();
          return;
        }
        try {
          await api.replaceRolePermissions({
            roleId: createdRoleId,
            permissionCodes: normalizedPermissionCodes
          });
        } catch (error) {
          notifyError(error, `组织角色已创建，但权限保存失败（role_id: ${createdRoleId || '-'})`);
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
      if (isTenantSysAdminRole(roleRecord)) {
        messageApi.warning('系统管理员角色不支持变更状态');
        return;
      }
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
    [api, loadRoles, messageApi, notifyError, notifySuccess, roleDetail?.role_id]
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
        render: (_value, record) => {
          const isSysAdminRole = isTenantSysAdminRole(record);
          return (
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
                disabled={isSysAdminRole}
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
                disabled={isSysAdminRole}
                onClick={(event) => {
                  event.stopPropagation();
                  void handleToggleRoleStatus(record);
                }}
              >
                {statusToggleLabel(String(record?.status || '').trim().toLowerCase())}
              </Button>
              {isDisabledStatus(record.status) && !isSysAdminRole ? (
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
          );
        }
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
        extra={(
          <Space>
            <Button
              data-testid="tenant-role-detail-edit"
              onClick={() => {
                if (!roleDetailWithPermission?.role_id) {
                  return;
                }
                void openEditRoleModal(roleDetailWithPermission);
              }}
              disabled={
                !roleDetailWithPermission?.role_id
                || isTenantSysAdminRole(roleDetailWithPermission)
              }
            >
              编辑
            </Button>
            <Button
              data-testid="tenant-role-detail-status-toggle"
              onClick={() => {
                if (!roleDetailWithPermission?.role_id) {
                  return;
                }
                void handleToggleRoleStatus(roleDetailWithPermission);
              }}
              disabled={
                !roleDetailWithPermission?.role_id
                || isTenantSysAdminRole(roleDetailWithPermission)
              }
            >
              {roleDetailWithPermission?.role_id
                ? statusToggleLabel(String(roleDetailWithPermission?.status || '').trim().toLowerCase())
                : '启用/禁用'}
            </Button>
          </Space>
        )}
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
