import { useCallback, useEffect, useMemo, useState } from 'react';
import {
  Alert,
  Avatar,
  Button,
  DatePicker,
  Descriptions,
  Drawer,
  Form,
  Input,
  Modal,
  Select,
  Space,
  Tabs,
  Timeline,
  Typography,
  theme,
  message
} from 'antd';
import { EditOutlined, UserOutlined } from '@ant-design/icons';
import CustomPanelTable from '../../../../components/CustomPanelTable';
import CustomFilter from '../../../../components/CustomFilter';
import CustomForm from '../../../../components/CustomForm';
import {
  createTenantManagementApi,
  toProblemMessage
} from '../../../../api/tenant-management.mjs';
import { formatDateTimeMinute } from '../../../../utils/date-time.mjs';

const { Text } = Typography;
const { TextArea } = Input;

const CUSTOMER_STATUS_OPTIONS = [
  { label: '全部', value: '' },
  { label: '有效', value: 'enabled' },
  { label: '无效', value: 'disabled' }
];
const CUSTOMER_SOURCE_OPTIONS = [
  { label: '地推', value: 'ground' },
  { label: '裂变', value: 'fission' },
  { label: '其它', value: 'other' }
];
const CUSTOMER_SCOPE_CONFIG = Object.freeze({
  my: {
    label: '我的客户',
    testId: 'tenant-customer-tab-my',
    viewSnakeCase: 'can_view_customer_scope_my',
    viewCamelCase: 'canViewCustomerScopeMy',
    operateSnakeCase: 'can_operate_customer_scope_my',
    operateCamelCase: 'canOperateCustomerScopeMy'
  },
  assist: {
    label: '协管客户',
    testId: 'tenant-customer-tab-assist',
    viewSnakeCase: 'can_view_customer_scope_assist',
    viewCamelCase: 'canViewCustomerScopeAssist',
    operateSnakeCase: 'can_operate_customer_scope_assist',
    operateCamelCase: 'canOperateCustomerScopeAssist'
  },
  all: {
    label: '全部客户',
    testId: 'tenant-customer-tab-all',
    viewSnakeCase: 'can_view_customer_scope_all',
    viewCamelCase: 'canViewCustomerScopeAll',
    operateSnakeCase: 'can_operate_customer_scope_all',
    operateCamelCase: 'canOperateCustomerScopeAll'
  }
});
const CUSTOMER_FILTER_INITIAL_VALUES = Object.freeze({
  wechat_id: '',
  account_ids: [],
  nickname: '',
  source: '',
  real_name: '',
  phone: '',
  status: '',
  created_time: []
});
const CUSTOMER_CREATE_INITIAL_VALUES = Object.freeze({
  account_id: undefined,
  wechat_id: '',
  nickname: '',
  source: undefined,
  real_name: '',
  school: '',
  class_name: '',
  relation: '',
  phone: '',
  address: ''
});
const CUSTOMER_BASIC_EDIT_INITIAL_VALUES = Object.freeze({
  customer_id: '',
  account_label: '',
  wechat_id: '',
  nickname: '',
  source: undefined
});
const CUSTOMER_REALNAME_EDIT_INITIAL_VALUES = Object.freeze({
  customer_id: '',
  real_name: '',
  school: '',
  class_name: '',
  relation: '',
  phone: '',
  address: ''
});

const readPermissionFlag = (permissionContext, snakeCase, camelCase) =>
  Boolean(permissionContext?.[snakeCase] || permissionContext?.[camelCase]);

const toStringList = (source = []) =>
  [...new Set(
    (Array.isArray(source) ? source : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  )];

const toNullableString = (value) => {
  const normalized = String(value == null ? '' : value).trim();
  return normalized || null;
};

const normalizeCustomerStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'active' || normalizedStatus === 'enabled') {
    return 'enabled';
  }
  if (normalizedStatus === 'inactive' || normalizedStatus === 'disabled') {
    return 'disabled';
  }
  return '';
};

const customerStatusLabel = (status) => {
  const normalizedStatus = normalizeCustomerStatus(status);
  if (normalizedStatus === 'enabled') {
    return '有效';
  }
  if (normalizedStatus === 'disabled') {
    return '无效';
  }
  return '-';
};

const normalizeCustomerSource = (source) => {
  const normalizedSource = String(source || '').trim().toLowerCase();
  if (normalizedSource === 'ground' || normalizedSource === '地推' || normalizedSource === '地堆') {
    return 'ground';
  }
  if (normalizedSource === 'fission' || normalizedSource === '裂变') {
    return 'fission';
  }
  if (normalizedSource === 'other' || normalizedSource === '其它' || normalizedSource === '其他') {
    return 'other';
  }
  return '';
};

const customerSourceLabel = (source) => {
  const normalizedSource = normalizeCustomerSource(source);
  if (normalizedSource === 'ground') {
    return '地推';
  }
  if (normalizedSource === 'fission') {
    return '裂变';
  }
  if (normalizedSource === 'other') {
    return '其它';
  }
  return '-';
};

const toAccountOptionLabel = (account = {}) => {
  const accountNickname = String(account?.nickname || '').trim();
  const accountWechatId = String(account?.wechat_id || '').trim();
  if (accountNickname && accountWechatId) {
    return `${accountNickname}(${accountWechatId})`;
  }
  if (accountNickname) {
    return accountNickname;
  }
  if (accountWechatId) {
    return accountWechatId;
  }
  return '未命名账号';
};

const toAccountDisplayLabel = ({
  accountId = '',
  accountNickname = '',
  accountWechatId = '',
  fallbackToAccountId = false
} = {}) => {
  const normalizedNickname = String(accountNickname || '').trim();
  const normalizedWechatId = String(accountWechatId || '').trim();
  if (normalizedNickname && normalizedWechatId) {
    return `${normalizedNickname}(${normalizedWechatId})`;
  }
  if (normalizedNickname) {
    return normalizedNickname;
  }
  if (normalizedWechatId) {
    return normalizedWechatId;
  }
  if (fallbackToAccountId) {
    return String(accountId || '').trim();
  }
  return '';
};

const resolveCustomerAccountLabel = ({
  customer = {},
  accountLabelById = {}
} = {}) => {
  const directLabel = String(
    customer?.account_label || customer?.accountLabel || ''
  ).trim();
  if (directLabel) {
    return directLabel;
  }
  const accountId = String(customer?.account_id || customer?.accountId || '').trim();
  const accountLabelFromMap = String(accountLabelById?.[accountId] || '').trim();
  if (accountLabelFromMap) {
    return accountLabelFromMap;
  }
  return toAccountDisplayLabel({
    accountId,
    accountNickname:
      customer?.account_nickname
      || customer?.accountNickname
      || customer?.account_name
      || customer?.accountName
      || customer?.account?.nickname
      || '',
    accountWechatId:
      customer?.account_wechat_id
      || customer?.accountWechatId
      || customer?.account?.wechat_id
      || customer?.account?.wechatId
      || ''
  });
};

const normalizeCustomerRecord = (customer = {}) => {
  const accountId = String(customer?.account_id || customer?.accountId || '').trim();
  const accountWechatId = String(
    customer?.account_wechat_id
    || customer?.accountWechatId
    || customer?.account?.wechat_id
    || customer?.account?.wechatId
    || ''
  ).trim();
  const accountNickname = String(
    customer?.account_nickname
    || customer?.accountNickname
    || customer?.account_name
    || customer?.accountName
    || customer?.account?.nickname
    || ''
  ).trim();

  return {
    customer_id: String(customer?.customer_id || customer?.customerId || '').trim(),
    tenant_id: String(customer?.tenant_id || customer?.tenantId || '').trim(),
    account_id: accountId,
    account_wechat_id: accountWechatId,
    account_nickname: accountNickname,
    account_label: toAccountDisplayLabel({
      accountId,
      accountNickname,
      accountWechatId
    }),
    wechat_id: String(customer?.wechat_id || customer?.wechatId || '').trim(),
    nickname: String(customer?.nickname || '').trim(),
    source: normalizeCustomerSource(customer?.source),
    school: String(customer?.school || '').trim(),
    class_name: String(customer?.class_name || customer?.className || '').trim(),
    real_name: String(customer?.real_name || customer?.realName || '').trim(),
    relation: String(customer?.relation || '').trim(),
    phone: String(customer?.phone || '').trim(),
    address: String(customer?.address || '').trim(),
    status: normalizeCustomerStatus(customer?.status),
    created_by_name: String(customer?.created_by_name || customer?.createdByName || '').trim(),
    created_by_user_id: String(customer?.created_by_user_id || customer?.createdByUserId || '').trim(),
    created_at: String(customer?.created_at || customer?.createdAt || '').trim(),
    updated_at: String(customer?.updated_at || customer?.updatedAt || '').trim(),
    operation_logs: Array.isArray(customer?.operation_logs)
      ? customer.operation_logs
      : (Array.isArray(customer?.logs) ? customer.logs : [])
  };
};

const parseTimeValue = (value) => {
  const normalizedValue = String(value || '').trim();
  if (!normalizedValue) {
    return 0;
  }
  const timestamp = Date.parse(normalizedValue);
  if (Number.isNaN(timestamp)) {
    return 0;
  }
  return timestamp;
};

const CUSTOMER_OPERATION_TYPE_LABEL_MAP = Object.freeze({
  create: '新建客户',
  update_basic: '编辑基本信息',
  update_realname: '编辑实名信息',
  status: '状态变更'
});

const normalizeCustomerOperationLogs = (logs = []) =>
  (Array.isArray(logs) ? logs : [])
    .map((log) => ({
      operation_type: CUSTOMER_OPERATION_TYPE_LABEL_MAP[String(log?.operation_type || log?.type || '').trim().toLowerCase()]
        || String(log?.operation_type || log?.type || '').trim()
        || '操作',
      operated_at: String(log?.operated_at || log?.operation_time || log?.created_at || '').trim(),
      operator_name: String(log?.operator_name || log?.operator || '').trim() || '-',
      content: String(log?.content || log?.operation_content || log?.detail || '-').trim() || '-'
    }))
    .sort((left, right) => parseTimeValue(right.operated_at) - parseTimeValue(left.operated_at));

const formatProblemText = (error, fallback) => {
  const text = toProblemMessage(error, fallback);
  const errorCode = String(error?.payload?.error_code || '').trim();
  if (!errorCode || text.includes(errorCode)) {
    return text;
  }
  return `${text}（${errorCode}）`;
};

const isForbiddenProblem = (error) =>
  String(error?.payload?.error_code || '').trim().toUpperCase() === 'AUTH-403-FORBIDDEN';

export default function TenantCustomerProfilePage({
  accessToken,
  tenantPermissionContext = null
}) {
  const { token } = theme.useToken();
  const api = useMemo(
    () => createTenantManagementApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [customerFilterForm] = Form.useForm();
  const [customerCreateForm] = Form.useForm();
  const [customerBasicEditForm] = Form.useForm();
  const [customerRealnameEditForm] = Form.useForm();

  const [customerFilters, setCustomerFilters] = useState({
    wechat_id: '',
    account_ids: [],
    nickname: '',
    source: '',
    real_name: '',
    phone: '',
    status: '',
    created_time_start: '',
    created_time_end: ''
  });
  const [customerTableRefreshToken, setCustomerTableRefreshToken] = useState(0);
  const [activeScope, setActiveScope] = useState('');
  const [accountOptions, setAccountOptions] = useState([]);
  const [accountOptionsLoading, setAccountOptionsLoading] = useState(false);
  const [accountLabelById, setAccountLabelById] = useState({});
  const [memberNameByUserId, setMemberNameByUserId] = useState({});
  const [customerCreateOpen, setCustomerCreateOpen] = useState(false);
  const [customerCreateSubmitting, setCustomerCreateSubmitting] = useState(false);
  const [customerBasicEditOpen, setCustomerBasicEditOpen] = useState(false);
  const [customerBasicEditLoading, setCustomerBasicEditLoading] = useState(false);
  const [customerBasicEditSubmitting, setCustomerBasicEditSubmitting] = useState(false);
  const [customerBasicEditTarget, setCustomerBasicEditTarget] = useState(null);
  const [customerRealnameEditOpen, setCustomerRealnameEditOpen] = useState(false);
  const [customerRealnameEditLoading, setCustomerRealnameEditLoading] = useState(false);
  const [customerRealnameEditSubmitting, setCustomerRealnameEditSubmitting] = useState(false);
  const [customerRealnameEditTarget, setCustomerRealnameEditTarget] = useState(null);
  const [customerDetailOpen, setCustomerDetailOpen] = useState(false);
  const [customerDetailLoading, setCustomerDetailLoading] = useState(false);
  const [customerDetail, setCustomerDetail] = useState(null);
  const [customerDetailTargetId, setCustomerDetailTargetId] = useState('');
  const [latestCustomerActionById, setLatestCustomerActionById] = useState({});

  const hasTenantPermissionContext =
    tenantPermissionContext && typeof tenantPermissionContext === 'object';
  const canViewAccountManagement =
    hasTenantPermissionContext
    && readPermissionFlag(
      tenantPermissionContext,
      'can_view_account_management',
      'canViewAccountManagement'
    );
  const canViewUserManagement =
    hasTenantPermissionContext
    && readPermissionFlag(
      tenantPermissionContext,
      'can_view_user_management',
      'canViewUserManagement'
    );

  const visibleScopes = useMemo(() => {
    if (!hasTenantPermissionContext) {
      return [];
    }
    return Object.entries(CUSTOMER_SCOPE_CONFIG)
      .filter(([_scopeKey, scopeMeta]) =>
        readPermissionFlag(
          tenantPermissionContext,
          scopeMeta.viewSnakeCase,
          scopeMeta.viewCamelCase
        )
      )
      .map(([scopeKey, scopeMeta]) => ({
        key: scopeKey,
        label: scopeMeta.label,
        testId: scopeMeta.testId
      }));
  }, [hasTenantPermissionContext, tenantPermissionContext]);

  const canOperateCustomerByScope = useMemo(() => {
    if (!hasTenantPermissionContext) {
      return {};
    }
    const hasLegacyOperatePermission = readPermissionFlag(
      tenantPermissionContext,
      'can_operate_customer_management',
      'canOperateCustomerManagement'
    );
    return Object.fromEntries(
      Object.entries(CUSTOMER_SCOPE_CONFIG).map(([scopeKey, scopeMeta]) => [
        scopeKey,
        Boolean(
          hasLegacyOperatePermission
          || readPermissionFlag(
            tenantPermissionContext,
            scopeMeta.operateSnakeCase,
            scopeMeta.operateCamelCase
          )
        )
      ])
    );
  }, [hasTenantPermissionContext, tenantPermissionContext]);

  const canOperateCustomerManagement = Boolean(
    activeScope && canOperateCustomerByScope[activeScope]
  );

  useEffect(() => {
    const firstScope = visibleScopes[0]?.key || '';
    if (!firstScope) {
      if (activeScope) {
        setActiveScope('');
      }
      return;
    }
    const activeScopeExists = visibleScopes.some((scope) => scope.key === activeScope);
    if (!activeScopeExists) {
      setActiveScope(firstScope);
    }
  }, [activeScope, visibleScopes]);

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

  const refreshCustomerTable = useCallback(() => {
    setCustomerTableRefreshToken((previous) => previous + 1);
  }, []);

  const loadAccountOptions = useCallback(async () => {
    setAccountOptionsLoading(true);
    try {
      const nextAccountOptions = [];
      const nextAccountLabelById = {};
      const seenAccountIds = new Set();
      let page = 1;
      const pageSize = 200;
      while (page <= 200) {
        const payload = await api.listAccounts({
          page,
          pageSize
        });
        const accounts = Array.isArray(payload?.accounts)
          ? payload.accounts
          : (Array.isArray(payload?.items) ? payload.items : []);
        for (const account of accounts) {
          const accountId = String(account?.account_id || account?.accountId || '').trim();
          if (!accountId || seenAccountIds.has(accountId)) {
            continue;
          }
          seenAccountIds.add(accountId);
          const accountNickname = String(account?.nickname || '').trim();
          const accountWechatId = String(account?.wechat_id || account?.wechatId || '').trim();
          const optionLabel = toAccountOptionLabel(account);
          const detailDisplayLabel = toAccountDisplayLabel({
            accountId,
            accountNickname,
            accountWechatId
          });
          if (detailDisplayLabel) {
            nextAccountLabelById[accountId] = detailDisplayLabel;
          }
          nextAccountOptions.push({
            value: accountId,
            label: optionLabel
          });
        }
        if (accounts.length < pageSize) {
          break;
        }
        page += 1;
      }
      nextAccountOptions.sort((left, right) =>
        String(left.label || '').localeCompare(String(right.label || ''), 'zh-Hans-CN')
      );
      setAccountOptions(nextAccountOptions);
      setAccountLabelById(nextAccountLabelById);
    } catch (error) {
      setAccountOptions([]);
      setAccountLabelById({});
      if (!isForbiddenProblem(error)) {
        notifyError(error, '加载账号选项失败');
      }
    } finally {
      setAccountOptionsLoading(false);
    }
  }, [api, notifyError]);

  const loadMemberNameMap = useCallback(async () => {
    try {
      const nextMap = {};
      let page = 1;
      const pageSize = 200;
      while (page <= 200) {
        const payload = await api.listUsers({
          page,
          pageSize
        });
        const members = Array.isArray(payload?.members) ? payload.members : [];
        for (const member of members) {
          const userId = String(member?.user_id || member?.userId || '').trim();
          if (!userId || nextMap[userId]) {
            continue;
          }
          const displayName = String(member?.display_name || member?.displayName || '').trim();
          if (displayName) {
            nextMap[userId] = displayName;
          }
        }
        if (members.length < pageSize) {
          break;
        }
        page += 1;
      }
      setMemberNameByUserId(nextMap);
    } catch (_error) {
      setMemberNameByUserId({});
    }
  }, [api]);

  useEffect(() => {
    if (!accessToken) {
      setAccountOptions([]);
      setAccountLabelById({});
      setMemberNameByUserId({});
      return;
    }
    if (!canViewAccountManagement) {
      setAccountOptions([]);
      setAccountLabelById({});
    }
    if (!canViewUserManagement) {
      setMemberNameByUserId({});
    }
    const loadingTasks = [];
    if (canViewAccountManagement) {
      loadingTasks.push(loadAccountOptions());
    }
    if (canViewUserManagement) {
      loadingTasks.push(loadMemberNameMap());
    }
    if (loadingTasks.length < 1) {
      return;
    }
    void Promise.all(loadingTasks);
  }, [
    accessToken,
    canViewAccountManagement,
    canViewUserManagement,
    loadAccountOptions,
    loadMemberNameMap
  ]);

  const openCustomerDetail = useCallback(async (customerId, latestActionOverride = null) => {
    const normalizedCustomerId = String(customerId || '').trim();
    if (!normalizedCustomerId) {
      setCustomerDetailTargetId('');
      return;
    }
    setCustomerDetailTargetId(normalizedCustomerId);
    setCustomerDetailOpen(true);
    setCustomerDetailLoading(true);
    try {
      const [detailPayload, logsPayload] = await Promise.all([
        api.getCustomerDetail(normalizedCustomerId),
        api.listCustomerOperationLogs(normalizedCustomerId).catch(() => null)
      ]);
      const normalizedCustomer = normalizeCustomerRecord(detailPayload);
      const logsFromDetail = Array.isArray(normalizedCustomer.operation_logs)
        ? normalizedCustomer.operation_logs
        : [];
      const logsFromPayload = Array.isArray(logsPayload?.logs)
        ? logsPayload.logs
        : (Array.isArray(logsPayload?.operation_logs) ? logsPayload.operation_logs : []);
      normalizedCustomer.operation_logs = logsFromDetail.length > 0
        ? logsFromDetail
        : logsFromPayload;
      if (normalizedCustomer.operation_logs.length < 1) {
        const latestAction = latestActionOverride || latestCustomerActionById[normalizedCustomerId] || null;
        if (latestAction) {
          normalizedCustomer.operation_logs = [
            {
              operation_type: String(latestAction.operation_type || latestAction.action || '操作').trim() || '操作',
              operated_at: String(latestAction.operated_at || latestAction.time || '').trim(),
              operator_name: String(latestAction.operator_name || latestAction.operator || '-').trim() || '-',
              content: String(latestAction.content || latestAction.result || '-').trim() || '-'
            }
          ];
        }
      }
      setCustomerDetail(normalizedCustomer);
    } catch (error) {
      setCustomerDetail(null);
      notifyError(error, '加载客户详情失败');
    } finally {
      setCustomerDetailLoading(false);
    }
  }, [api, latestCustomerActionById, notifyError]);

  const openCustomerCreateModal = useCallback(() => {
    if (!canOperateCustomerManagement) {
      return;
    }
    customerCreateForm.setFieldsValue(CUSTOMER_CREATE_INITIAL_VALUES);
    setCustomerCreateOpen(true);
  }, [canOperateCustomerManagement, customerCreateForm]);

  const openCustomerBasicEditModal = useCallback(async (record = {}) => {
    if (!canOperateCustomerManagement) {
      return;
    }
    const normalizedRecord = normalizeCustomerRecord(record);
    const normalizedCustomerId = String(
      normalizedRecord.customer_id
      || customerDetail?.customer_id
      || customerDetailTargetId
      || ''
    ).trim();
    if (!normalizedCustomerId) {
      return;
    }

    setCustomerBasicEditTarget(normalizedRecord);
    customerBasicEditForm.setFieldsValue({
      customer_id: normalizedCustomerId,
      account_label: resolveCustomerAccountLabel({
        customer: normalizedRecord,
        accountLabelById
      }) || '-',
      wechat_id: normalizedRecord.wechat_id,
      nickname: normalizedRecord.nickname,
      source: normalizedRecord.source || undefined
    });
    setCustomerBasicEditOpen(true);
    setCustomerBasicEditLoading(true);

    try {
      const detailPayload = await api.getCustomerDetail(normalizedCustomerId);
      const normalizedDetail = normalizeCustomerRecord(detailPayload);
      setCustomerBasicEditTarget(normalizedDetail);
      customerBasicEditForm.setFieldsValue({
        customer_id: normalizedDetail.customer_id,
        account_label: resolveCustomerAccountLabel({
          customer: normalizedDetail,
          accountLabelById
        }) || '-',
        wechat_id: normalizedDetail.wechat_id,
        nickname: normalizedDetail.nickname,
        source: normalizedDetail.source || undefined
      });
    } catch (error) {
      notifyError(error, '加载客户详情失败，已回退为行数据');
    } finally {
      setCustomerBasicEditLoading(false);
    }
  }, [
    api,
    canOperateCustomerManagement,
    accountLabelById,
    customerBasicEditForm,
    customerDetail,
    customerDetailTargetId,
    notifyError
  ]);

  const openCustomerRealnameEditModal = useCallback(async (record = {}) => {
    if (!canOperateCustomerManagement) {
      return;
    }
    const normalizedRecord = normalizeCustomerRecord(record);
    const normalizedCustomerId = String(
      normalizedRecord.customer_id
      || customerDetail?.customer_id
      || customerDetailTargetId
      || ''
    ).trim();
    if (!normalizedCustomerId) {
      return;
    }

    setCustomerRealnameEditTarget(normalizedRecord);
    customerRealnameEditForm.setFieldsValue({
      customer_id: normalizedCustomerId,
      real_name: normalizedRecord.real_name,
      school: normalizedRecord.school,
      class_name: normalizedRecord.class_name,
      relation: normalizedRecord.relation,
      phone: normalizedRecord.phone,
      address: normalizedRecord.address
    });
    setCustomerRealnameEditOpen(true);
    setCustomerRealnameEditLoading(true);

    try {
      const detailPayload = await api.getCustomerDetail(normalizedCustomerId);
      const normalizedDetail = normalizeCustomerRecord(detailPayload);
      setCustomerRealnameEditTarget(normalizedDetail);
      customerRealnameEditForm.setFieldsValue({
        customer_id: normalizedDetail.customer_id,
        real_name: normalizedDetail.real_name,
        school: normalizedDetail.school,
        class_name: normalizedDetail.class_name,
        relation: normalizedDetail.relation,
        phone: normalizedDetail.phone,
        address: normalizedDetail.address
      });
    } catch (error) {
      notifyError(error, '加载客户详情失败，已回退为行数据');
    } finally {
      setCustomerRealnameEditLoading(false);
    }
  }, [
    api,
    canOperateCustomerManagement,
    customerDetail,
    customerDetailTargetId,
    customerRealnameEditForm,
    notifyError
  ]);

const toCustomerCreatePayload = (values = {}) => ({
  account_id: String(values.account_id || '').trim(),
  wechat_id: toNullableString(values.wechat_id),
  nickname: String(values.nickname || '').trim(),
  source: normalizeCustomerSource(values.source),
    real_name: toNullableString(values.real_name),
    school: toNullableString(values.school),
    class_name: toNullableString(values.class_name),
    relation: toNullableString(values.relation),
    phone: toNullableString(values.phone),
    address: toNullableString(values.address)
  });

  const handleSubmitCustomerCreate = useCallback(async () => {
    try {
      const values = await customerCreateForm.validateFields();
      const payload = toCustomerCreatePayload(values);
      setCustomerCreateSubmitting(true);
      const createdPayload = await api.createCustomer(payload);
      const createdCustomerId = String(
        createdPayload?.customer_id || createdPayload?.customerId || ''
      ).trim();
      const latestAction = {
        action: 'create',
        operation_type: '新建客户',
        operated_at: new Date().toISOString(),
        operator_name: '-',
        content: `request_id: ${String(createdPayload?.request_id || '-')}`
      };
      if (createdCustomerId) {
        setLatestCustomerActionById((previous) => ({
          ...previous,
          [createdCustomerId]: latestAction
        }));
      }
      notifySuccess(`客户新建成功（request_id: ${createdPayload?.request_id || '-'}）`);
      setCustomerCreateOpen(false);
      customerCreateForm.resetFields();
      refreshCustomerTable();
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '新建客户失败');
    } finally {
      setCustomerCreateSubmitting(false);
    }
  }, [
    api,
    customerCreateForm,
    notifyError,
    notifySuccess,
    refreshCustomerTable
  ]);

  const handleSubmitCustomerBasicEdit = useCallback(async () => {
    try {
      const values = await customerBasicEditForm.validateFields();
      const normalizedCustomerId = String(
        customerBasicEditTarget?.customer_id
        || values.customer_id
        || customerDetail?.customer_id
        || ''
      ).trim();
      if (!normalizedCustomerId) {
        return;
      }
      setCustomerBasicEditSubmitting(true);
      const updatedPayload = await api.updateCustomer({
        customerId: normalizedCustomerId,
        payload: {
          nickname: String(values.nickname || customerBasicEditTarget?.nickname || '').trim(),
          source: normalizeCustomerSource(values.source)
        }
      });
      const latestAction = {
        action: 'update_basic',
        operation_type: '编辑基本信息',
        operated_at: new Date().toISOString(),
        operator_name: '-',
        content: `request_id: ${String(updatedPayload?.request_id || '-')}`
      };
      setLatestCustomerActionById((previous) => ({
        ...previous,
        [normalizedCustomerId]: latestAction
      }));
      notifySuccess('客户基本信息更新成功');
      setCustomerBasicEditOpen(false);
      setCustomerBasicEditTarget(null);
      refreshCustomerTable();

      const detailCustomerId = String(customerDetail?.customer_id || '').trim();
      if (customerDetailOpen && detailCustomerId === normalizedCustomerId) {
        void openCustomerDetail(normalizedCustomerId, latestAction);
      }
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '编辑客户基本信息失败');
    } finally {
      setCustomerBasicEditSubmitting(false);
    }
  }, [
    api,
    customerBasicEditForm,
    customerBasicEditTarget,
    customerDetail,
    customerDetailOpen,
    notifyError,
    notifySuccess,
    openCustomerDetail,
    refreshCustomerTable
  ]);

  const handleSubmitCustomerRealnameEdit = useCallback(async () => {
    try {
      const values = await customerRealnameEditForm.validateFields();
      const normalizedCustomerId = String(
        customerRealnameEditTarget?.customer_id
        || values.customer_id
        || customerDetail?.customer_id
        || ''
      ).trim();
      if (!normalizedCustomerId) {
        return;
      }
      const normalizedNickname = String(
        customerRealnameEditTarget?.nickname
        || customerDetail?.nickname
        || ''
      ).trim();
      const normalizedSource = normalizeCustomerSource(
        customerRealnameEditTarget?.source
        || customerDetail?.source
      );
      if (!normalizedNickname || !normalizedSource) {
        throw new Error('缺少客户基础信息，无法提交编辑');
      }
      setCustomerRealnameEditSubmitting(true);
      const updatedPayload = await api.updateCustomer({
        customerId: normalizedCustomerId,
        payload: {
          nickname: normalizedNickname,
          source: normalizedSource,
          real_name: toNullableString(values.real_name),
          school: toNullableString(values.school),
          class_name: toNullableString(values.class_name),
          relation: toNullableString(values.relation),
          phone: toNullableString(values.phone),
          address: toNullableString(values.address)
        }
      });
      const latestAction = {
        action: 'update_realname',
        operation_type: '编辑实名信息',
        operated_at: new Date().toISOString(),
        operator_name: '-',
        content: `request_id: ${String(updatedPayload?.request_id || '-')}`
      };
      setLatestCustomerActionById((previous) => ({
        ...previous,
        [normalizedCustomerId]: latestAction
      }));
      notifySuccess('客户实名信息更新成功');
      setCustomerRealnameEditOpen(false);
      setCustomerRealnameEditTarget(null);
      refreshCustomerTable();

      const detailCustomerId = String(customerDetail?.customer_id || '').trim();
      if (customerDetailOpen && detailCustomerId === normalizedCustomerId) {
        void openCustomerDetail(normalizedCustomerId, latestAction);
      }
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, '编辑客户实名信息失败');
    } finally {
      setCustomerRealnameEditSubmitting(false);
    }
  }, [
    api,
    customerDetail,
    customerDetailOpen,
    customerRealnameEditForm,
    customerRealnameEditTarget,
    notifyError,
    notifySuccess,
    openCustomerDetail,
    refreshCustomerTable
  ]);

  const customerTableRequest = useCallback(async (params) => {
    if (!activeScope) {
      return {
        data: [],
        total: 0,
        success: true
      };
    }

    const page = Math.max(1, Number(params?.current || 1));
    const pageSize = Math.max(1, Number(params?.pageSize || 10));
    const payload = await api.listCustomers({
      page,
      pageSize,
      scope: activeScope,
      wechat_id: customerFilters.wechat_id,
      account_ids: customerFilters.account_ids,
      nickname: customerFilters.nickname,
      source: customerFilters.source,
      real_name: customerFilters.real_name,
      phone: customerFilters.phone,
      status: customerFilters.status,
      created_time_start: customerFilters.created_time_start,
      created_time_end: customerFilters.created_time_end
    });

    const sourceCustomers = Array.isArray(payload?.customers)
      ? payload.customers
      : (Array.isArray(payload?.items) ? payload.items : []);
    const data = sourceCustomers
      .map((customer) => normalizeCustomerRecord(customer))
      .map((customer) => ({ ...customer, key: customer.customer_id }));

    let total = Number(payload?.total);
    if (!Number.isFinite(total)) {
      total = (page - 1) * pageSize + sourceCustomers.length;
      if (sourceCustomers.length === pageSize) {
        total += 1;
      }
    }

    return {
      data,
      total,
      success: true
    };
  }, [
    activeScope,
    api,
    customerFilters.account_ids,
    customerFilters.created_time_end,
    customerFilters.created_time_start,
    customerFilters.nickname,
    customerFilters.phone,
    customerFilters.real_name,
    customerFilters.source,
    customerFilters.status,
    customerFilters.wechat_id,
    customerTableRefreshToken
  ]);

  const customerTableQueryKey = useMemo(
    () => [
      activeScope,
      customerFilters.wechat_id,
      customerFilters.account_ids.join(','),
      customerFilters.nickname,
      customerFilters.source,
      customerFilters.real_name,
      customerFilters.phone,
      customerFilters.status,
      customerFilters.created_time_start,
      customerFilters.created_time_end,
      customerTableRefreshToken
    ].join('|'),
    [
      activeScope,
      customerFilters.account_ids,
      customerFilters.created_time_end,
      customerFilters.created_time_start,
      customerFilters.nickname,
      customerFilters.phone,
      customerFilters.real_name,
      customerFilters.source,
      customerFilters.status,
      customerFilters.wechat_id,
      customerTableRefreshToken
    ]
  );

  const customerColumns = useMemo(
    () => [
      {
        title: '客户ID',
        dataIndex: 'customer_id',
        key: 'customer_id',
        width: 220,
        render: (value) => (
          <span data-testid={`tenant-customer-id-${String(value || '').trim() || '-'}`}>
            {String(value || '').trim() || '-'}
          </span>
        )
      },
      {
        title: '所属账号',
        dataIndex: 'account_label',
        key: 'account_label',
        width: 220,
        render: (value, record) =>
          String(value || '').trim()
          || accountLabelById[String(record?.account_id || '').trim()]
          || toAccountDisplayLabel({
            accountId: record?.account_id,
            accountNickname: record?.account_nickname,
            accountWechatId: record?.account_wechat_id,
            fallbackToAccountId: true
          })
          || '-'
      },
      {
        title: '微信号',
        dataIndex: 'wechat_id',
        key: 'wechat_id',
        width: 180,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '昵称',
        dataIndex: 'nickname',
        key: 'nickname',
        width: 160,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '来源',
        dataIndex: 'source',
        key: 'source',
        width: 120,
        render: (value) => customerSourceLabel(value)
      },
      {
        title: '学校',
        dataIndex: 'school',
        key: 'school',
        width: 180,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '班级',
        dataIndex: 'class_name',
        key: 'class_name',
        width: 160,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '姓名',
        dataIndex: 'real_name',
        key: 'real_name',
        width: 120,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '关系',
        dataIndex: 'relation',
        key: 'relation',
        width: 140,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '联系电话',
        dataIndex: 'phone',
        key: 'phone',
        width: 160,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        width: 100,
        render: (value) => customerStatusLabel(value)
      },
      {
        title: '创建时间',
        dataIndex: 'created_at',
        key: 'created_at',
        width: 180,
        render: (value) => formatDateTimeMinute(value)
      }
    ],
    [accountLabelById]
  );

  const customerDetailCustomerId = String(
    customerDetail?.customer_id
    || customerDetailTargetId
    || ''
  ).trim();
  const customerDetailOperationLogs = useMemo(
    () => normalizeCustomerOperationLogs(customerDetail?.operation_logs),
    [customerDetail]
  );

  if (!accessToken) {
    return (
      <section data-testid="tenant-customers-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载客户资料。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="tenant-customers-module" style={{ display: 'grid', gap: 12 }}>
      {messageContextHolder}

      {visibleScopes.length > 0 ? (
        <Tabs
          activeKey={activeScope}
          style={{ margin: '-12px 0 0 0' }}
          tabBarStyle={{ margin: '0 0 12px 0' }}
          onChange={(scope) => {
            setActiveScope(scope);
            refreshCustomerTable();
          }}
          items={visibleScopes.map((scope) => ({
            key: scope.key,
            label: <span data-testid={scope.testId}>{scope.label}</span>
          }))}
        />
      ) : (
        <Alert
          type="warning"
          showIcon
          message="当前角色缺少客户范围权限，无法访问客户列表。"
        />
      )}

      {visibleScopes.length > 0 ? (
        <>
          <CustomFilter
            form={customerFilterForm}
            initialValues={CUSTOMER_FILTER_INITIAL_VALUES}
            onFinish={(values) => {
              const createdRange = Array.isArray(values.created_time) ? values.created_time : [];
              const [createdStart, createdEnd] = createdRange;
              setCustomerFilters({
                wechat_id: String(values.wechat_id || '').trim(),
                account_ids: toStringList(values.account_ids),
                nickname: String(values.nickname || '').trim(),
                source: normalizeCustomerSource(values.source),
                real_name: String(values.real_name || '').trim(),
                phone: String(values.phone || '').trim(),
                status: normalizeCustomerStatus(values.status),
                created_time_start:
                  createdStart && typeof createdStart.format === 'function'
                    ? createdStart.format('YYYY-MM-DD HH:mm:ss')
                    : '',
                created_time_end:
                  createdEnd && typeof createdEnd.format === 'function'
                    ? createdEnd.format('YYYY-MM-DD HH:mm:ss')
                    : ''
              });
              refreshCustomerTable();
            }}
            onReset={() => {
              setCustomerFilters({
                wechat_id: '',
                account_ids: [],
                nickname: '',
                source: '',
                real_name: '',
                phone: '',
                status: '',
                created_time_start: '',
                created_time_end: ''
              });
              refreshCustomerTable();
            }}
          >
            <Form.Item label="所属账号" name="account_ids">
              <Select
                data-testid="tenant-customer-filter-account-ids"
                mode="multiple"
                allowClear
                showSearch
                optionFilterProp="label"
                options={accountOptions}
                loading={accountOptionsLoading}
                placeholder="请选择所属账号（可多选）"
              />
            </Form.Item>
            <Form.Item label="微信号" name="wechat_id">
              <Input
                data-testid="tenant-customer-filter-wechat-id"
                placeholder="请输入微信号（精确）"
                allowClear
              />
            </Form.Item>
            <Form.Item label="昵称" name="nickname">
              <Input
                data-testid="tenant-customer-filter-nickname"
                placeholder="请输入昵称（模糊）"
                allowClear
              />
            </Form.Item>
            <Form.Item label="来源" name="source">
              <Select
                data-testid="tenant-customer-filter-source"
                options={CUSTOMER_SOURCE_OPTIONS}
                allowClear
                placeholder="请选择来源"
              />
            </Form.Item>
            <Form.Item label="姓名" name="real_name">
              <Input
                data-testid="tenant-customer-filter-real-name"
                placeholder="请输入姓名（模糊）"
                allowClear
              />
            </Form.Item>
            <Form.Item label="联系电话" name="phone">
              <Input
                data-testid="tenant-customer-filter-phone"
                placeholder="请输入联系电话（精确）"
                allowClear
              />
            </Form.Item>
            <Form.Item label="状态" name="status">
              <Select
                data-testid="tenant-customer-filter-status"
                options={CUSTOMER_STATUS_OPTIONS}
                allowClear
                placeholder="请选择状态"
              />
            </Form.Item>
            <Form.Item label="创建时间" name="created_time">
              <DatePicker.RangePicker
                data-testid="tenant-customer-filter-created-time"
                showTime
                placeholder={['开始时间', '结束时间']}
                format="YYYY-MM-DD HH:mm:ss"
              />
            </Form.Item>
          </CustomFilter>

          <CustomPanelTable
            key={customerTableQueryKey}
            title="客户列表"
            rowKey="customer_id"
            columns={customerColumns}
            request={customerTableRequest}
            onRow={(record) => ({
              onClick: () => {
                void openCustomerDetail(record.customer_id);
              },
              style: { cursor: 'pointer' }
            })}
            extra={canOperateCustomerManagement ? (
              <Button
                data-testid="tenant-customer-create-open"
                type="primary"
                onClick={() => {
                  openCustomerCreateModal();
                }}
              >
                新建
              </Button>
            ) : null}
          />
        </>
      ) : null}

      <Modal
        open={customerCreateOpen}
        title="新建客户"
        onCancel={() => {
          setCustomerCreateOpen(false);
        }}
        onOk={() => {
          void handleSubmitCustomerCreate();
        }}
        confirmLoading={customerCreateSubmitting}
        okButtonProps={{
          disabled: customerCreateSubmitting,
          'data-testid': 'tenant-customer-create-confirm'
        }}
        cancelButtonProps={{
          disabled: customerCreateSubmitting
        }}
        destroyOnClose
      >
        <CustomForm
          form={customerCreateForm}
          initialValues={CUSTOMER_CREATE_INITIAL_VALUES}
          layout="vertical"
          submitter={false}
        >
          <CustomForm.Item
            label="所属账号"
            name="account_id"
            rules={[
              { required: true, message: '请选择所属账号' }
            ]}
          >
            <Select
              data-testid="tenant-customer-create-account-id"
              showSearch
              optionFilterProp="label"
              options={accountOptions}
              loading={accountOptionsLoading}
              placeholder="请选择所属账号"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="微信号"
            name="wechat_id"
            rules={[
              { max: 128, message: '微信号长度不能超过 128' }
            ]}
          >
            <Input
              data-testid="tenant-customer-create-wechat-id"
              maxLength={128}
              placeholder="请输入微信号"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="昵称"
            name="nickname"
            rules={[
              { required: true, message: '请输入昵称' },
              { max: 128, message: '昵称长度不能超过 128' }
            ]}
          >
            <Input
              data-testid="tenant-customer-create-nickname"
              maxLength={128}
              placeholder="请输入昵称"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="来源"
            name="source"
            rules={[
              { required: true, message: '请选择来源' }
            ]}
          >
            <Select
              data-testid="tenant-customer-create-source"
              options={CUSTOMER_SOURCE_OPTIONS}
              placeholder="请选择来源"
            />
          </CustomForm.Item>
          <CustomForm.Item label="姓名" name="real_name">
            <Input data-testid="tenant-customer-create-real-name" placeholder="请输入姓名" maxLength={64} />
          </CustomForm.Item>
          <CustomForm.Item label="学校" name="school">
            <Input data-testid="tenant-customer-create-school" placeholder="请输入学校" maxLength={128} />
          </CustomForm.Item>
          <CustomForm.Item label="班级" name="class_name">
            <Input data-testid="tenant-customer-create-class-name" placeholder="请输入班级" maxLength={128} />
          </CustomForm.Item>
          <CustomForm.Item label="关系" name="relation">
            <Input data-testid="tenant-customer-create-relation" placeholder="请输入关系" maxLength={128} />
          </CustomForm.Item>
          <CustomForm.Item label="联系电话" name="phone">
            <Input data-testid="tenant-customer-create-phone" placeholder="请输入联系电话" maxLength={32} />
          </CustomForm.Item>
          <CustomForm.Item label="地址" name="address">
            <TextArea
              data-testid="tenant-customer-create-address"
              rows={3}
              maxLength={255}
              placeholder="请输入地址"
            />
          </CustomForm.Item>
        </CustomForm>
      </Modal>

      <Modal
        open={customerBasicEditOpen}
        title="编辑"
        onCancel={() => {
          setCustomerBasicEditOpen(false);
          setCustomerBasicEditTarget(null);
          setCustomerBasicEditLoading(false);
        }}
        onOk={() => {
          void handleSubmitCustomerBasicEdit();
        }}
        confirmLoading={customerBasicEditSubmitting}
        okButtonProps={{
          disabled: customerBasicEditSubmitting || customerBasicEditLoading,
          'data-testid': 'tenant-customer-basic-confirm'
        }}
        cancelButtonProps={{
          disabled: customerBasicEditSubmitting
        }}
        destroyOnClose
      >
        {customerBasicEditLoading ? (
          <Text type="secondary">加载中...</Text>
        ) : (
          <CustomForm
            form={customerBasicEditForm}
            initialValues={CUSTOMER_BASIC_EDIT_INITIAL_VALUES}
            layout="vertical"
            submitter={false}
          >
            <CustomForm.Item label="客户ID" name="customer_id">
              <Input data-testid="tenant-customer-basic-customer-id" disabled />
            </CustomForm.Item>
            <CustomForm.Item label="所属账号" name="account_label">
              <Input data-testid="tenant-customer-basic-account-label" disabled />
            </CustomForm.Item>
            <CustomForm.Item label="微信号" name="wechat_id">
              <Input data-testid="tenant-customer-basic-wechat-id" disabled />
            </CustomForm.Item>
            <CustomForm.Item label="昵称" name="nickname">
              <Input data-testid="tenant-customer-basic-nickname" disabled />
            </CustomForm.Item>
            <CustomForm.Item
              label="来源"
              name="source"
              rules={[
                { required: true, message: '请选择来源' }
              ]}
            >
              <Select
                data-testid="tenant-customer-basic-source"
                options={CUSTOMER_SOURCE_OPTIONS}
                placeholder="请选择来源"
              />
            </CustomForm.Item>
          </CustomForm>
        )}
      </Modal>

      <Modal
        open={customerRealnameEditOpen}
        title="编辑"
        onCancel={() => {
          setCustomerRealnameEditOpen(false);
          setCustomerRealnameEditTarget(null);
          setCustomerRealnameEditLoading(false);
        }}
        onOk={() => {
          void handleSubmitCustomerRealnameEdit();
        }}
        confirmLoading={customerRealnameEditSubmitting}
        okButtonProps={{
          disabled: customerRealnameEditSubmitting || customerRealnameEditLoading,
          'data-testid': 'tenant-customer-realname-confirm'
        }}
        cancelButtonProps={{
          disabled: customerRealnameEditSubmitting
        }}
        destroyOnClose
      >
        {customerRealnameEditLoading ? (
          <Text type="secondary">加载中...</Text>
        ) : (
          <CustomForm
            form={customerRealnameEditForm}
            initialValues={CUSTOMER_REALNAME_EDIT_INITIAL_VALUES}
            layout="vertical"
            submitter={false}
          >
            <CustomForm.Item label="客户ID" name="customer_id">
              <Input data-testid="tenant-customer-realname-customer-id" disabled />
            </CustomForm.Item>
            <CustomForm.Item label="姓名" name="real_name">
              <Input data-testid="tenant-customer-realname-name" maxLength={64} placeholder="请输入姓名" />
            </CustomForm.Item>
            <CustomForm.Item label="学校" name="school">
              <Input data-testid="tenant-customer-realname-school" maxLength={128} placeholder="请输入学校" />
            </CustomForm.Item>
            <CustomForm.Item label="班级" name="class_name">
              <Input data-testid="tenant-customer-realname-class-name" maxLength={128} placeholder="请输入班级" />
            </CustomForm.Item>
            <CustomForm.Item label="关系" name="relation">
              <Input data-testid="tenant-customer-realname-relation" maxLength={128} placeholder="请输入关系" />
            </CustomForm.Item>
            <CustomForm.Item label="联系电话" name="phone">
              <Input data-testid="tenant-customer-realname-phone" maxLength={32} placeholder="请输入联系电话" />
            </CustomForm.Item>
            <CustomForm.Item label="地址" name="address">
              <TextArea
                data-testid="tenant-customer-realname-address"
                rows={3}
                maxLength={255}
                placeholder="请输入地址"
              />
            </CustomForm.Item>
          </CustomForm>
        )}
      </Modal>

      <Drawer
        open={customerDetailOpen}
        title={customerDetailCustomerId ? `客户ID:${customerDetailCustomerId}` : '客户ID:-'}
        size="large"
        onClose={() => {
          setCustomerDetailOpen(false);
          setCustomerDetail(null);
          setCustomerDetailTargetId('');
        }}
        destroyOnClose
      >
        <div data-testid="tenant-customer-detail-drawer" style={{ display: 'grid', gap: 12 }}>
          {customerDetailLoading ? (
            <Text>加载中...</Text>
          ) : customerDetail ? (
            <div style={{ display: 'grid', gap: 12 }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <Avatar
                  size={56}
                  icon={<UserOutlined />}
                  style={{ backgroundColor: token.colorPrimary, color: token.colorWhite }}
                />
                <div style={{ display: 'grid', gap: 2 }}>
                  <Text strong>{String(customerDetail?.nickname || '').trim() || '-'}</Text>
                  <Text type="secondary">微信号：{String(customerDetail?.wechat_id || '').trim() || '-'}</Text>
                </div>
              </div>

              <Tabs
                items={[
                  {
                    key: 'overview',
                    label: '概览',
                    children: (
                      <div style={{ display: 'grid', gap: 12 }}>
                        <div style={{ display: 'grid', gap: 8 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Text strong>基本信息</Text>
                            {canOperateCustomerManagement ? (
                              <Button
                                type="text"
                                icon={<EditOutlined />}
                                data-testid="tenant-customer-overview-edit-basic"
                                onClick={() => {
                                  void openCustomerBasicEditModal(customerDetail || {});
                                }}
                              />
                            ) : null}
                          </div>
                          <Descriptions column={2}>
                            <Descriptions.Item label="所属账号">
                              {resolveCustomerAccountLabel({
                                customer: customerDetail || {},
                                accountLabelById
                              }) || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="微信号">
                              {String(customerDetail?.wechat_id || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="昵称">
                              {String(customerDetail?.nickname || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="来源">
                              {customerSourceLabel(customerDetail?.source)}
                            </Descriptions.Item>
                            <Descriptions.Item label="状态">
                              {customerStatusLabel(customerDetail?.status)}
                            </Descriptions.Item>
                          </Descriptions>
                        </div>

                        <div style={{ display: 'grid', gap: 8 }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <Text strong>实名信息</Text>
                            {canOperateCustomerManagement ? (
                              <Button
                                type="text"
                                icon={<EditOutlined />}
                                data-testid="tenant-customer-overview-edit-realname"
                                onClick={() => {
                                  void openCustomerRealnameEditModal(customerDetail || {});
                                }}
                              />
                            ) : null}
                          </div>
                          <Descriptions column={2}>
                            <Descriptions.Item label="姓名">
                              {String(customerDetail?.real_name || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="学校">
                              {String(customerDetail?.school || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="班级">
                              {String(customerDetail?.class_name || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="关系">
                              {String(customerDetail?.relation || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="联系电话">
                              {String(customerDetail?.phone || '').trim() || '-'}
                            </Descriptions.Item>
                            <Descriptions.Item label="地址">
                              {String(customerDetail?.address || '').trim() || '-'}
                            </Descriptions.Item>
                          </Descriptions>
                        </div>

                        <Descriptions title="系统信息" column={2}>
                          <Descriptions.Item label="创建人">
                            {String(customerDetail?.created_by_name || '').trim()
                              || memberNameByUserId[String(customerDetail?.created_by_user_id || '').trim()]
                              || '-'}
                          </Descriptions.Item>
                          <Descriptions.Item label="创建时间">
                            {formatDateTimeMinute(customerDetail?.created_at)}
                          </Descriptions.Item>
                          <Descriptions.Item label="最新更新">
                            {formatDateTimeMinute(customerDetail?.updated_at)}
                          </Descriptions.Item>
                        </Descriptions>
                      </div>
                    )
                  },
                  {
                    key: 'timeline',
                    label: '操作记录',
                    children: customerDetailOperationLogs.length > 0 ? (
                      <Timeline
                        items={customerDetailOperationLogs.map((log, index) => ({
                          key: `${log.operation_type}-${log.operated_at}-${index}`,
                          children: (
                            <div data-testid={`tenant-customer-log-${index}`} style={{ display: 'grid', gap: 2 }}>
                              <Text strong>{log.operation_type || '-'}</Text>
                              <Text type="secondary">
                                {formatDateTimeMinute(log.operated_at)}
                                <span style={{ margin: '0 8px' }}>·</span>
                                {log.operator_name || '-'}
                              </Text>
                              <Text>{log.content || '-'}</Text>
                            </div>
                          )
                        }))}
                      />
                    ) : (
                      <Text type="secondary">暂无操作记录</Text>
                    )
                  }
                ]}
              />
            </div>
          ) : (
            <Text type="secondary">暂无详情数据</Text>
          )}
        </div>
      </Drawer>
    </section>
  );
}
