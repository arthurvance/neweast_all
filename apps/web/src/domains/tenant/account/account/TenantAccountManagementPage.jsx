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
import { UserOutlined } from '@ant-design/icons';
import CustomCardTable from '../../../../components/CustomCardTable';
import CustomFilter from '../../../../components/CustomFilter';
import CustomForm from '../../../../components/CustomForm';
import {
  createTenantManagementApi,
  toProblemMessage
} from '../../../../api/tenant-management.mjs';
import { formatDateTimeMinute } from '../../../../utils/date-time.mjs';

const { Text } = Typography;

const ACCOUNT_STATUS_OPTIONS = [
  { label: '全部', value: '' },
  { label: '启用', value: 'enabled' },
  { label: '禁用', value: 'disabled' }
];
const ACCOUNT_FILTER_INITIAL_VALUES = Object.freeze({
  wechat_id: '',
  nickname: '',
  owner_keyword: '',
  assistant_keyword: '',
  status: '',
  created_time: []
});
const ACCOUNT_FORM_INITIAL_VALUES = Object.freeze({
  account_id: '',
  wechat_id: '',
  nickname: '',
  owner_membership_id: undefined,
  assistant_membership_ids: []
});

const normalizeStatus = (status) => {
  const normalizedStatus = String(status || '').trim().toLowerCase();
  if (normalizedStatus === 'active' || normalizedStatus === 'enabled') {
    return 'enabled';
  }
  if (normalizedStatus === 'inactive' || normalizedStatus === 'disabled') {
    return 'disabled';
  }
  return '';
};
const statusDisplayLabel = (status) => {
  const normalizedStatus = normalizeStatus(status);
  if (normalizedStatus === 'enabled') {
    return '启用';
  }
  if (normalizedStatus === 'disabled') {
    return '禁用';
  }
  return '-';
};
const statusToggleLabel = (status) => (normalizeStatus(status) === 'enabled' ? '禁用' : '启用');
const statusToggleValue = (status) => (normalizeStatus(status) === 'enabled' ? 'disabled' : 'enabled');
const isActiveMemberStatus = (status) =>
  String(status || '').trim().toLowerCase() === 'active';

const toStringList = (source = []) =>
  [...new Set(
    (Array.isArray(source) ? source : [])
      .map((value) => String(value || '').trim())
      .filter(Boolean)
  )];

const toAssistantNames = (account = {}) => {
  const rawAssistantNames = account?.assistant_names;
  if (Array.isArray(rawAssistantNames)) {
    return toStringList(rawAssistantNames);
  }
  const rawAssistants = Array.isArray(account?.assistants) ? account.assistants : [];
  return toStringList(rawAssistants.map((assistant) => assistant?.name || assistant?.display_name));
};

const toAssistantMembershipIds = (account = {}) => {
  if (Array.isArray(account?.assistant_membership_ids)) {
    return toStringList(account.assistant_membership_ids);
  }
  const rawAssistants = Array.isArray(account?.assistants) ? account.assistants : [];
  return toStringList(rawAssistants.map((assistant) => assistant?.membership_id));
};

const normalizeAccountRecord = (account = {}) => ({
  account_id: String(account?.account_id || account?.accountId || '').trim(),
  wechat_id: String(account?.wechat_id || account?.wechatId || '').trim(),
  nickname: String(account?.nickname || '').trim(),
  avatar_url: String(account?.avatar_url || account?.avatarUrl || '').trim(),
  owner_name: String(
    account?.owner_name
    || account?.owner_display_name
    || account?.owner?.name
    || account?.owner?.display_name
    || ''
  ).trim(),
  owner_membership_id: String(
    account?.owner_membership_id
    || account?.owner?.membership_id
    || ''
  ).trim(),
  assistant_names: toAssistantNames(account),
  assistant_membership_ids: toAssistantMembershipIds(account),
  customer_count: Number.isFinite(Number(account?.customer_count))
    ? Number(account.customer_count)
    : 0,
  group_chat_count: Number.isFinite(Number(account?.group_chat_count))
    ? Number(account.group_chat_count)
    : 0,
  status: normalizeStatus(account?.status),
  created_by_user_id: String(
    account?.created_by_user_id || account?.createdByUserId || ''
  ).trim(),
  created_by_name: String(
    account?.created_by_name || account?.createdByName || ''
  ).trim(),
  created_at: String(account?.created_at || account?.createdAt || '').trim(),
  updated_at: String(account?.updated_at || account?.updatedAt || '').trim(),
  operation_logs: Array.isArray(account?.operation_logs)
    ? account.operation_logs
    : (Array.isArray(account?.logs) ? account.logs : [])
});

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

const OPERATION_TYPE_LABEL_MAP = {
  create: '新建账号',
  edit: '编辑账号',
  update: '更新账号',
  status: '状态变更'
};

const normalizeOperationLogs = (logs = []) =>
  (Array.isArray(logs) ? logs : [])
    .map((log) => ({
      operation_type: OPERATION_TYPE_LABEL_MAP[log?.operation_type || log?.type] || String(log?.operation_type || log?.type || '').trim() || '操作',
      operated_at: String(log?.operated_at || log?.operation_time || log?.created_at || '').trim(),
      operator_name: String(log?.operator_name || log?.operator || '').trim() || '-',
      content: String(log?.content || log?.detail || '-').trim() || '-'
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

const readPermissionFlag = (permissionContext, snakeCase, camelCase) =>
  Boolean(permissionContext?.[snakeCase] || permissionContext?.[camelCase]);

const toMemberOptionLabel = ({
  displayName = '',
  phone = '',
  membershipId = ''
} = {}) => {
  const normalizedDisplayName = String(displayName || '').trim();
  const normalizedPhone = String(phone || '').trim();
  const normalizedMembershipId = String(membershipId || '').trim();
  if (normalizedDisplayName && normalizedPhone) {
    return `${normalizedDisplayName}（${normalizedPhone}）`;
  }
  if (normalizedDisplayName) {
    return normalizedDisplayName;
  }
  if (normalizedPhone) {
    return normalizedPhone;
  }
  return normalizedMembershipId;
};

export default function TenantAccountManagementPage({
  accessToken,
  tenantPermissionContext = null
}) {
  const { token } = theme.useToken();
  const api = useMemo(
    () => createTenantManagementApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [accountFilterForm] = Form.useForm();
  const [accountEditForm] = Form.useForm();

  const [accountFilters, setAccountFilters] = useState({
    wechat_id: '',
    nickname: '',
    owner_keyword: '',
    assistant_keyword: '',
    status: '',
    created_time_start: '',
    created_time_end: ''
  });
  const [accountTableRefreshToken, setAccountTableRefreshToken] = useState(0);
  const [memberOptions, setMemberOptions] = useState([]);
  const [memberOptionsLoading, setMemberOptionsLoading] = useState(false);
  const [memberLabelByMembershipId, setMemberLabelByMembershipId] = useState({});
  const [accountEditOpen, setAccountEditOpen] = useState(false);
  const [accountEditMode, setAccountEditMode] = useState('create');
  const [accountEditLoading, setAccountEditLoading] = useState(false);
  const [accountEditSubmitting, setAccountEditSubmitting] = useState(false);
  const [accountEditTarget, setAccountEditTarget] = useState(null);
  const [statusActionSubmittingByAccountId, setStatusActionSubmittingByAccountId] = useState({});
  const [accountDetailOpen, setAccountDetailOpen] = useState(false);
  const [accountDetailLoading, setAccountDetailLoading] = useState(false);
  const [accountDetail, setAccountDetail] = useState(null);
  const [latestAccountActionById, setLatestAccountActionById] = useState({});
  const hasTenantPermissionContext =
    tenantPermissionContext && typeof tenantPermissionContext === 'object';
  const canOperateAccountManagement =
    hasTenantPermissionContext
    && readPermissionFlag(
      tenantPermissionContext,
      'can_operate_account_management',
      'canOperateAccountManagement'
    );

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

  const refreshAccountTable = useCallback(() => {
    setAccountTableRefreshToken((previous) => previous + 1);
  }, []);

  const loadMemberOptions = useCallback(async () => {
    setMemberOptionsLoading(true);
    try {
      const nextOptions = [];
      const nextMemberLabelByMembershipId = {};
      let page = 1;
      const pageSize = 200;
      while (page <= 200) {
        const payload = await api.listUsers({
          page,
          pageSize
        });
        const members = Array.isArray(payload?.members) ? payload.members : [];
        for (const member of members) {
          const membershipId = String(member?.membership_id || '').trim();
          if (!membershipId || nextMemberLabelByMembershipId[membershipId]) {
            continue;
          }
          if (!isActiveMemberStatus(member?.status)) {
            continue;
          }
          const displayName = String(member?.display_name || '').trim();
          const phone = String(member?.phone || '').trim();
          const label = toMemberOptionLabel({
            displayName,
            phone,
            membershipId
          });
          nextMemberLabelByMembershipId[membershipId] = label;
          nextOptions.push({
            value: membershipId,
            label
          });
        }
        if (members.length < pageSize) {
          break;
        }
        page += 1;
      }
      nextOptions.sort((left, right) =>
        String(left.label || '').localeCompare(String(right.label || ''), 'zh-Hans-CN')
      );
      setMemberOptions(nextOptions);
      setMemberLabelByMembershipId(nextMemberLabelByMembershipId);
    } catch (error) {
      setMemberOptions([]);
      setMemberLabelByMembershipId({});
      notifyError(error, '加载组织成员列表失败');
    } finally {
      setMemberOptionsLoading(false);
    }
  }, [api, notifyError]);

  useEffect(() => {
    if (!accessToken) {
      setMemberOptions([]);
      setMemberLabelByMembershipId({});
      return;
    }
    void loadMemberOptions();
  }, [accessToken, loadMemberOptions]);

  const openAccountDetail = useCallback(async (accountId, latestActionOverride = null) => {
    const normalizedAccountId = String(accountId || '').trim();
    if (!normalizedAccountId) {
      return;
    }
    setAccountDetailOpen(true);
    setAccountDetailLoading(true);
    try {
      const payload = await api.getAccountDetail(normalizedAccountId);
      const normalizedAccount = normalizeAccountRecord(payload);
      if (normalizedAccount.operation_logs.length < 1) {
        const latestAction = latestActionOverride || latestAccountActionById[normalizedAccountId] || null;
        if (latestAction) {
          normalizedAccount.operation_logs = [
            {
              operation_type: String(latestAction.operation_type || latestAction.action || '操作').trim() || '操作',
              operated_at: String(latestAction.operated_at || latestAction.time || '').trim(),
              operator_name: String(latestAction.operator_name || latestAction.operator || '-').trim() || '-',
              content: String(latestAction.content || latestAction.result || '-').trim() || '-'
            }
          ];
        }
      }
      setAccountDetail(normalizedAccount);
    } catch (error) {
      setAccountDetail(null);
      notifyError(error, '加载账号详情失败');
    } finally {
      setAccountDetailLoading(false);
    }
  }, [api, latestAccountActionById, notifyError]);

  const openAccountCreateModal = useCallback(async () => {
    if (!canOperateAccountManagement) {
      return;
    }
    setAccountEditMode('create');
    setAccountEditTarget(null);
    setAccountEditLoading(false);
    accountEditForm.setFieldsValue(ACCOUNT_FORM_INITIAL_VALUES);
    setAccountEditOpen(true);
    if (memberOptions.length < 1 && !memberOptionsLoading) {
      await loadMemberOptions();
    }
  }, [
    accountEditForm,
    canOperateAccountManagement,
    loadMemberOptions,
    memberOptions.length,
    memberOptionsLoading
  ]);

  const openAccountEditModal = useCallback(async (record = {}) => {
    if (!canOperateAccountManagement) {
      return;
    }
    const normalizedRecord = normalizeAccountRecord(record);
    const normalizedAccountId = String(normalizedRecord.account_id || '').trim();
    if (!normalizedAccountId) {
      return;
    }
    setAccountEditMode('edit');
    setAccountEditTarget(normalizedRecord);
    setAccountEditLoading(true);
    accountEditForm.setFieldsValue({
      account_id: normalizedRecord.account_id,
      wechat_id: normalizedRecord.wechat_id,
      nickname: normalizedRecord.nickname,
      owner_membership_id: normalizedRecord.owner_membership_id || undefined,
      assistant_membership_ids: normalizedRecord.assistant_membership_ids
    });
    setAccountEditOpen(true);

    if (memberOptions.length < 1 && !memberOptionsLoading) {
      await loadMemberOptions();
    }

    try {
      const detailPayload = await api.getAccountDetail(normalizedAccountId);
      const normalizedDetail = normalizeAccountRecord(detailPayload);
      setAccountEditTarget(normalizedDetail);
      accountEditForm.setFieldsValue({
        account_id: normalizedDetail.account_id,
        wechat_id: normalizedDetail.wechat_id,
        nickname: normalizedDetail.nickname,
        owner_membership_id: normalizedDetail.owner_membership_id || undefined,
        assistant_membership_ids: normalizedDetail.assistant_membership_ids
      });
    } catch (error) {
      notifyError(error, '加载账号详情失败，已回退为行数据');
    } finally {
      setAccountEditLoading(false);
    }
  }, [
    accountEditForm,
    api,
    canOperateAccountManagement,
    loadMemberOptions,
    memberOptions.length,
    memberOptionsLoading,
    notifyError
  ]);

  const toAccountWritePayload = (values = {}) => ({
    wechat_id: String(values.wechat_id || '').trim(),
    nickname: String(values.nickname || '').trim(),
    owner_membership_id: String(values.owner_membership_id || '').trim(),
    assistant_membership_ids: toStringList(values.assistant_membership_ids)
  });

  const handleSubmitAccountEdit = useCallback(async () => {
    try {
      const values = await accountEditForm.validateFields();
      const payload = toAccountWritePayload(values);
      setAccountEditSubmitting(true);

      if (accountEditMode === 'create') {
        const createdPayload = await api.createAccount(payload);
        const createdAccountId = String(createdPayload?.account_id || createdPayload?.accountId || '').trim();
        const latestAction = {
          action: 'create',
          operation_type: '新建账号',
          operated_at: new Date().toISOString(),
          operator_name: '-',
          content: `request_id: ${String(createdPayload?.request_id || '-')}`
        };
        if (createdAccountId) {
          setLatestAccountActionById((previous) => ({
            ...previous,
            [createdAccountId]: latestAction
          }));
        }
        notifySuccess(`账号新建成功（request_id: ${createdPayload?.request_id || '-'}）`);
      } else {
        const normalizedAccountId = String(
          accountEditTarget?.account_id || accountEditForm.getFieldValue('account_id') || ''
        ).trim();
        const updatedPayload = await api.updateAccount({
          accountId: normalizedAccountId,
          payload
        });
        const latestAction = {
          action: 'edit',
          operation_type: '编辑账号',
          operated_at: new Date().toISOString(),
          operator_name: '-',
          content: `request_id: ${String(updatedPayload?.request_id || '-')}`
        };
        if (normalizedAccountId) {
          setLatestAccountActionById((previous) => ({
            ...previous,
            [normalizedAccountId]: latestAction
          }));
        }
        notifySuccess(`账号编辑成功（request_id: ${updatedPayload?.request_id || '-'}）`);

        const normalizedDetailAccountId = String(accountDetail?.account_id || '').trim();
        if (
          normalizedAccountId
          && accountDetailOpen
          && normalizedDetailAccountId === normalizedAccountId
        ) {
          void openAccountDetail(normalizedAccountId, latestAction);
        }
      }

      setAccountEditOpen(false);
      setAccountEditTarget(null);
      accountEditForm.resetFields();
      refreshAccountTable();
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      notifyError(error, accountEditMode === 'create' ? '新建账号失败' : '编辑账号失败');
    } finally {
      setAccountEditSubmitting(false);
    }
  }, [
    accountDetail,
    accountDetailOpen,
    accountEditForm,
    accountEditMode,
    accountEditTarget,
    api,
    notifyError,
    notifySuccess,
    openAccountDetail,
    refreshAccountTable
  ]);

  const handleToggleAccountStatus = useCallback(
    async (record, { refreshDetail = false } = {}) => {
      if (!canOperateAccountManagement) {
        return;
      }
      const normalizedRecord = normalizeAccountRecord(record);
      const normalizedAccountId = normalizedRecord.account_id;
      if (!normalizedAccountId) {
        return;
      }
      if (statusActionSubmittingByAccountId[normalizedAccountId]) {
        return;
      }
      try {
        setStatusActionSubmittingByAccountId((previous) => ({
          ...previous,
          [normalizedAccountId]: true
        }));
        const payload = await api.updateAccountStatus({
          accountId: normalizedAccountId,
          status: statusToggleValue(normalizedRecord.status)
        });
        const latestAction = {
          action: 'status',
          operation_type: '状态变更',
          operated_at: new Date().toISOString(),
          operator_name: '-',
          content: `${String(payload?.previous_status || '-')} -> ${String(payload?.current_status || '-')}`
        };
        setLatestAccountActionById((previous) => ({
          ...previous,
          [normalizedAccountId]: latestAction
        }));
        notifySuccess('操作成功');
        refreshAccountTable();

        const normalizedDetailAccountId = String(accountDetail?.account_id || '').trim();
        const shouldRefreshDetail = refreshDetail || (
          accountDetailOpen
          && normalizedDetailAccountId === normalizedAccountId
        );
        if (shouldRefreshDetail) {
          void openAccountDetail(normalizedAccountId, latestAction);
        }
      } catch (error) {
        notifyError(error, '更新账号状态失败');
      } finally {
        setStatusActionSubmittingByAccountId((previous) => ({
          ...previous,
          [normalizedAccountId]: false
        }));
      }
    },
    [
      accountDetail,
      accountDetailOpen,
      api,
      canOperateAccountManagement,
      notifyError,
      notifySuccess,
      openAccountDetail,
      refreshAccountTable,
      statusActionSubmittingByAccountId
    ]
  );

  const accountTableRequest = useCallback(async (params) => {
    const page = Math.max(1, Number(params?.current || 1));
    const pageSize = Math.max(1, Number(params?.pageSize || 10));
    const payload = await api.listAccounts({
      page,
      pageSize,
      wechat_id: accountFilters.wechat_id,
      nickname: accountFilters.nickname,
      owner_keyword: accountFilters.owner_keyword,
      assistant_keyword: accountFilters.assistant_keyword,
      status: accountFilters.status,
      created_time_start: accountFilters.created_time_start,
      created_time_end: accountFilters.created_time_end
    });

    const sourceAccounts = Array.isArray(payload?.accounts)
      ? payload.accounts
      : (Array.isArray(payload?.items) ? payload.items : []);
    const data = sourceAccounts
      .map((account) => normalizeAccountRecord(account))
      .map((account) => ({ ...account, key: account.account_id }));

    let total = Number(payload?.total);
    if (!Number.isFinite(total)) {
      total = (page - 1) * pageSize + sourceAccounts.length;
      if (sourceAccounts.length === pageSize) {
        total += 1;
      }
    }

    return {
      data,
      total,
      success: true
    };
  }, [
    accountFilters.assistant_keyword,
    accountFilters.created_time_end,
    accountFilters.created_time_start,
    accountFilters.nickname,
    accountFilters.owner_keyword,
    accountFilters.status,
    accountFilters.wechat_id,
    accountTableRefreshToken,
    api
  ]);

  const accountTableQueryKey = useMemo(
    () => [
      accountFilters.wechat_id,
      accountFilters.nickname,
      accountFilters.owner_keyword,
      accountFilters.assistant_keyword,
      accountFilters.status,
      accountFilters.created_time_start,
      accountFilters.created_time_end,
      accountTableRefreshToken
    ].join('|'),
    [
      accountFilters.assistant_keyword,
      accountFilters.created_time_end,
      accountFilters.created_time_start,
      accountFilters.nickname,
      accountFilters.owner_keyword,
      accountFilters.status,
      accountFilters.wechat_id,
      accountTableRefreshToken
    ]
  );

  const accountColumns = useMemo(
    () => [
      {
        title: '账号ID',
        dataIndex: 'account_id',
        key: 'account_id',
        width: 220,
        render: (value) => (
          <span data-testid={`tenant-account-id-${String(value || '').trim() || '-'}`}>
            {String(value || '').trim() || '-'}
          </span>
        )
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
        title: '负责人',
        dataIndex: 'owner_name',
        key: 'owner_name',
        width: 180,
        render: (value, record) => {
          const ownerName = String(value || '').trim();
          if (ownerName) {
            return ownerName;
          }
          const ownerMembershipId = String(record?.owner_membership_id || '').trim();
          if (!ownerMembershipId) {
            return '-';
          }
          return memberLabelByMembershipId[ownerMembershipId] || ownerMembershipId;
        }
      },
      {
        title: '协管人',
        dataIndex: 'assistant_names',
        key: 'assistant_names',
        width: 220,
        render: (value, record) => {
          const names = toStringList(value);
          if (names.length > 0) {
            return names.join('、');
          }
          const assistantMembershipIds = toStringList(record?.assistant_membership_ids);
          if (assistantMembershipIds.length < 1) {
            return '-';
          }
          return assistantMembershipIds
            .map((membershipId) => memberLabelByMembershipId[membershipId] || membershipId)
            .join('、');
        }
      },
      {
        title: '客户数',
        dataIndex: 'customer_count',
        key: 'customer_count',
        width: 110,
        render: (value) => Number.isFinite(Number(value)) ? Number(value) : 0
      },
      {
        title: '群聊数',
        dataIndex: 'group_chat_count',
        key: 'group_chat_count',
        width: 110,
        render: (value) => Number.isFinite(Number(value)) ? Number(value) : 0
      },
      {
        title: '状态',
        dataIndex: 'status',
        key: 'status',
        width: 110,
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
        width: 210,
        render: (_value, record) => {
          if (!canOperateAccountManagement) {
            return <Text type="secondary">仅查看</Text>;
          }
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
                data-testid={`tenant-account-status-${record.account_id}`}
                size="small"
                type="link"
                loading={Boolean(statusActionSubmittingByAccountId[record.account_id])}
                onClick={(event) => {
                  event.stopPropagation();
                  void handleToggleAccountStatus(record);
                }}
              >
                {statusToggleLabel(record.status)}
              </Button>
              <Button
                data-testid={`tenant-account-edit-${record.account_id}`}
                size="small"
                type="link"
                onClick={(event) => {
                  event.stopPropagation();
                  void openAccountEditModal(record);
                }}
              >
                编辑
              </Button>
            </Space>
          );
        }
      }
    ],
    [
      canOperateAccountManagement,
      handleToggleAccountStatus,
      memberLabelByMembershipId,
      openAccountEditModal,
      statusActionSubmittingByAccountId
    ]
  );

  const accountDetailAccountId = String(accountDetail?.account_id || '').trim();
  const accountDetailStatus = normalizeStatus(accountDetail?.status);
  const accountDetailNickname = String(accountDetail?.nickname || '').trim();
  const accountDetailWechatId = String(accountDetail?.wechat_id || '').trim();
  const accountDetailOwnerName = String(accountDetail?.owner_name || '').trim();
  const accountDetailOwnerMembershipId = String(accountDetail?.owner_membership_id || '').trim();
  const accountDetailAssistantNames = toStringList(accountDetail?.assistant_names);
  const accountDetailAssistantMembershipIds = toStringList(accountDetail?.assistant_membership_ids);
  const accountDetailOperationLogs = useMemo(
    () => normalizeOperationLogs(accountDetail?.operation_logs),
    [accountDetail]
  );

  if (!accessToken) {
    return (
      <section data-testid="tenant-accounts-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载账号管理。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="tenant-accounts-module" style={{ display: 'grid', gap: 12 }}>
      {messageContextHolder}

      <CustomFilter
        form={accountFilterForm}
        initialValues={ACCOUNT_FILTER_INITIAL_VALUES}
        onFinish={(values) => {
          const createdRange = Array.isArray(values.created_time) ? values.created_time : [];
          const [createdStart, createdEnd] = createdRange;
          setAccountFilters({
            wechat_id: String(values.wechat_id || '').trim(),
            nickname: String(values.nickname || '').trim(),
            owner_keyword: String(values.owner_keyword || '').trim(),
            assistant_keyword: String(values.assistant_keyword || '').trim(),
            status: String(values.status || '').trim(),
            created_time_start:
              createdStart && typeof createdStart.format === 'function'
                ? createdStart.format('YYYY-MM-DD HH:mm:ss')
                : '',
            created_time_end:
              createdEnd && typeof createdEnd.format === 'function'
                ? createdEnd.format('YYYY-MM-DD HH:mm:ss')
                : ''
          });
          refreshAccountTable();
        }}
        onReset={() => {
          setAccountFilters({
            wechat_id: '',
            nickname: '',
            owner_keyword: '',
            assistant_keyword: '',
            status: '',
            created_time_start: '',
            created_time_end: ''
          });
          refreshAccountTable();
        }}
      >
        <Form.Item label="微信号" name="wechat_id">
          <Input data-testid="tenant-account-filter-wechat-id" placeholder="请输入微信号（精确）" allowClear />
        </Form.Item>
        <Form.Item label="昵称" name="nickname">
          <Input data-testid="tenant-account-filter-nickname" placeholder="请输入昵称（模糊）" allowClear />
        </Form.Item>
        <Form.Item label="负责人" name="owner_keyword">
          <Input data-testid="tenant-account-filter-owner" placeholder="请输入负责人关键词（模糊）" allowClear />
        </Form.Item>
        <Form.Item label="协管人" name="assistant_keyword">
          <Input data-testid="tenant-account-filter-assistant" placeholder="请输入协管人关键词（模糊）" allowClear />
        </Form.Item>
        <Form.Item label="状态" name="status">
          <Select data-testid="tenant-account-filter-status" options={ACCOUNT_STATUS_OPTIONS} />
        </Form.Item>
        <Form.Item label="创建时间" name="created_time">
          <DatePicker.RangePicker
            data-testid="tenant-account-filter-created-time"
            showTime
            placeholder={['开始时间', '结束时间']}
            format="YYYY-MM-DD HH:mm:ss"
          />
        </Form.Item>
      </CustomFilter>

      <CustomCardTable
        key={accountTableQueryKey}
        title="账号列表"
        rowKey="account_id"
        columns={accountColumns}
        request={accountTableRequest}
        onRow={(record) => ({
          onClick: () => {
            void openAccountDetail(record.account_id);
          },
          style: { cursor: 'pointer' }
        })}
        extra={canOperateAccountManagement ? (
          <Button
            data-testid="tenant-account-create-open"
            type="primary"
            onClick={() => {
              void openAccountCreateModal();
            }}
          >
            新建
          </Button>
        ) : null}
      />

      <Modal
        open={accountEditOpen}
        title={accountEditMode === 'create' ? '新建' : '编辑'}
        onCancel={() => {
          setAccountEditOpen(false);
          setAccountEditTarget(null);
          setAccountEditLoading(false);
        }}
        onOk={() => {
          void handleSubmitAccountEdit();
        }}
        confirmLoading={accountEditSubmitting}
        okButtonProps={{
          disabled: accountEditSubmitting || accountEditLoading,
          'data-testid': accountEditMode === 'create'
            ? 'tenant-account-create-confirm'
            : 'tenant-account-edit-confirm'
        }}
        cancelButtonProps={{
          disabled: accountEditSubmitting
        }}
        destroyOnClose
      >
        {accountEditLoading ? (
          <Text type="secondary">加载中...</Text>
        ) : (
          <CustomForm
            form={accountEditForm}
            initialValues={ACCOUNT_FORM_INITIAL_VALUES}
            layout="vertical"
            submitter={false}
          >
            {accountEditMode === 'edit' ? (
              <CustomForm.Item label="账号ID" name="account_id">
                <Input data-testid="tenant-account-edit-account-id" disabled />
              </CustomForm.Item>
            ) : null}
            <CustomForm.Item
              label="微信号"
              name="wechat_id"
              rules={[
                { required: true, message: '请输入微信号' },
                { max: 64, message: '微信号长度不能超过 64' }
              ]}
            >
              <Input
                data-testid="tenant-account-edit-wechat-id"
                maxLength={64}
                placeholder="请输入微信号"
              />
            </CustomForm.Item>
            <CustomForm.Item
              label="昵称"
              name="nickname"
              rules={[
                { required: true, message: '请输入昵称' },
                { max: 64, message: '昵称长度不能超过 64' }
              ]}
            >
              <Input
                data-testid="tenant-account-edit-nickname"
                maxLength={64}
                placeholder="请输入昵称"
              />
            </CustomForm.Item>
            <CustomForm.Item
              label="负责人"
              name="owner_membership_id"
              rules={[
                { required: true, message: '请选择负责人' }
              ]}
            >
              <Select
                data-testid="tenant-account-edit-owner-membership-id"
                allowClear
                showSearch
                optionFilterProp="label"
                loading={memberOptionsLoading}
                options={memberOptions}
                placeholder="请选择负责人"
              />
            </CustomForm.Item>
            <CustomForm.Item
              label="协管人"
              name="assistant_membership_ids"
            >
              <Select
                data-testid="tenant-account-edit-assistant-membership-ids"
                mode="multiple"
                allowClear
                showSearch
                optionFilterProp="label"
                loading={memberOptionsLoading}
                options={memberOptions}
                placeholder="请选择协管成员（可多选）"
              />
            </CustomForm.Item>
          </CustomForm>
        )}
      </Modal>

      <Drawer
        open={accountDetailOpen}
        title={accountDetailAccountId ? `账号ID:${accountDetailAccountId}` : '账号ID:-'}
        extra={canOperateAccountManagement ? (
          <Space>
            <Button
              data-testid="tenant-account-detail-edit"
              size="small"
              disabled={!accountDetailAccountId}
              onClick={() => {
                void openAccountEditModal(accountDetail || {});
              }}
            >
              编辑
            </Button>
            <Button
              data-testid="tenant-account-detail-status"
              size="small"
              loading={Boolean(statusActionSubmittingByAccountId[accountDetailAccountId])}
              disabled={!accountDetailAccountId || !accountDetailStatus}
              onClick={() => {
                void handleToggleAccountStatus(
                  {
                    account_id: accountDetailAccountId,
                    status: accountDetailStatus
                  },
                  { refreshDetail: true }
                );
              }}
            >
              {statusToggleLabel(accountDetailStatus)}
            </Button>
          </Space>
        ) : null}
        size="large"
        onClose={() => {
          setAccountDetailOpen(false);
          setAccountDetail(null);
        }}
        destroyOnClose
      >
        <div data-testid="tenant-account-detail-drawer" style={{ display: 'grid', gap: 12 }}>
          {accountDetailLoading ? (
            <Text>加载中...</Text>
          ) : accountDetail ? (
            <div style={{ display: 'grid', gap: 12 }}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
                <Avatar
                  size={56}
                  icon={<UserOutlined />}
                  style={{ backgroundColor: token.colorPrimary, color: token.colorWhite }}
                />
                <div style={{ display: 'grid', gap: 2 }}>
                  <Text strong>{accountDetailNickname || '-'}</Text>
                  <Text type="secondary">微信号：{accountDetailWechatId || '-'}</Text>
                </div>
              </div>

              <Tabs
                items={[
                  {
                    key: 'overview',
                    label: '概览',
                    children: (
                      <div style={{ display: 'grid', gap: 12 }}>
                        <Descriptions
                          title="基本信息"
                          column={2}
                        >
                          <Descriptions.Item label="账号ID">
                            {accountDetailAccountId || '-'}
                          </Descriptions.Item>
                          <Descriptions.Item label="微信号">
                            {accountDetailWechatId || '-'}
                          </Descriptions.Item>
                          <Descriptions.Item label="昵称">
                            {accountDetailNickname || '-'}
                          </Descriptions.Item>
                          <Descriptions.Item label="负责人">
                            {accountDetailOwnerName
                              || memberLabelByMembershipId[accountDetailOwnerMembershipId]
                              || accountDetailOwnerMembershipId
                              || '-'}
                          </Descriptions.Item>
                          <Descriptions.Item label="协管人">
                            {accountDetailAssistantNames.length > 0
                              ? accountDetailAssistantNames.join('、')
                              : (
                                accountDetailAssistantMembershipIds.length > 0
                                  ? accountDetailAssistantMembershipIds
                                    .map((membershipId) => memberLabelByMembershipId[membershipId] || membershipId)
                                    .join('、')
                                  : '-'
                              )}
                          </Descriptions.Item>
                          <Descriptions.Item label="客户数">
                            {Number.isFinite(Number(accountDetail?.customer_count))
                              ? Number(accountDetail.customer_count)
                              : 0}
                          </Descriptions.Item>
                          <Descriptions.Item label="群聊数">
                            {Number.isFinite(Number(accountDetail?.group_chat_count))
                              ? Number(accountDetail.group_chat_count)
                              : 0}
                          </Descriptions.Item>
                          <Descriptions.Item label="状态">
                            {statusDisplayLabel(accountDetailStatus)}
                          </Descriptions.Item>
                        </Descriptions>

                        <Descriptions
                          title="系统信息"
                          column={2}
                        >
                          <Descriptions.Item label="创建人">
                            {accountDetail?.created_by_name
                              || accountDetail?.created_by_user_id
                              || '-'}
                          </Descriptions.Item>
                          <Descriptions.Item label="创建时间">
                            {formatDateTimeMinute(accountDetail?.created_at)}
                          </Descriptions.Item>
                          <Descriptions.Item label="最新更新">
                            {formatDateTimeMinute(accountDetail?.updated_at)}
                          </Descriptions.Item>
                        </Descriptions>
                      </div>
                    )
                  },
                  {
                    key: 'timeline',
                    label: '操作记录',
                    children: accountDetailOperationLogs.length > 0 ? (
                      <Timeline
                        items={accountDetailOperationLogs.map((log, index) => ({
                          key: `${log.operation_type}-${log.operated_at}-${index}`,
                          children: (
                            <div data-testid={`tenant-account-log-${index}`} style={{ display: 'grid', gap: 2 }}>
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
