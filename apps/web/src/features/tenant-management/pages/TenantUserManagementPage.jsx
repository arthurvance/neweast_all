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
  Select,
  Space,
  Tag,
  Typography,
  message
} from 'antd';
import CustomCardTable from '../../../components/CustomCardTable';
import CustomFilter from '../../../components/CustomFilter';
import CustomForm from '../../../components/CustomForm';
import {
  createTenantManagementApi,
  normalizeRoleIds,
  toProblemMessage
} from '../../../api/tenant-management.mjs';
import {
  formatDateTimeMinute,
  toDateTimeMinuteEpoch
} from '../../../utils/date-time.mjs';

const { Text } = Typography;

const MEMBER_STATUS_OPTIONS = [
  { label: '全部', value: '' },
  { label: '启用', value: 'active' },
  { label: '禁用', value: 'disabled' }
];
const MEMBER_FILTER_INITIAL_VALUES = Object.freeze({
  phone: '',
  name: '',
  status: '',
  created_time: []
});

const statusDisplayLabel = (status) => {
  const normalized = String(status || '').trim().toLowerCase();
  if (normalized === 'active') {
    return '启用';
  }
  if (normalized === 'disabled') {
    return '禁用';
  }
  if (normalized === 'left') {
    return '离开';
  }
  return '-';
};

const statusToggleLabel = (status) => {
  const normalized = String(status || '').trim().toLowerCase();
  return normalized === 'active' ? '禁用' : '启用';
};

const statusToggleValue = (status) => {
  const normalized = String(status || '').trim().toLowerCase();
  return normalized === 'active' ? 'disabled' : 'active';
};

const resolveMemberCreatedTime = (member = {}) =>
  String(member?.joined_at || member?.created_at || '').trim();

const filterMembersOnClient = (members = [], filters = {}) => {
  const phone = String(filters.phone || '').trim();
  const name = String(filters.name || '').trim().toLowerCase();
  const status = String(filters.status || '').trim().toLowerCase();
  const createdTimeStart = toDateTimeMinuteEpoch(filters.created_time_start);
  const createdTimeEnd = toDateTimeMinuteEpoch(filters.created_time_end);
  return members.filter((member) => {
    const memberStatus = String(member.status || '').trim().toLowerCase();
    if (status && status !== memberStatus) {
      return false;
    }
    if (phone && String(member.phone || '').trim() !== phone) {
      return false;
    }
    if (name && !String(member.display_name || '').trim().toLowerCase().includes(name)) {
      return false;
    }
    if (createdTimeStart !== null || createdTimeEnd !== null) {
      const memberCreatedTime = toDateTimeMinuteEpoch(resolveMemberCreatedTime(member));
      if (memberCreatedTime === null) {
        return false;
      }
      if (createdTimeStart !== null && memberCreatedTime < createdTimeStart) {
        return false;
      }
      if (createdTimeEnd !== null && memberCreatedTime > createdTimeEnd) {
        return false;
      }
    }
    return true;
  });
};

const hasActiveMemberFilters = (filters = {}) => {
  const phone = String(filters.phone || '').trim();
  const name = String(filters.name || '').trim();
  const status = String(filters.status || '').trim();
  const createdTimeStart = String(filters.created_time_start || '').trim();
  const createdTimeEnd = String(filters.created_time_end || '').trim();
  return Boolean(phone || name || status || createdTimeStart || createdTimeEnd);
};

const formatProblemText = (error, fallback) => {
  const text = toProblemMessage(error, fallback);
  const errorCode = String(error?.payload?.error_code || '').trim();
  if (!errorCode || text.includes(errorCode)) {
    return text;
  }
  return `${text}（${errorCode}）`;
};

export default function TenantUserManagementPage({
  accessToken,
  onTenantPermissionContextRefresh
}) {
  const api = useMemo(
    () => createTenantManagementApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [memberFilterForm] = Form.useForm();
  const [memberCreateForm] = Form.useForm();
  const [memberProfileForm] = Form.useForm();

  const [memberFilters, setMemberFilters] = useState({
    phone: '',
    name: '',
    status: '',
    created_time_start: '',
    created_time_end: ''
  });
  const [memberTableRefreshToken, setMemberTableRefreshToken] = useState(0);
  const [memberCreateOpen, setMemberCreateOpen] = useState(false);
  const [memberCreateSubmitting, setMemberCreateSubmitting] = useState(false);
  const [memberProfileOpen, setMemberProfileOpen] = useState(false);
  const [memberProfileSubmitting, setMemberProfileSubmitting] = useState(false);
  const [memberProfileTarget, setMemberProfileTarget] = useState(null);
  const [statusActionSubmittingByMembershipId, setStatusActionSubmittingByMembershipId] = useState({});
  const [memberDetailOpen, setMemberDetailOpen] = useState(false);
  const [memberDetailLoading, setMemberDetailLoading] = useState(false);
  const [memberDetail, setMemberDetail] = useState(null);
  const [latestMemberActionById, setLatestMemberActionById] = useState({});
  const [tenantRoleLabelById, setTenantRoleLabelById] = useState({});
  const [tenantActiveRoleOptions, setTenantActiveRoleOptions] = useState([]);
  const [tenantActiveRoleOptionsLoading, setTenantActiveRoleOptionsLoading] = useState(false);

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

  const loadTenantRoleLabels = useCallback(async () => {
    setTenantActiveRoleOptionsLoading(true);
    try {
      const payload = await api.listRoles();
      const roles = Array.isArray(payload?.roles) ? payload.roles : [];
      const nextRoleLabelById = {};
      const nextActiveRoleOptions = [];
      for (const role of roles) {
        const roleId = String(role?.role_id || '').trim().toLowerCase();
        if (!roleId) {
          continue;
        }
        const roleLabel = String(role?.name || role?.code || roleId).trim() || roleId;
        nextRoleLabelById[roleId] = roleLabel;
        const roleStatus = String(role?.status || '').trim().toLowerCase();
        if (roleStatus === 'active') {
          nextActiveRoleOptions.push({
            label: roleLabel,
            value: roleId
          });
        }
      }
      setTenantRoleLabelById(nextRoleLabelById);
      setTenantActiveRoleOptions(nextActiveRoleOptions);
    } catch (error) {
      setTenantRoleLabelById({});
      setTenantActiveRoleOptions([]);
      notifyError(error, '加载组织角色列表失败');
    } finally {
      setTenantActiveRoleOptionsLoading(false);
    }
  }, [api, notifyError]);

  useEffect(() => {
    if (!accessToken) {
      setTenantRoleLabelById({});
      return;
    }
    void loadTenantRoleLabels();
  }, [accessToken, loadTenantRoleLabels]);

  const attachMemberRoles = useCallback(
    async (members = []) => {
      if (!Array.isArray(members) || members.length < 1) {
        return [];
      }
      const roleEntries = await Promise.all(
        members.map(async (member) => {
          const membershipId = String(member?.membership_id || '').trim();
          if (!membershipId) {
            return [membershipId, []];
          }
          try {
            const payload = await api.getMemberRoles(membershipId);
            const roleIds = Array.isArray(payload?.role_ids) ? payload.role_ids : [];
            return [membershipId, normalizeRoleIds(roleIds)];
          } catch (_error) {
            return [membershipId, []];
          }
        })
      );
      const roleMap = new Map(roleEntries);
      return members.map((member) => {
        const membershipId = String(member?.membership_id || '').trim();
        return {
          ...member,
          role_ids: roleMap.get(membershipId) || []
        };
      });
    },
    [api]
  );

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

  const openMemberProfileModal = useCallback(async (record) => {
    const normalizedMembershipId = String(record?.membership_id || '').trim();
    if (!normalizedMembershipId) {
      return;
    }
    setMemberProfileTarget(record);
    setMemberProfileOpen(true);
    memberProfileForm.setFieldsValue({
      user_id: String(record?.user_id || '').trim(),
      phone: String(record?.phone || '').trim(),
      display_name: record?.display_name || '',
      department_name: record?.department_name || '',
      role_ids: normalizeRoleIds(Array.isArray(record?.role_ids) ? record.role_ids : [])
    });
    try {
      const rolePayload = await api.getMemberRoles(normalizedMembershipId);
      const normalizedRoleIds = normalizeRoleIds(
        Array.isArray(rolePayload?.role_ids) ? rolePayload.role_ids : []
      );
      memberProfileForm.setFieldsValue({
        role_ids: normalizedRoleIds
      });
    } catch (_error) {
      // Keep current row value when role pull fails.
    }
  }, [api, memberProfileForm]);

  const handleCreateMember = useCallback(async () => {
    let createdMemberPayload = null;
    try {
      const values = await memberCreateForm.validateFields();
      const normalizedRoleIds = normalizeRoleIds(
        Array.isArray(values.role_ids) ? values.role_ids : []
      );
      const displayName = String(values.display_name || '').trim();
      const departmentName = String(values.department_name || '').trim() || null;
      setMemberCreateSubmitting(true);
      createdMemberPayload = await api.createMember({
        phone: values.phone
      });
      const createdMembershipId = String(createdMemberPayload?.membership_id || '').trim();
      if (!createdMembershipId) {
        throw new Error('create member payload missing membership_id');
      }

      await api.updateMemberProfile({
        membershipId: createdMembershipId,
        display_name: displayName,
        department_name: departmentName
      });
      if (normalizedRoleIds.length > 0) {
        await api.replaceMemberRoles({
          membershipId: createdMembershipId,
          role_ids: normalizedRoleIds
        });
      }

      const latestAction = {
        action: 'create',
        request_id: createdMemberPayload.request_id,
        result: createdMemberPayload.created_user ? 'created' : 'reused'
      };
      setLatestMemberActionById((previous) => ({
        ...previous,
        [createdMembershipId]: latestAction
      }));
      notifySuccess(`组织成员新建成功（request_id: ${createdMemberPayload.request_id}）`);
      setMemberCreateOpen(false);
      memberCreateForm.resetFields();
      refreshMemberTable();
      void openMemberDetail(createdMembershipId, latestAction);
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      const errorCode = String(error?.payload?.error_code || '').trim();
      if (
        !createdMemberPayload
        && errorCode === 'AUTH-409-PROVISION-CONFLICT'
      ) {
        messageApi.error('手机号在组织内已存在，请使用其他手机号');
        return;
      }
      if (createdMemberPayload?.membership_id) {
        const fallbackLatestAction = {
          action: 'create',
          request_id: createdMemberPayload.request_id,
          result: createdMemberPayload.created_user ? 'created-partial' : 'reused-partial'
        };
        setLatestMemberActionById((previous) => ({
          ...previous,
          [createdMemberPayload.membership_id]: fallbackLatestAction
        }));
        notifyError(error, '成员已新建，但资料或角色保存失败');
        setMemberCreateOpen(false);
        memberCreateForm.resetFields();
        refreshMemberTable();
        void openMemberDetail(createdMemberPayload.membership_id, fallbackLatestAction);
        return;
      }
      notifyError(error, '新建组织成员失败');
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

  const handleDirectToggleMemberStatus = useCallback(
    async (record, { refreshDetail = false } = {}) => {
      const normalizedMembershipId = String(record?.membership_id || '').trim();
      if (!normalizedMembershipId) {
        return;
      }
      if (statusActionSubmittingByMembershipId[normalizedMembershipId]) {
        return;
      }
      try {
        setStatusActionSubmittingByMembershipId((previous) => ({
          ...previous,
          [normalizedMembershipId]: true
        }));
        const targetStatus = statusToggleValue(record?.status);
        const payload = await api.updateMemberStatus({
          membershipId: normalizedMembershipId,
          status: targetStatus,
          reason: null
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
        notifySuccess('操作成功');
        refreshMemberTable();
        const shouldRefreshDetail = refreshDetail || (
          memberDetailOpen
          && String(memberDetail?.membership_id || '').trim() === normalizedMembershipId
        );
        if (shouldRefreshDetail) {
          void openMemberDetail(payload.membership_id, latestAction);
        }
      } catch (error) {
        notifyError(error, '更新成员状态失败');
      } finally {
        setStatusActionSubmittingByMembershipId((previous) => ({
          ...previous,
          [normalizedMembershipId]: false
        }));
      }
    },
    [
      api,
      memberDetail,
      memberDetailOpen,
      notifyError,
      notifySuccess,
      openMemberDetail,
      refreshMemberTable,
      statusActionSubmittingByMembershipId
    ]
  );

  const handleSubmitMemberProfile = useCallback(async () => {
    if (!memberProfileTarget?.membership_id) {
      return;
    }
    let profilePayload = null;
    try {
      const values = await memberProfileForm.validateFields();
      const normalizedRoleIds = normalizeRoleIds(
        Array.isArray(values.role_ids) ? values.role_ids : []
      );
      if (normalizedRoleIds.length < 1 || normalizedRoleIds.length > 5) {
        messageApi.error('角色分配必须为 1 到 5 个角色，请稍后重试');
        return;
      }
      setMemberProfileSubmitting(true);
      profilePayload = await api.updateMemberProfile({
        membershipId: memberProfileTarget.membership_id,
        display_name: values.display_name,
        department_name: values.department_name || null
      });
      const rolePayload = await api.replaceMemberRoles({
        membershipId: memberProfileTarget.membership_id,
        role_ids: normalizedRoleIds
      });
      const requestId = String(rolePayload?.request_id || profilePayload?.request_id || '').trim();
      const latestAction = {
        action: 'edit',
        request_id: requestId,
        result: 'profile-and-roles-updated'
      };
      setLatestMemberActionById((previous) => ({
        ...previous,
        [memberProfileTarget.membership_id]: latestAction
      }));
      notifySuccess(`成员编辑成功（request_id: ${requestId}）`);
      setMemberProfileOpen(false);
      setMemberProfileTarget(null);
      memberProfileForm.resetFields();
      refreshMemberTable();
      void openMemberDetail(memberProfileTarget.membership_id, latestAction);

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
      if (profilePayload?.membership_id) {
        notifyError(error, '成员资料已更新，但角色保存失败');
        refreshMemberTable();
        return;
      }
      notifyError(error, '编辑成员失败');
    } finally {
      setMemberProfileSubmitting(false);
    }
  }, [
    api,
    memberProfileForm,
    memberProfileTarget,
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
        const pagedMembers = filteredMembers.slice(offset, offset + pageSize);
        const pagedMembersWithRoles = await attachMemberRoles(pagedMembers);
        return {
          data: pagedMembersWithRoles.map((member) => ({ ...member, key: member.membership_id })),
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

      const sourceMembersWithRoles = await attachMemberRoles(sourceMembers);
      return {
        data: sourceMembersWithRoles.map((member) => ({ ...member, key: member.membership_id })),
        total,
        success: true
      };
    },
    [api, attachMemberRoles, memberFilters, memberTableRefreshToken]
  );
  const memberTableQueryKey = useMemo(
    () =>
      [
        memberFilters.phone,
        memberFilters.name,
        memberFilters.status,
        memberFilters.created_time_start,
        memberFilters.created_time_end
      ].join('|'),
    [
      memberFilters.created_time_end,
      memberFilters.created_time_start,
      memberFilters.name,
      memberFilters.phone,
      memberFilters.status
    ]
  );

  const memberColumns = useMemo(
    () => [
      {
        title: '用户ID',
        dataIndex: 'user_id',
        key: 'user_id',
        width: 220,
        render: (value) => <span data-testid={`tenant-member-user-id-${value}`}>{value}</span>
      },
      {
        title: '手机号',
        dataIndex: 'phone',
        key: 'phone',
        width: 160
      },
      {
        title: '姓名',
        dataIndex: 'display_name',
        key: 'display_name',
        width: 160,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '部门',
        dataIndex: 'department_name',
        key: 'department_name',
        width: 180,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '角色',
        dataIndex: 'role_ids',
        key: 'role_ids',
        width: 220,
        render: (value) => {
          const roleIds = normalizeRoleIds(Array.isArray(value) ? value : []);
          if (roleIds.length < 1) {
            return '-';
          }
          return (
            <Space size={[4, 4]} wrap>
              {roleIds.map((roleId) => (
                <Tag key={roleId}>
                  {tenantRoleLabelById[roleId] || roleId}
                </Tag>
              ))}
            </Space>
          );
        }
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
        dataIndex: 'joined_at',
        key: 'joined_at',
        width: 180,
        render: (value) => formatDateTimeMinute(value)
      },
      {
        title: '操作',
        key: 'actions',
        width: 220,
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
              data-testid={`tenant-member-status-${record.membership_id}`}
              size="small"
              type="link"
              loading={Boolean(statusActionSubmittingByMembershipId[record.membership_id])}
              onClick={(event) => {
                event.stopPropagation();
                void handleDirectToggleMemberStatus(record);
              }}
            >
              {statusToggleLabel(record.status)}
            </Button>
            <Button
              data-testid={`tenant-member-profile-${record.membership_id}`}
              size="small"
              type="link"
              onClick={(event) => {
                event.stopPropagation();
                openMemberProfileModal(record);
              }}
            >
              编辑
            </Button>
          </Space>
        )
      }
    ],
    [
      handleDirectToggleMemberStatus,
      openMemberProfileModal,
      statusActionSubmittingByMembershipId,
      tenantRoleLabelById
    ]
  );

  const memberDetailMembershipId = String(memberDetail?.membership_id || '').trim();
  const memberDetailUserId = String(memberDetail?.user_id || '').trim();
  const memberDetailStatus = String(memberDetail?.status || '').trim().toLowerCase();
  const memberDetailRoleIds = normalizeRoleIds(Array.isArray(memberDetail?.role_ids) ? memberDetail.role_ids : []);

  if (!accessToken) {
    return (
      <section data-testid="tenant-users-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载组织用户管理。" showIcon />
      </section>
    );
  }

  return (
    <section data-testid="tenant-members-module" style={{ display: 'grid', gap: 12 }}>
      {messageContextHolder}

      <CustomFilter
        form={memberFilterForm}
        initialValues={MEMBER_FILTER_INITIAL_VALUES}
        onFinish={(values) => {
          const createdRange = Array.isArray(values.created_time)
            ? values.created_time
            : [];
          const [createdStart, createdEnd] = createdRange;
          setMemberFilters({
            phone: String(values.phone || '').trim(),
            name: String(values.name || '').trim(),
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
          refreshMemberTable();
        }}
        onReset={() => {
          setMemberFilters({
            phone: '',
            name: '',
            status: '',
            created_time_start: '',
            created_time_end: ''
          });
          refreshMemberTable();
        }}
      >
        <Form.Item label="手机号" name="phone">
          <Input data-testid="tenant-member-filter-phone" placeholder="请输入手机号（精确）" allowClear />
        </Form.Item>
        <Form.Item label="姓名" name="name">
          <Input data-testid="tenant-member-filter-name" placeholder="请输入姓名（模糊）" allowClear />
        </Form.Item>
        <Form.Item label="状态" name="status">
          <Select
            data-testid="tenant-member-filter-status"
            options={MEMBER_STATUS_OPTIONS}
          />
        </Form.Item>
        <Form.Item label="创建时间" name="created_time">
          <DatePicker.RangePicker
            data-testid="tenant-member-filter-created-time"
            showTime
            placeholder={['开始时间', '结束时间']}
            format="YYYY-MM-DD HH:mm:ss"
          />
        </Form.Item>
      </CustomFilter>

      <CustomCardTable
        key={memberTableQueryKey}
        title="组织成员列表"
        rowKey="membership_id"
        columns={memberColumns}
        request={memberTableRequest}
        onRow={(record) => ({
          onClick: () => {
            void openMemberDetail(record.membership_id);
          },
          style: { cursor: 'pointer' }
        })}
        extra={(
          <Button
            data-testid="tenant-member-create-open"
            type="primary"
            onClick={() => {
              void loadTenantRoleLabels();
              memberCreateForm.resetFields();
              setMemberCreateOpen(true);
            }}
          >
            新建
          </Button>
        )}
      />

      <Modal
        open={memberCreateOpen}
        title="新建"
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
            <Input
              data-testid="tenant-member-create-phone"
              maxLength={11}
              inputMode="numeric"
              placeholder="请输入手机号"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="姓名"
            name="display_name"
            rules={[
              { required: true, message: '请输入姓名' },
              { max: 64, message: '姓名长度不能超过 64' }
            ]}
          >
            <Input
              data-testid="tenant-member-create-display-name"
              maxLength={64}
              placeholder="请输入姓名"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="部门"
            name="department_name"
            rules={[
              { max: 128, message: '部门长度不能超过 128' }
            ]}
          >
            <Input
              data-testid="tenant-member-create-department-name"
              maxLength={128}
              placeholder="请输入部门（选填）"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="角色"
            name="role_ids"
          >
            <Select
              data-testid="tenant-member-create-role-ids"
              mode="multiple"
              allowClear
              loading={tenantActiveRoleOptionsLoading}
              options={tenantActiveRoleOptions}
              placeholder="请选择角色（可多选）"
              optionFilterProp="label"
            />
          </CustomForm.Item>
        </CustomForm>
      </Modal>

      <Modal
        open={memberProfileOpen}
        title="编辑"
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
            label="用户ID"
            name="user_id"
          >
            <Input data-testid="tenant-member-profile-user-id" disabled />
          </CustomForm.Item>
          <CustomForm.Item
            label="手机号"
            name="phone"
          >
            <Input data-testid="tenant-member-profile-phone" disabled />
          </CustomForm.Item>
          <CustomForm.Item
            label="姓名"
            name="display_name"
            rules={[
              { required: true, message: '请输入姓名' },
              { max: 64, message: '姓名长度不能超过 64' }
            ]}
          >
            <Input
              data-testid="tenant-member-profile-display-name"
              maxLength={64}
              placeholder="请输入姓名"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="部门"
            name="department_name"
            rules={[
              { max: 128, message: '部门长度不能超过 128' }
            ]}
          >
            <Input
              data-testid="tenant-member-profile-department-name"
              maxLength={128}
              placeholder="请输入部门（选填）"
            />
          </CustomForm.Item>
          <CustomForm.Item
            label="角色"
            name="role_ids"
            rules={[
              { required: true, message: '请选择角色' },
              {
                validator: (_rule, value) => {
                  const normalizedRoleIds = normalizeRoleIds(Array.isArray(value) ? value : []);
                  if (normalizedRoleIds.length < 1 || normalizedRoleIds.length > 5) {
                    return Promise.reject(new Error('角色分配数量必须在 1 到 5 之间'));
                  }
                  return Promise.resolve();
                }
              }
            ]}
          >
            <Select
              data-testid="tenant-member-profile-role-ids"
              mode="multiple"
              allowClear
              loading={tenantActiveRoleOptionsLoading}
              options={tenantActiveRoleOptions}
              placeholder="请选择角色（可多选）"
              optionFilterProp="label"
            />
          </CustomForm.Item>
        </CustomForm>
      </Modal>

      <Drawer
        open={memberDetailOpen}
        title={memberDetailUserId ? `用户ID:${memberDetailUserId}` : '用户ID:-'}
        extra={(
          <Space>
            <Button
              data-testid="tenant-member-detail-edit"
              size="small"
              disabled={!memberDetailMembershipId}
              onClick={() => {
                void openMemberProfileModal(memberDetail || {});
              }}
            >
              编辑
            </Button>
            <Button
              data-testid="tenant-member-detail-status"
              size="small"
              loading={Boolean(statusActionSubmittingByMembershipId[memberDetailMembershipId])}
              disabled={!memberDetailMembershipId || !memberDetailStatus}
              onClick={() => {
                void handleDirectToggleMemberStatus(
                  {
                    membership_id: memberDetailMembershipId,
                    status: memberDetailStatus
                  },
                  { refreshDetail: true }
                );
              }}
            >
              {statusToggleLabel(memberDetailStatus)}
            </Button>
          </Space>
        )}
        size="large"
        onClose={() => {
          setMemberDetailOpen(false);
          setMemberDetail(null);
        }}
        destroyOnClose
      >
        <div data-testid="tenant-member-detail-drawer" style={{ display: 'grid', gap: 8 }}>
          {memberDetailLoading ? (
            <Text>加载中...</Text>
          ) : memberDetail ? (
            <Descriptions
              size="small"
              bordered
              column={1}
            >
              <Descriptions.Item label="手机号">
                {String(memberDetail.phone || '').trim() || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="姓名">
                {String(memberDetail.display_name || '').trim() || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="部门">
                {String(memberDetail.department_name || '').trim() || '-'}
              </Descriptions.Item>
              <Descriptions.Item label="角色">
                {memberDetailRoleIds.length > 0 ? (
                  <Space size={[4, 4]} wrap>
                    {memberDetailRoleIds.map((roleId) => (
                      <Tag key={roleId}>
                        {tenantRoleLabelById[roleId] || roleId}
                      </Tag>
                    ))}
                  </Space>
                ) : (
                  '-'
                )}
              </Descriptions.Item>
              <Descriptions.Item label="状态">
                {statusDisplayLabel(memberDetail.status)}
              </Descriptions.Item>
              <Descriptions.Item label="创建时间">
                {formatDateTimeMinute(resolveMemberCreatedTime(memberDetail))}
              </Descriptions.Item>
            </Descriptions>
          ) : (
            <Text type="secondary">暂无详情数据</Text>
          )}
        </div>
      </Drawer>
    </section>
  );
}
