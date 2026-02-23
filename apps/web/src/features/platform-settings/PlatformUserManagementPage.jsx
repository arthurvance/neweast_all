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
  Space,
  Tag,
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

const USER_STATUS_SELECT_OPTIONS = [
  { label: '全部', value: '' },
  { label: '启用', value: 'active' },
  { label: '禁用', value: 'disabled' }
];
const USER_FILTER_INITIAL_VALUES = Object.freeze({
  phone: '',
  name: '',
  status: '',
  created_time: []
});

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
const normalizeRoleList = (roles = []) =>
  (Array.isArray(roles) ? roles : [])
    .map((role) => ({
      role_id: String(role?.role_id || '').trim().toLowerCase(),
      code: String(role?.code || '').trim(),
      name: String(role?.name || '').trim(),
      status: String(role?.status || '').trim().toLowerCase()
    }))
    .filter((role) => role.role_id);

export default function PlatformUserManagementPage({ accessToken }) {
  const api = useMemo(
    () => createPlatformSettingsApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [userFilterForm] = Form.useForm();
  const [createUserForm] = Form.useForm();
  const [statusActionForm] = Form.useForm();

  const [userFilters, setUserFilters] = useState({
    phone: '',
    name: '',
    status: '',
    created_at_start: '',
    created_at_end: ''
  });
  const [userTableRefreshToken, setUserTableRefreshToken] = useState(0);
  const [userModalOpen, setUserModalOpen] = useState(false);
  const [userModalSubmitting, setUserModalSubmitting] = useState(false);
  const [userStatusModalOpen, setUserStatusModalOpen] = useState(false);
  const [userStatusModalSubmitting, setUserStatusModalSubmitting] = useState(false);
  const [userStatusActionTarget, setUserStatusActionTarget] = useState(null);
  const [statusActionSubmittingByUserId, setStatusActionSubmittingByUserId] = useState({});
  const [userDetailOpen, setUserDetailOpen] = useState(false);
  const [userDetailLoading, setUserDetailLoading] = useState(false);
  const [userDetail, setUserDetail] = useState(null);
  const [latestUserActionById, setLatestUserActionById] = useState({});
  const [enabledRoleOptions, setEnabledRoleOptions] = useState([]);
  const [enabledRoleOptionsLoading, setEnabledRoleOptionsLoading] = useState(false);

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

  const loadEnabledRoleOptions = useCallback(async () => {
    setEnabledRoleOptionsLoading(true);
    try {
      const payload = await api.listRoles();
      const roles = Array.isArray(payload?.roles) ? payload.roles : [];
      setEnabledRoleOptions(
        roles
          .filter((role) => String(role?.status || '').trim().toLowerCase() === 'active')
          .map((role) => ({
            label: String(role?.name || role?.code || role?.role_id || '').trim() || '-',
            value: String(role?.role_id || '').trim().toLowerCase()
          }))
          .filter((role) => role.value)
      );
    } catch (error) {
      setEnabledRoleOptions([]);
      withErrorNotice(error, '加载启用角色列表失败');
    } finally {
      setEnabledRoleOptionsLoading(false);
    }
  }, [api, withErrorNotice]);

  useEffect(() => {
    if (!accessToken) {
      return;
    }
    void loadEnabledRoleOptions();
  }, [accessToken, loadEnabledRoleOptions]);

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
      const normalizedRoleIds = (Array.isArray(values.role_ids) ? values.role_ids : [])
        .map((roleId) => String(roleId || '').trim().toLowerCase())
        .filter((roleId) => roleId);
      const payload = await api.createUser({
        phone: String(values.phone || '').replace(/\D/g, '').slice(0, 11),
        name: String(values.name || '').trim(),
        department: String(values.department || '').trim() || null,
        roleIds: [...new Set(normalizedRoleIds)]
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
    } catch (error) {
      if (error?.errorFields) {
        return;
      }
      withErrorNotice(error, '创建平台用户失败');
    } finally {
      setUserModalSubmitting(false);
    }
  }, [api, createUserForm, notify, refreshUserTable, withErrorNotice]);

  const handleSubmitStatusAction = useCallback(async () => {
    if (!userStatusActionTarget) {
      return;
    }
    const normalizedUserId = String(userStatusActionTarget.user_id || '').trim();
    if (!normalizedUserId) {
      return;
    }
    try {
      const values = await statusActionForm.validateFields();
      setStatusActionSubmittingByUserId((previous) => ({
        ...previous,
        [normalizedUserId]: true
      }));
      setUserStatusModalSubmitting(true);
      const payload = await api.updateUserStatus({
        user_id: normalizedUserId,
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
        text: '操作成功'
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
      setStatusActionSubmittingByUserId((previous) => ({
        ...previous,
        [normalizedUserId]: false
      }));
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

  const handleDirectToggleUserStatus = useCallback(
    async (record) => {
      const normalizedUserId = String(record?.user_id || '').trim();
      if (!normalizedUserId) {
        return;
      }
      if (statusActionSubmittingByUserId[normalizedUserId]) {
        return;
      }

      try {
        setStatusActionSubmittingByUserId((previous) => ({
          ...previous,
          [normalizedUserId]: true
        }));
        const targetStatus = statusToggleValue(record?.status);
        const payload = await api.updateUserStatus({
          user_id: normalizedUserId,
          status: targetStatus,
          reason: null
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
          text: '操作成功'
        });
        refreshUserTable();
      } catch (error) {
        withErrorNotice(error, '更新用户状态失败');
      } finally {
        setStatusActionSubmittingByUserId((previous) => ({
          ...previous,
          [normalizedUserId]: false
        }));
      }
    },
    [
      api,
      notify,
      refreshUserTable,
      statusActionSubmittingByUserId,
      withErrorNotice
    ]
  );

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
        phone: userFilters.phone || null,
        name: userFilters.name || null,
        createdAtStart: userFilters.created_at_start || null,
        createdAtEnd: userFilters.created_at_end || null
      });
      return {
        data: Array.isArray(payload.items) ? payload.items : [],
        total: Number(payload.total || 0),
        success: true
      };
    },
    [
      api,
      userFilters.created_at_end,
      userFilters.created_at_start,
      userFilters.name,
      userFilters.phone,
      userFilters.status,
      userTableRefreshToken
    ]
  );
  const userTableQueryKey = useMemo(
    () =>
      [
        userFilters.phone,
        userFilters.name,
        userFilters.status,
        userFilters.created_at_start,
        userFilters.created_at_end
      ].join('|'),
    [
      userFilters.created_at_end,
      userFilters.created_at_start,
      userFilters.name,
      userFilters.phone,
      userFilters.status
    ]
  );

  const openEditUser = useCallback(
    (record) => {
      if (!record?.user_id) {
        return;
      }
      void openUserDetail(record.user_id);
    },
    [openUserDetail]
  );

  const userColumns = useMemo(
    () => [
      {
        title: '用户ID',
        dataIndex: 'user_id',
        key: 'user_id',
        width: 280,
        render: (value) => <span data-testid={`platform-user-id-${value}`}>{value}</span>
      },
      {
        title: '手机号',
        dataIndex: 'phone',
        key: 'phone',
        width: 160
      },
      {
        title: '姓名',
        dataIndex: 'name',
        key: 'name',
        width: 160,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '部门',
        dataIndex: 'department',
        key: 'department',
        width: 180,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '角色',
        dataIndex: 'roles',
        key: 'roles',
        width: 240,
        render: (value) => {
          const roles = normalizeRoleList(value);
          if (roles.length < 1) {
            return '-';
          }
          return (
            <Space size={[4, 4]} wrap>
              {roles.map((role) => (
                <Tag key={role.role_id}>
                  {role.name || role.code || role.role_id}
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
        dataIndex: 'created_at',
        key: 'created_at',
        width: 180,
        render: (value) => normalizeDateTimeValue(value)
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
              data-testid={`platform-user-edit-${record.user_id}`}
              size="small"
              type="link"
              onClick={(event) => {
                event.stopPropagation();
                openEditUser(record);
              }}
            >
              编辑
            </Button>
            <Button
              data-testid={`platform-user-status-${record.user_id}`}
              size="small"
              type="link"
              loading={Boolean(statusActionSubmittingByUserId[record.user_id])}
              onClick={(event) => {
                event.stopPropagation();
                void handleDirectToggleUserStatus(record);
              }}
            >
              {statusToggleLabel(record.status)}
            </Button>
            {isDisabledStatus(record.status) ? (
              <Popconfirm
                title="确认删除该平台用户吗？"
                onConfirm={(event) => {
                  event?.stopPropagation?.();
                  void handleSoftDeleteUser(record.user_id);
                }}
                onCancel={(event) => {
                  event?.stopPropagation?.();
                }}
              >
                <Button
                  data-testid={`platform-user-delete-${record.user_id}`}
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
    [
      handleDirectToggleUserStatus,
      handleSoftDeleteUser,
      openEditUser,
      statusActionSubmittingByUserId
    ]
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
      <section data-testid="platform-users-module" style={{ display: 'grid', gap: 12 }}>
        <CustomFilter
          form={userFilterForm}
          initialValues={USER_FILTER_INITIAL_VALUES}
          onFinish={(values) => {
            const createdRange = Array.isArray(values.created_time)
              ? values.created_time
              : [];
            const [createdStart, createdEnd] = createdRange;
            setUserFilters({
              phone: String(values.phone || '').trim(),
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
            refreshUserTable();
          }}
          onReset={() => {
            setUserFilters({
              phone: '',
              name: '',
              status: '',
              created_at_start: '',
              created_at_end: ''
            });
            refreshUserTable();
          }}
        >
          <Form.Item label="手机号" name="phone">
            <Input data-testid="platform-user-filter-phone" placeholder="请输入手机号（精确）" allowClear />
          </Form.Item>
          <Form.Item label="姓名" name="name">
            <Input data-testid="platform-user-filter-name" placeholder="请输入姓名（模糊）" allowClear />
          </Form.Item>
          <Form.Item label="状态" name="status">
            <Select
              data-testid="platform-user-filter-status"
              options={USER_STATUS_SELECT_OPTIONS}
            />
          </Form.Item>
          <Form.Item label="创建时间" name="created_time">
            <DatePicker.RangePicker
              data-testid="platform-user-filter-created-time"
              showTime
              placeholder={['开始时间', '结束时间']}
              format="YYYY-MM-DD HH:mm:ss"
            />
          </Form.Item>
        </CustomFilter>

        <CustomCardTable
          key={userTableQueryKey}
          title="平台用户列表"
          rowKey="user_id"
          columns={userColumns}
          request={userTableRequest}
          onRow={(record) => ({
            onClick: () => {
              void openUserDetail(record.user_id);
            },
            style: { cursor: 'pointer' }
          })}
          extra={(
            <Button
              data-testid="platform-user-create-open"
              type="primary"
              onClick={() => {
                void loadEnabledRoleOptions();
                createUserForm.resetFields();
                setUserModalOpen(true);
              }}
            >
              新建
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
              <Input
                data-testid="platform-user-create-phone"
                maxLength={11}
                inputMode="numeric"
                placeholder="请输入手机号"
              />
            </CustomForm.Item>
            <CustomForm.Item
              label="姓名"
              name="name"
              rules={[
                {
                  required: true,
                  message: '请输入姓名'
                },
                {
                  max: 64,
                  message: '姓名长度不能超过 64'
                }
              ]}
            >
              <Input data-testid="platform-user-create-name" maxLength={64} placeholder="请输入姓名" />
            </CustomForm.Item>
            <CustomForm.Item
              label="部门"
              name="department"
              rules={[
                {
                  max: 128,
                  message: '部门长度不能超过 128'
                }
              ]}
            >
              <Input
                data-testid="platform-user-create-department"
                maxLength={128}
                placeholder="请输入部门（选填）"
              />
            </CustomForm.Item>
            <CustomForm.Item
              label="角色"
              name="role_ids"
            >
              <Select
                data-testid="platform-user-create-roles"
                mode="multiple"
                allowClear
                loading={enabledRoleOptionsLoading}
                options={enabledRoleOptions}
                placeholder="请选择角色（可多选）"
                optionFilterProp="label"
              />
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
                <Text>name: {String(userDetail.name || '').trim() || '-'}</Text>
                <Text>department: {String(userDetail.department || '').trim() || '-'}</Text>
                <Text>
                  roles:
                  {' '}
                  {normalizeRoleList(userDetail.roles).length > 0 ? (
                    <Space size={[4, 4]} wrap>
                      {normalizeRoleList(userDetail.roles).map((role) => (
                        <Tag key={role.role_id}>
                          {role.name || role.code || role.role_id}
                        </Tag>
                      ))}
                    </Space>
                  ) : (
                    '-'
                  )}
                </Text>
                <Text>status: {statusDisplayLabel(userDetail.status)}</Text>
                <Text>created_at: {normalizeDateTimeValue(userDetail.created_at)}</Text>
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
    </section>
  );
}
