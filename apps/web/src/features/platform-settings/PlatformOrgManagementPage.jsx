import { useCallback, useMemo, useState } from 'react';
import {
  Alert,
  Button,
  DatePicker,
  Form,
  Input,
  Modal,
  Select,
  message
} from 'antd';
import CustomCardTable from '../../components/CustomCardTable';
import CustomFilter from '../../components/CustomFilter';
import {
  createPlatformSettingsApi,
  toProblemMessage
} from '../../api/platform-settings.mjs';
import { formatDateTimeMinute } from '../../utils/date-time.mjs';

const ORG_STATUS_SELECT_OPTIONS = [
  { label: '全部', value: '' },
  { label: '启用', value: 'active' },
  { label: '禁用', value: 'disabled' }
];

const ORG_FILTER_INITIAL_VALUES = Object.freeze({
  org_name: '',
  owner: '',
  status: '',
  created_time: []
});
const ORG_CREATE_INITIAL_VALUES = Object.freeze({
  org_name: '',
  initial_owner_name: '',
  initial_owner_phone: ''
});

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

const renderOwnerLabel = (record = {}) => {
  const ownerName = String(record?.owner_name || '').trim();
  const ownerPhone = String(record?.owner_phone || '').trim();
  if (!ownerName && !ownerPhone) {
    return '-';
  }
  if (!ownerName) {
    return ownerPhone;
  }
  if (!ownerPhone) {
    return ownerName;
  }
  return `${ownerName}（${ownerPhone}）`;
};

export default function PlatformOrgManagementPage({ accessToken }) {
  const api = useMemo(
    () => createPlatformSettingsApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();
  const [orgFilterForm] = Form.useForm();
  const [orgCreateForm] = Form.useForm();

  const [orgFilters, setOrgFilters] = useState({
    org_name: '',
    owner: '',
    status: '',
    created_at_start: '',
    created_at_end: ''
  });
  const [orgTableRefreshToken, setOrgTableRefreshToken] = useState(0);
  const [orgCreateModalOpen, setOrgCreateModalOpen] = useState(false);
  const [orgCreateSubmitting, setOrgCreateSubmitting] = useState(false);

  const refreshOrgTable = useCallback(() => {
    setOrgTableRefreshToken((previous) => previous + 1);
  }, []);

  const openOrgCreateModal = useCallback(() => {
    orgCreateForm.setFieldsValue(ORG_CREATE_INITIAL_VALUES);
    setOrgCreateModalOpen(true);
  }, [orgCreateForm]);

  const closeOrgCreateModal = useCallback(() => {
    if (orgCreateSubmitting) {
      return;
    }
    setOrgCreateModalOpen(false);
    orgCreateForm.resetFields();
  }, [orgCreateForm, orgCreateSubmitting]);

  const submitOrgCreate = useCallback(async () => {
    let values = null;
    try {
      values = await orgCreateForm.validateFields();
    } catch (error) {
      return;
    }

    setOrgCreateSubmitting(true);
    try {
      const payload = await api.createOrg({
        orgName: String(values.org_name || '').trim(),
        initialOwnerName: String(values.initial_owner_name || '').trim(),
        initialOwnerPhone: String(values.initial_owner_phone || '').trim()
      });
      messageApi.success(
        `组织创建成功（request_id: ${String(payload?.request_id || '').trim() || '-'}）`
      );
      setOrgCreateModalOpen(false);
      orgCreateForm.resetFields();
      refreshOrgTable();
    } catch (error) {
      const errorCode = String(error?.payload?.error_code || '').trim();
      if (errorCode === 'ORG-409-ORG-CONFLICT') {
        messageApi.error('组织名称已存在，请重新输入');
        return;
      }
      messageApi.error(toProblemMessage(error, '创建组织失败'));
    } finally {
      setOrgCreateSubmitting(false);
    }
  }, [api, messageApi, orgCreateForm, refreshOrgTable]);

  const orgTableRequest = useCallback(
    async (params) => {
      try {
        const payload = await api.listOrgs({
          page: params.current,
          pageSize: params.pageSize,
          orgName: orgFilters.org_name || null,
          owner: orgFilters.owner || null,
          status: orgFilters.status || null,
          createdAtStart: orgFilters.created_at_start || null,
          createdAtEnd: orgFilters.created_at_end || null
        });
        return {
          data: Array.isArray(payload.items) ? payload.items : [],
          total: Number(payload.total || 0),
          success: true
        };
      } catch (error) {
        messageApi.error(toProblemMessage(error, '加载组织列表失败'));
        return {
          data: [],
          total: 0,
          success: false
        };
      }
    },
    [
      api,
      messageApi,
      orgFilters.created_at_end,
      orgFilters.created_at_start,
      orgFilters.org_name,
      orgFilters.owner,
      orgFilters.status,
      orgTableRefreshToken
    ]
  );

  const orgColumns = useMemo(
    () => [
      {
        title: '组织ID',
        dataIndex: 'org_id',
        key: 'org_id',
        width: 280
      },
      {
        title: '组织名称',
        dataIndex: 'org_name',
        key: 'org_name',
        width: 220,
        render: (value) => String(value || '').trim() || '-'
      },
      {
        title: '负责人',
        key: 'owner',
        width: 260,
        render: (_value, record) => renderOwnerLabel(record)
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
      }
    ],
    []
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
      <section data-testid="platform-orgs-module" style={{ display: 'grid', gap: 12 }}>
        <CustomFilter
          form={orgFilterForm}
          initialValues={ORG_FILTER_INITIAL_VALUES}
          onFinish={(values) => {
            const createdRange = Array.isArray(values.created_time)
              ? values.created_time
              : [];
            const [createdStart, createdEnd] = createdRange;
            setOrgFilters({
              org_name: String(values.org_name || '').trim(),
              owner: String(values.owner || '').trim(),
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
            refreshOrgTable();
          }}
          onReset={() => {
            setOrgFilters({
              org_name: '',
              owner: '',
              status: '',
              created_at_start: '',
              created_at_end: ''
            });
            refreshOrgTable();
          }}
        >
          <Form.Item label="组织名称" name="org_name">
            <Input
              data-testid="platform-org-filter-name"
              placeholder="请输入组织名称（模糊）"
              allowClear
            />
          </Form.Item>
          <Form.Item label="负责人" name="owner">
            <Input
              data-testid="platform-org-filter-owner"
              placeholder="请输入负责人姓名（模糊）或手机号（精确）"
              allowClear
            />
          </Form.Item>
          <Form.Item label="状态" name="status">
            <Select
              data-testid="platform-org-filter-status"
              options={ORG_STATUS_SELECT_OPTIONS}
            />
          </Form.Item>
          <Form.Item label="创建时间" name="created_time">
            <DatePicker.RangePicker
              data-testid="platform-org-filter-created-time"
              showTime
              placeholder={['开始时间', '结束时间']}
              format="YYYY-MM-DD HH:mm:ss"
            />
          </Form.Item>
        </CustomFilter>

        <CustomCardTable
          title="组织列表"
          extra={(
            <Button
              type="primary"
              data-testid="platform-org-create-open"
              onClick={openOrgCreateModal}
            >
              新建
            </Button>
          )}
          rowKey="org_id"
          columns={orgColumns}
          request={orgTableRequest}
        />

        <Modal
          title="新建组织"
          open={orgCreateModalOpen}
          onCancel={closeOrgCreateModal}
          onOk={submitOrgCreate}
          okText="确定"
          cancelText="取消"
          destroyOnClose
          maskClosable={!orgCreateSubmitting}
          confirmLoading={orgCreateSubmitting}
        >
          <Form
            form={orgCreateForm}
            layout="vertical"
            preserve={false}
            initialValues={ORG_CREATE_INITIAL_VALUES}
          >
            <Form.Item
              label="组织名称"
              name="org_name"
              rules={[
                {
                  required: true,
                  message: '请输入组织名称'
                },
                {
                  validator: (_rule, value) => {
                    if (typeof value !== 'string' || value.trim()) {
                      return Promise.resolve();
                    }
                    return Promise.reject(new Error('请输入组织名称'));
                  }
                }
              ]}
            >
              <Input
                data-testid="platform-org-create-name"
                placeholder="请输入组织名称"
                maxLength={128}
              />
            </Form.Item>
            <Form.Item
              label="负责人姓名"
              name="initial_owner_name"
              rules={[
                {
                  required: true,
                  message: '请输入负责人姓名'
                },
                {
                  validator: (_rule, value) => {
                    if (typeof value !== 'string' || value.trim()) {
                      return Promise.resolve();
                    }
                    return Promise.reject(new Error('请输入负责人姓名'));
                  }
                }
              ]}
            >
              <Input
                data-testid="platform-org-create-owner-name"
                placeholder="请输入负责人姓名"
                maxLength={64}
              />
            </Form.Item>
            <Form.Item
              label="负责人手机号"
              name="initial_owner_phone"
              rules={[
                {
                  required: true,
                  message: '请输入负责人手机号'
                },
                {
                  pattern: /^1\d{10}$/,
                  message: '请输入11位手机号'
                }
              ]}
            >
              <Input
                data-testid="platform-org-create-owner-phone"
                placeholder="请输入负责人手机号"
                maxLength={11}
              />
            </Form.Item>
          </Form>
        </Modal>
      </section>
    </section>
  );
}
