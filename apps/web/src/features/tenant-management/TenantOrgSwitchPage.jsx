import { Card, Empty, Space, Tag, Typography } from 'antd';

const { Text } = Typography;

const toOwnerLabel = ({ owner_name: ownerName, owner_phone: ownerPhone }) => {
  const normalizedOwnerName = String(ownerName || '').trim();
  const normalizedOwnerPhone = String(ownerPhone || '').trim();
  if (!normalizedOwnerName && !normalizedOwnerPhone) {
    return '-';
  }
  if (!normalizedOwnerName) {
    return normalizedOwnerPhone;
  }
  if (!normalizedOwnerPhone) {
    return normalizedOwnerName;
  }
  return `${normalizedOwnerName}（${normalizedOwnerPhone}）`;
};

export default function TenantOrgSwitchPage({
  organizations = [],
  activeTenantId = '',
  onSelect = null
}) {
  const normalizedActiveTenantId = String(activeTenantId || '').trim();
  const normalizedOrganizations = (Array.isArray(organizations) ? organizations : [])
    .map((organization) => ({
      tenant_id: String(organization?.tenant_id || '').trim(),
      tenant_name: String(organization?.tenant_name || '').trim(),
      owner_name: String(organization?.owner_name || '').trim(),
      owner_phone: String(organization?.owner_phone || '').trim()
    }))
    .filter((organization) => organization.tenant_id);

  if (normalizedOrganizations.length < 1) {
    return (
      <Empty data-testid="tenant-org-switch-page-empty" description="暂无可切换组织" />
    );
  }

  return normalizedOrganizations.map((organization) => {
    const isActive = organization.tenant_id === normalizedActiveTenantId;
    return (
      <Card
        key={organization.tenant_id}
        data-testid={`tenant-org-switch-card-${organization.tenant_id}`}
        hoverable
        size="small"
        onClick={() => {
          if (typeof onSelect === 'function') {
            onSelect(organization.tenant_id);
          }
        }}
        style={{
          borderColor: isActive ? '#1677ff' : undefined
        }}
      >
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Space
            align="center"
            style={{ width: '100%', justifyContent: 'space-between' }}
          >
            <Text strong style={{ fontSize: 16 }}>
              {organization.tenant_name || organization.tenant_id}
            </Text>
            {isActive ? <Tag color="blue">当前组织</Tag> : null}
          </Space>
          <Text type="secondary">
            组织ID：{organization.tenant_id}
          </Text>
          <Text>
            负责人：{toOwnerLabel(organization)}
          </Text>
        </Space>
      </Card>
    );
  });
}
