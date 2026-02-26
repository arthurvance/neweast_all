import { Typography } from 'antd';
import TenantOrgSwitchPage from './TenantOrgSwitchPage';

export default function TenantSwitchScreen({
  tenantOptions = [],
  activeTenantId = '',
  onSelect = null
}) {
  return (
    <section
      data-testid="tenant-org-switch-shell"
      style={{
        marginTop: 16,
        display: 'grid',
        justifyItems: 'center',
        gap: 32
      }}
    >
      <Typography.Title
        level={4}
        style={{ margin: 0 }}
      >
        切换组织
      </Typography.Title>
      <section
        data-testid="tenant-org-switch-list"
        style={{
          width: 'min(680px, 100%)',
          display: 'grid',
          gap: 12
        }}
      >
        <TenantOrgSwitchPage
          organizations={tenantOptions}
          activeTenantId={activeTenantId}
          onSelect={onSelect}
        />
      </section>
    </section>
  );
}
