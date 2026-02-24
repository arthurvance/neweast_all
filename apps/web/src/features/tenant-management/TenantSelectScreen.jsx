export default function TenantSelectScreen({
  tenantOptions = [],
  tenantSelectionValue = '',
  onTenantSelectionChange = null,
  onConfirm = null,
  isSubmitting = false
}) {
  return (
    <section
      style={{
        marginTop: 16,
        background: '#f6f8fa',
        borderRadius: 8,
        padding: 12,
        display: 'grid',
        gap: 12
      }}
    >
      <h2 style={{ margin: 0 }}>请选择组织</h2>
      <p style={{ margin: 0 }}>当前为组织入口，请先选择目标组织后进入工作台。</p>
      <select
        data-testid="tenant-select"
        value={tenantSelectionValue}
        onChange={(event) => onTenantSelectionChange?.(event.target.value)}
        disabled={isSubmitting}
        style={{ padding: '8px 10px', borderRadius: 6, border: '1px solid #d0d7de' }}
      >
        {tenantOptions.map((option) => (
          <option key={option.tenant_id} value={option.tenant_id}>
            {option.tenant_name || option.tenant_id}
          </option>
        ))}
      </select>
      <button
        data-testid="tenant-select-confirm"
        type="button"
        onClick={onConfirm}
        disabled={isSubmitting}
        style={{
          padding: '10px 14px',
          borderRadius: 6,
          border: '1px solid #1d4ed8',
          background: '#2563eb',
          color: '#fff'
        }}
      >
        {isSubmitting ? '处理中...' : '确认进入'}
      </button>
    </section>
  );
}
