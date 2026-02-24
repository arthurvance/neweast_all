export const normalizeEntryDomain = (value) =>
  String(value || '').trim().toLowerCase() === 'tenant' ? 'tenant' : 'platform';

export const asTenantOptions = (options) => {
  if (!Array.isArray(options)) {
    return [];
  }
  return options
    .map((item) => ({
      tenant_id: String(item?.tenant_id || '').trim(),
      tenant_name: item?.tenant_name ? String(item.tenant_name) : '',
      owner_name: item?.owner_name ? String(item.owner_name) : '',
      owner_phone: item?.owner_phone ? String(item.owner_phone) : ''
    }))
    .filter((item) => item.tenant_id.length > 0);
};

export const normalizeUserName = (value) => {
  const normalized = String(value || '').trim();
  return normalized || null;
};
