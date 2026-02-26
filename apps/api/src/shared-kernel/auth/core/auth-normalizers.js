'use strict';

const normalizeTrimmedString = (value) => String(value || '').trim();

const normalizeLowerCaseString = (value) => normalizeTrimmedString(value).toLowerCase();

const normalizeNullableString = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  const normalized = normalizeTrimmedString(value);
  return normalized.length > 0 ? normalized : null;
};

module.exports = {
  normalizeTrimmedString,
  normalizeLowerCaseString,
  normalizeNullableString
};
