import dayjs from 'dayjs';
import customParseFormat from 'dayjs/plugin/customParseFormat';

dayjs.extend(customParseFormat);

const DATE_TIME_FORMATS = Object.freeze([
  'YYYY-MM-DD HH:mm:ss',
  'YYYY-MM-DD HH:mm',
  'YYYY-MM-DDTHH:mm:ss.SSSZ',
  'YYYY-MM-DDTHH:mm:ssZ',
  'YYYY-MM-DDTHH:mm:ss.SSS[Z]',
  'YYYY-MM-DDTHH:mm:ss[Z]',
  'YYYY-MM-DDTHH:mm:ss',
  'YYYY-MM-DDTHH:mm'
]);

const parseDateTime = (value) => {
  if (value === null || value === undefined) {
    return null;
  }
  if (dayjs.isDayjs(value)) {
    return value.isValid() ? value : null;
  }
  if (value instanceof Date || typeof value === 'number') {
    const parsed = dayjs(value);
    return parsed.isValid() ? parsed : null;
  }
  const normalized = String(value || '').trim();
  if (!normalized) {
    return null;
  }
  for (const format of DATE_TIME_FORMATS) {
    const parsed = dayjs(normalized, format, true);
    if (parsed.isValid()) {
      return parsed;
    }
  }
  const fallback = dayjs(normalized);
  if (fallback.isValid()) {
    return fallback;
  }
  return null;
};

export const formatDateTimeMinute = (value) => {
  const normalized = String(value || '').trim();
  if (!normalized) {
    return '-';
  }
  const parsed = parseDateTime(value);
  if (!parsed) {
    return normalized;
  }
  return parsed.format('YYYY-MM-DD HH:mm');
};

export const toDateTimeMinuteEpoch = (value) => {
  const parsed = parseDateTime(value);
  if (!parsed) {
    return null;
  }
  return Math.floor(parsed.valueOf() / 60000);
};

