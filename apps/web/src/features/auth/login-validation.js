const PHONE_PATTERN = /^1\d{10}$/;
const OTP_PATTERN = /^\d{6}$/;

const normalizePhone = (value) => String(value || '').trim();

const buildValidationResult = ({
  entryDomain,
  mode,
  phone,
  password,
  otpCode
}) => {
  const normalizedPhone = normalizePhone(phone);
  const nextErrors = { phone: '', password: '', otpCode: '' };

  if (!PHONE_PATTERN.test(normalizedPhone)) {
    nextErrors.phone = '请输入正确的 11 位手机号';
  }

  if (mode === 'password') {
    if (String(password).trim() === '') {
      nextErrors.password = '请输入密码';
    }
  } else if (!OTP_PATTERN.test(String(otpCode).trim())) {
    nextErrors.otpCode = '请输入 6 位数字验证码';
  }

  const hasErrors = Object.values(nextErrors).some((value) => value.length > 0);
  if (hasErrors) {
    return {
      fieldErrors: nextErrors,
      request: null
    };
  }

  if (mode === 'password') {
    return {
      fieldErrors: nextErrors,
      request: {
        path: '/auth/login',
        payload: {
          phone: normalizedPhone,
          password: String(password),
          entry_domain: entryDomain
        }
      }
    };
  }

  return {
    fieldErrors: nextErrors,
    request: {
      path: '/auth/otp/login',
      payload: {
        phone: normalizedPhone,
        otp_code: String(otpCode).trim(),
        entry_domain: entryDomain
      }
    }
  };
};

export const isValidPhone = (value) => PHONE_PATTERN.test(normalizePhone(value));

export const validatePlatformLoginSubmission = ({ mode, phone, password, otpCode }) =>
  buildValidationResult({
    entryDomain: 'platform',
    mode,
    phone,
    password,
    otpCode
  });

export const validateTenantLoginSubmission = ({ mode, phone, password, otpCode }) =>
  buildValidationResult({
    entryDomain: 'tenant',
    mode,
    phone,
    password,
    otpCode
  });

export const validateLoginSubmissionByDomain = ({
  entryDomain,
  mode,
  phone,
  password,
  otpCode
}) => {
  if (entryDomain === 'platform') {
    return validatePlatformLoginSubmission({
      mode,
      phone,
      password,
      otpCode
    });
  }

  return validateTenantLoginSubmission({
    mode,
    phone,
    password,
    otpCode
  });
};

export const validatePhoneOnlyByDomain = ({ entryDomain, phone }) => {
  const normalizedPhone = normalizePhone(phone);
  if (!PHONE_PATTERN.test(normalizedPhone)) {
    return {
      fieldErrors: { phone: '请输入正确的 11 位手机号', password: '', otpCode: '' },
      normalizedPhone: null
    };
  }
  return {
    fieldErrors: { phone: '', password: '', otpCode: '' },
    normalizedPhone,
    entryDomain
  };
};

export { normalizePhone };
