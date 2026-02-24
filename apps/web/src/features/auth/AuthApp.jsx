import { Grid, Spin } from 'antd';
import { Suspense, lazy, useEffect, useRef, useState } from 'react';
import {
  isValidPhone,
  normalizePhone,
  validateLoginSubmissionByDomain,
  validatePhoneOnlyByDomain
} from './login-validation';

const OTP_RESEND_UNTIL_STORAGE_KEY_PREFIX = 'neweast.auth.otp.resend_until_ms';
const PlatformLoginPage = lazy(() => import('./PlatformLoginPage'));
const TenantLoginPage = lazy(() => import('./TenantLoginPage'));

const otpResendStorageKeyOf = (rawPhone) => {
  const normalizedPhone = normalizePhone(rawPhone);
  if (!isValidPhone(normalizedPhone)) {
    return null;
  }
  return `${OTP_RESEND_UNTIL_STORAGE_KEY_PREFIX}:${normalizedPhone}`;
};

export default function AuthApp({
  visible = false,
  entryDomain = 'tenant',
  postJson,
  formatRetryMessage,
  onLoginPayload,
  onGlobalMessage,
  onLoginFailure
}) {
  const screens = Grid.useBreakpoint();
  const [mode, setMode] = useState('password');
  const [phone, setPhone] = useState('');
  const [password, setPassword] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [otpResendUntilMs, setOtpResendUntilMs] = useState(0);
  const [otpCountdownSeconds, setOtpCountdownSeconds] = useState(0);
  const [fieldErrors, setFieldErrors] = useState({
    phone: '',
    password: '',
    otpCode: ''
  });
  const [isSendingOtp, setIsSendingOtp] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const latestPhoneRef = useRef('');

  useEffect(() => {
    latestPhoneRef.current = normalizePhone(phone);
  }, [phone]);

  useEffect(() => {
    const storageKey = otpResendStorageKeyOf(phone);
    if (!storageKey) {
      setOtpResendUntilMs(0);
      return;
    }

    const stored = Number(window.localStorage.getItem(storageKey) || 0);
    if (Number.isFinite(stored) && stored > Date.now()) {
      setOtpResendUntilMs(stored);
      return;
    }

    setOtpResendUntilMs(0);
    if (stored > 0) {
      window.localStorage.removeItem(storageKey);
    }
  }, [phone]);

  useEffect(() => {
    const storageKey = otpResendStorageKeyOf(phone);
    if (!otpResendUntilMs) {
      setOtpCountdownSeconds(0);
      return;
    }

    const tick = () => {
      const remainingSeconds = Math.max(0, Math.ceil((otpResendUntilMs - Date.now()) / 1000));
      setOtpCountdownSeconds(remainingSeconds);
      if (remainingSeconds <= 0) {
        setOtpResendUntilMs(0);
        if (storageKey) {
          window.localStorage.removeItem(storageKey);
        }
      }
    };

    tick();
    const timer = window.setInterval(tick, 1000);
    return () => window.clearInterval(timer);
  }, [otpResendUntilMs, phone]);

  const setServerCountdown = (seconds, targetPhone) => {
    const normalizedTargetPhone = normalizePhone(targetPhone);
    const storageKey = otpResendStorageKeyOf(normalizedTargetPhone);
    const normalizedSeconds = Math.max(0, Number(seconds) || 0);
    if (normalizedSeconds <= 0 || !storageKey) {
      if (storageKey) {
        window.localStorage.removeItem(storageKey);
      }
      if (normalizedTargetPhone === latestPhoneRef.current) {
        setOtpResendUntilMs(0);
      }
      return;
    }
    const untilMs = Date.now() + normalizedSeconds * 1000;
    window.localStorage.setItem(storageKey, String(untilMs));
    if (normalizedTargetPhone === latestPhoneRef.current) {
      setOtpResendUntilMs(untilMs);
    }
  };

  const clearErrorsAndGlobal = () => {
    setFieldErrors({ phone: '', password: '', otpCode: '' });
    onGlobalMessage?.(null);
  };

  const resolvePhoneOnlyValidation = () => {
    const validationResult = validatePhoneOnlyByDomain({
      entryDomain,
      phone
    });
    if (!validationResult.normalizedPhone) {
      setFieldErrors(validationResult.fieldErrors);
      onGlobalMessage?.(null);
      return null;
    }
    return validationResult.normalizedPhone;
  };

  const resolveLoginSubmitRequest = () => {
    const validationResult = validateLoginSubmissionByDomain({
      entryDomain,
      mode,
      phone,
      password,
      otpCode
    });
    setFieldErrors(validationResult.fieldErrors);
    onGlobalMessage?.(null);
    return validationResult.request;
  };

  const handleModeSwitch = (nextMode) => {
    setMode(nextMode);
    setPassword('');
    setOtpCode('');
    clearErrorsAndGlobal();
  };

  const handleSendOtp = async () => {
    const normalizedPhone = resolvePhoneOnlyValidation();
    if (!normalizedPhone) {
      return;
    }

    clearErrorsAndGlobal();
    setIsSendingOtp(true);
    try {
      const payload = await postJson('/auth/otp/send', {
        phone: normalizedPhone
      });
      setServerCountdown(payload.resend_after_seconds, normalizedPhone);
      onGlobalMessage?.({
        type: 'success',
        text: '验证码已发送，请查收短信后继续登录'
      });
    } catch (error) {
      const payload = error.payload || {};
      if (error.status === 400) {
        setFieldErrors((previous) => ({
          ...previous,
          phone: '请输入正确的 11 位手机号'
        }));
        onGlobalMessage?.(null);
      } else {
        if (error.status === 429 && payload.retry_after_seconds) {
          setServerCountdown(payload.retry_after_seconds, normalizedPhone);
        }
        onGlobalMessage?.({
          type: 'error',
          text: formatRetryMessage(payload.detail)
        });
        setFieldErrors({ phone: '', password: '', otpCode: '' });
      }
    } finally {
      setIsSendingOtp(false);
    }
  };

  const handleSubmit = async () => {
    const request = resolveLoginSubmitRequest();
    if (!request) {
      onLoginFailure?.();
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = await postJson(request.path, request.payload);
      setOtpCode('');
      setPassword('');
      setFieldErrors({ phone: '', password: '', otpCode: '' });
      onLoginPayload?.(payload);
    } catch (error) {
      const payload = error.payload || {};
      if (error.status === 400) {
        const fallback = resolveLoginSubmitRequest();
        if (fallback) {
          onGlobalMessage?.({
            type: 'error',
            text: formatRetryMessage(payload.detail)
          });
          setFieldErrors({ phone: '', password: '', otpCode: '' });
        }
      } else {
        onGlobalMessage?.({
          type: 'error',
          text: formatRetryMessage(payload.detail)
        });
        setFieldErrors({ phone: '', password: '', otpCode: '' });
      }
      onLoginFailure?.();
    } finally {
      setIsSubmitting(false);
    }
  };

  if (!visible) {
    return null;
  }

  const LoginPage = entryDomain === 'platform' ? PlatformLoginPage : TenantLoginPage;

  return (
    <Suspense
      fallback={(
        <section
          data-testid="auth-login-page-loading"
          style={{
            minHeight: '100vh',
            display: 'grid',
            placeItems: 'center'
          }}
        >
          <Spin size="large" />
        </section>
      )}
    >
      <LoginPage
        screens={screens}
        mode={mode}
        onModeSwitch={handleModeSwitch}
        phone={phone}
        onPhoneChange={setPhone}
        password={password}
        onPasswordChange={setPassword}
        otpCode={otpCode}
        onOtpCodeChange={setOtpCode}
        fieldErrors={fieldErrors}
        isSubmitting={isSubmitting}
        isSendingOtp={isSendingOtp}
        otpCountdownSeconds={otpCountdownSeconds}
        onSendOtp={handleSendOtp}
        onSubmit={handleSubmit}
      />
    </Suspense>
  );
}
