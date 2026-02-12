import { useEffect, useRef, useState } from 'react';

const API_BASE_URL = String(import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const OTP_RESEND_UNTIL_STORAGE_KEY_PREFIX = 'neweast.auth.otp.resend_until_ms';
const PHONE_PATTERN = /^1\d{10}$/;
const OTP_PATTERN = /^\d{6}$/;

const readJsonSafely = async (response) => {
  const contentType = response.headers.get('content-type') || '';
  if (
    contentType.includes('application/json') ||
    contentType.includes('application/problem+json')
  ) {
    try {
      return await response.json();
    } catch (_error) {
      return {};
    }
  }

  const text = await response.text();
  return {
    detail: text || '请求失败'
  };
};

const postJson = async (path, payload) => {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: 'POST',
    headers: {
      Accept: 'application/json, application/problem+json',
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  const body = await readJsonSafely(response);
  if (response.ok) {
    return body;
  }

  const error = new Error(body?.detail || '请求失败');
  error.status = response.status;
  error.payload = body || {};
  throw error;
};

const formatRetryMessage = (detail) => `${detail || '操作失败'}，请稍后重试`;

const normalizePhone = (value) => String(value || '').trim();
const otpResendStorageKeyOf = (rawPhone) => {
  const normalizedPhone = normalizePhone(rawPhone);
  if (!PHONE_PATTERN.test(normalizedPhone)) {
    return null;
  }
  return `${OTP_RESEND_UNTIL_STORAGE_KEY_PREFIX}:${normalizedPhone}`;
};

export default function App() {
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
  const [globalMessage, setGlobalMessage] = useState(null);
  const [isSendingOtp, setIsSendingOtp] = useState(false);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [loginResult, setLoginResult] = useState(null);
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
    setGlobalMessage(null);
  };

  const validatePhoneOnly = () => {
    const normalizedPhone = normalizePhone(phone);
    if (!PHONE_PATTERN.test(normalizedPhone)) {
      setFieldErrors((previous) => ({
        ...previous,
        phone: '请输入正确的 11 位手机号'
      }));
      setGlobalMessage(null);
      return null;
    }
    return normalizedPhone;
  };

  const handleModeSwitch = (nextMode) => {
    setMode(nextMode);
    setPassword('');
    setOtpCode('');
    setLoginResult(null);
    clearErrorsAndGlobal();
  };

  const handleSendOtp = async () => {
    const normalizedPhone = validatePhoneOnly();
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
      setGlobalMessage({
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
        setGlobalMessage(null);
      } else {
        if (error.status === 429 && payload.retry_after_seconds) {
          setServerCountdown(payload.retry_after_seconds, normalizedPhone);
        }
        setGlobalMessage({
          type: 'error',
          text: formatRetryMessage(payload.detail)
        });
        setFieldErrors({ phone: '', password: '', otpCode: '' });
      }
    } finally {
      setIsSendingOtp(false);
    }
  };

  const validateSubmitPayload = () => {
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
    setFieldErrors(nextErrors);
    setGlobalMessage(null);

    if (hasErrors) {
      return null;
    }

    if (mode === 'password') {
      return {
        path: '/auth/login',
        payload: {
          phone: normalizedPhone,
          password: String(password)
        }
      };
    }

    return {
      path: '/auth/otp/login',
      payload: {
        phone: normalizedPhone,
        otp_code: String(otpCode).trim()
      }
    };
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const request = validateSubmitPayload();
    if (!request) {
      setLoginResult(null);
      return;
    }

    setIsSubmitting(true);
    setLoginResult(null);
    try {
      const payload = await postJson(request.path, request.payload);
      setLoginResult({
        sessionId: payload.session_id,
        tokenType: payload.token_type
      });
      setOtpCode('');
      setPassword('');
      setGlobalMessage({
        type: 'success',
        text: '登录成功'
      });
      setFieldErrors({ phone: '', password: '', otpCode: '' });
    } catch (error) {
      const payload = error.payload || {};
      if (error.status === 400) {
        const fallback = validateSubmitPayload();
        if (fallback) {
          setGlobalMessage({
            type: 'error',
            text: formatRetryMessage(payload.detail)
          });
          setFieldErrors({ phone: '', password: '', otpCode: '' });
        }
      } else {
        setGlobalMessage({
          type: 'error',
          text: formatRetryMessage(payload.detail)
        });
        setFieldErrors({ phone: '', password: '', otpCode: '' });
      }
      setLoginResult(null);
    } finally {
      setIsSubmitting(false);
    }
  };

  return (
    <main style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 24, maxWidth: 560 }}>
      <h1 data-testid="page-title">Neweast 登录</h1>
      <p>支持密码登录与验证码登录，频控倒计时以服务端返回为准。</p>

      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button
          data-testid="mode-password"
          type="button"
          onClick={() => handleModeSwitch('password')}
          disabled={isSubmitting || isSendingOtp}
          style={{
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid #d0d7de',
            background: mode === 'password' ? '#dbeafe' : '#fff'
          }}
        >
          密码登录
        </button>
        <button
          data-testid="mode-otp"
          type="button"
          onClick={() => handleModeSwitch('otp')}
          disabled={isSubmitting || isSendingOtp}
          style={{
            padding: '8px 12px',
            borderRadius: 6,
            border: '1px solid #d0d7de',
            background: mode === 'otp' ? '#dbeafe' : '#fff'
          }}
        >
          验证码登录
        </button>
      </div>

      <form onSubmit={handleSubmit} style={{ display: 'grid', gap: 12 }}>
        <label style={{ display: 'grid', gap: 6 }}>
          <span>手机号</span>
          <input
            data-testid="input-phone"
            value={phone}
            onChange={(event) => setPhone(event.target.value)}
            placeholder="请输入 11 位手机号"
            autoComplete="tel"
            disabled={isSubmitting || isSendingOtp}
            style={{ padding: '8px 10px', borderRadius: 6, border: '1px solid #d0d7de' }}
          />
          {fieldErrors.phone ? <small style={{ color: '#dc2626' }}>{fieldErrors.phone}</small> : null}
        </label>

        {mode === 'password' ? (
          <label style={{ display: 'grid', gap: 6 }}>
            <span>密码</span>
            <input
              data-testid="input-password"
              type="password"
              value={password}
              onChange={(event) => setPassword(event.target.value)}
              placeholder="请输入密码"
              autoComplete="current-password"
              disabled={isSubmitting || isSendingOtp}
              style={{ padding: '8px 10px', borderRadius: 6, border: '1px solid #d0d7de' }}
            />
            {fieldErrors.password ? (
              <small style={{ color: '#dc2626' }}>{fieldErrors.password}</small>
            ) : null}
          </label>
        ) : (
          <label style={{ display: 'grid', gap: 6 }}>
            <span>验证码</span>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                data-testid="input-otp-code"
                value={otpCode}
                onChange={(event) => setOtpCode(event.target.value)}
                placeholder="请输入 6 位验证码"
                autoComplete="one-time-code"
                disabled={isSubmitting}
                style={{
                  flex: 1,
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: '1px solid #d0d7de'
                }}
              />
              <button
                data-testid="button-send-otp"
                type="button"
                onClick={handleSendOtp}
                disabled={isSendingOtp || isSubmitting || otpCountdownSeconds > 0}
                style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
              >
                {isSendingOtp
                  ? '发送中...'
                  : otpCountdownSeconds > 0
                    ? `${otpCountdownSeconds}s 后重试`
                    : '发送验证码'}
              </button>
            </div>
            {fieldErrors.otpCode ? (
              <small style={{ color: '#dc2626' }}>{fieldErrors.otpCode}</small>
            ) : null}
          </label>
        )}

        <button
          data-testid="button-submit-login"
          type="submit"
          disabled={isSubmitting || isSendingOtp}
          style={{
            padding: '10px 14px',
            borderRadius: 6,
            border: '1px solid #1d4ed8',
            background: '#2563eb',
            color: '#fff'
          }}
        >
          {isSubmitting ? '提交中...' : '登录'}
        </button>
      </form>

      {globalMessage ? (
        <p
          data-testid="message-global"
          style={{ marginTop: 16, color: globalMessage.type === 'error' ? '#dc2626' : '#16a34a' }}
        >
          {globalMessage.text}
        </p>
      ) : null}

      {loginResult ? (
        <pre
          style={{
            marginTop: 16,
            background: '#f6f8fa',
            padding: 12,
            borderRadius: 8,
            overflowX: 'auto'
          }}
        >
          {JSON.stringify(loginResult, null, 2)}
        </pre>
      ) : null}
    </main>
  );
}
