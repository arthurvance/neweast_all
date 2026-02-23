import { useCallback, useEffect, useRef, useState } from 'react';
import {
  resolveTenantMutationUiState,
  resolveTenantRefreshUiState,
  resolveTenantMutationPermissionContext,
  resolveTenantMutationSessionState,
  readSessionIdFromAccessToken,
  isTenantRefreshResultBoundToCurrentSession
} from './tenant-mutation.mjs';
import { createLatestRequestExecutor } from './latest-request.mjs';
import PlatformGovernanceWorkbench from './features/platform-governance/PlatformGovernanceWorkbench';
import TenantGovernanceWorkbench from './features/tenant-governance/TenantGovernanceWorkbench';

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

const requestJson = async ({ path, method = 'POST', payload, accessToken }) => {
  const headers = {
    Accept: 'application/json, application/problem+json'
  };

  if (payload !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  if (accessToken) {
    headers.Authorization = `Bearer ${accessToken}`;
  }

  const response = await fetch(`${API_BASE_URL}${path}`, {
    method,
    headers,
    body: payload === undefined ? undefined : JSON.stringify(payload)
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

const postJson = async (path, payload) => requestJson({ path, payload, method: 'POST' });

const RETRY_SUFFIX = '请稍后重试';
const formatRetryMessage = (detail) => {
  const base = detail || '操作失败';
  if (String(base).includes(RETRY_SUFFIX)) {
    return base;
  }
  return `${base}，${RETRY_SUFFIX}`;
};

const normalizePhone = (value) => String(value || '').trim();
const otpResendStorageKeyOf = (rawPhone) => {
  const normalizedPhone = normalizePhone(rawPhone);
  if (!PHONE_PATTERN.test(normalizedPhone)) {
    return null;
  }
  return `${OTP_RESEND_UNTIL_STORAGE_KEY_PREFIX}:${normalizedPhone}`;
};

const asTenantOptions = (options) => {
  if (!Array.isArray(options)) {
    return [];
  }
  return options
    .map((item) => ({
      tenant_id: String(item?.tenant_id || '').trim(),
      tenant_name: item?.tenant_name ? String(item.tenant_name) : ''
    }))
    .filter((item) => item.tenant_id.length > 0);
};

const normalizeTenantMutationPayload = (payload) =>
  payload && typeof payload === 'object' ? payload : {};

const readTenantPermissionState = (sessionState) => {
  const permission = sessionState?.tenant_permission_context;
  if (permission && typeof permission === 'object') {
    return {
      scope_label: String(permission.scope_label || '组织权限快照（服务端）'),
      can_view_member_admin: Boolean(permission.can_view_member_admin),
      can_operate_member_admin: Boolean(permission.can_operate_member_admin),
      can_view_billing: Boolean(permission.can_view_billing),
      can_operate_billing: Boolean(permission.can_operate_billing)
    };
  }

  if (sessionState?.entry_domain !== 'tenant') {
    return {
      scope_label: '平台入口（无组织侧权限上下文）',
      can_view_member_admin: false,
      can_operate_member_admin: false,
      can_view_billing: false,
      can_operate_billing: false
    };
  }

  return {
    scope_label: '组织权限加载中（以服务端返回为准）',
    can_view_member_admin: false,
    can_operate_member_admin: false,
    can_view_billing: false,
    can_operate_billing: false
  };
};

const selectPermissionUiState = (permissionState) => {
  const canAccessMemberAdmin = Boolean(
    permissionState?.can_view_member_admin
    && permissionState?.can_operate_member_admin
  );
  const canAccessBilling = Boolean(
    permissionState?.can_view_billing
    && permissionState?.can_operate_billing
  );

  return {
    menu: {
      member_admin: canAccessMemberAdmin,
      billing: canAccessBilling
    },
    action: {
      member_admin: canAccessMemberAdmin,
      billing: canAccessBilling
    }
  };
};

export default function App() {
  const [mode, setMode] = useState('password');
  const [entryDomain, setEntryDomain] = useState('platform');
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
  const [isTenantSubmitting, setIsTenantSubmitting] = useState(false);
  const [screen, setScreen] = useState('login');
  const [sessionState, setSessionState] = useState(null);
  const [tenantOptions, setTenantOptions] = useState([]);
  const [tenantSelectionValue, setTenantSelectionValue] = useState('');
  const [tenantSwitchValue, setTenantSwitchValue] = useState('');
  const latestPhoneRef = useRef('');
  const sessionStateRef = useRef(null);
  const tenantContextRefreshExecutorRef = useRef(createLatestRequestExecutor());
  const permissionState = readTenantPermissionState(sessionState);
  const permissionUiState = selectPermissionUiState(permissionState);

  useEffect(() => {
    latestPhoneRef.current = normalizePhone(phone);
  }, [phone]);

  useEffect(() => {
    sessionStateRef.current = sessionState;
  }, [sessionState]);

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
    clearErrorsAndGlobal();
  };

  const handleEntryDomainSwitch = (nextDomain) => {
    setEntryDomain(nextDomain);
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
          password: String(password),
          entry_domain: entryDomain
        }
      };
    }

    return {
      path: '/auth/otp/login',
      payload: {
        phone: normalizedPhone,
        otp_code: String(otpCode).trim(),
        entry_domain: entryDomain
      }
    };
  };

  const refreshTenantContext = async (accessToken, options = {}) => {
    const requestSessionId = readSessionIdFromAccessToken(accessToken);
    const expectedSession = options.expectedSession || null;
    return tenantContextRefreshExecutorRef.current.run(
      () =>
        requestJson({
          path: '/auth/tenant/options',
          method: 'GET',
          accessToken
        }),
      (payload) => {
        const nextTenantOptions = asTenantOptions(payload.tenant_options);
        setSessionState((previous) => ({
          ...(previous || {}),
          session_id: payload.session_id || previous?.session_id || null,
          entry_domain: payload.entry_domain,
          active_tenant_id: payload.active_tenant_id,
          tenant_selection_required: Boolean(payload.tenant_selection_required),
          tenant_permission_context: payload.tenant_permission_context || null
        }));
        setTenantSelectionValue((previous) => {
          const nextUiState = resolveTenantRefreshUiState({
            tenantOptions: nextTenantOptions,
            activeTenantId: payload.active_tenant_id,
            previousTenantSelectionValue: previous
          });
          if (nextUiState.tenantOptionsUpdate !== undefined) {
            setTenantOptions(nextUiState.tenantOptionsUpdate);
          }
          setTenantSwitchValue(nextUiState.tenantSwitchValue);
          return nextUiState.tenantSelectionValue;
        });
      },
      {
        isResultCurrent: (payload) =>
          isTenantRefreshResultBoundToCurrentSession({
            currentSession: sessionStateRef.current,
            expectedSession,
            requestAccessToken: accessToken,
            requestSessionId,
            responsePayload: payload
          })
      }
    );
  };

  const applyTenantMutationPayload = (payload, fallbackTenantId) => {
    const normalizedPayload = normalizeTenantMutationPayload(payload);
    const hasPermissionContext = Object.prototype.hasOwnProperty.call(
      normalizedPayload,
      'tenant_permission_context'
    );
    const normalizedActiveTenantId = String(
      normalizedPayload.active_tenant_id || fallbackTenantId || ''
    ).trim();
    const nextActiveTenantId = normalizedActiveTenantId || null;
    const hasTenantOptions = Array.isArray(normalizedPayload.tenant_options);
    const nextTenantOptions = asTenantOptions(normalizedPayload.tenant_options);
    const nextTenantPermissionContext = resolveTenantMutationPermissionContext({
      hasTenantPermissionContext: hasPermissionContext,
      nextTenantPermissionContext: normalizedPayload.tenant_permission_context
    });
    const nextSessionState = resolveTenantMutationSessionState({
      previousSessionState: sessionStateRef.current,
      payload: normalizedPayload,
      nextActiveTenantId,
      nextTenantPermissionContext
    });
    const nextAccessToken = String(nextSessionState?.access_token || '').trim();

    // Keep the session binding reference in sync before starting refresh.
    sessionStateRef.current = nextSessionState;
    setSessionState(nextSessionState);

    setTenantSelectionValue((previous) => {
      const nextUiState = resolveTenantMutationUiState({
        nextTenantOptions,
        nextActiveTenantId,
        hasTenantOptions,
        previousTenantSelectionValue: previous,
        previousTenantOptions: tenantOptions
      });
      if (nextUiState.tenantOptionsUpdate !== undefined) {
        setTenantOptions(nextUiState.tenantOptionsUpdate);
      }
      setTenantSwitchValue(nextUiState.tenantSwitchValue);
      return nextUiState.tenantSelectionValue;
    });

    return {
      nextAccessToken,
      nextSessionState
    };
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    const request = validateSubmitPayload();
    if (!request) {
      setSessionState(null);
      setScreen('login');
      return;
    }

    setIsSubmitting(true);
    try {
      const payload = await postJson(request.path, request.payload);
      const options = asTenantOptions(payload.tenant_options);
      const resolvedSession = {
        access_token: payload.access_token,
        session_id: payload.session_id,
        entry_domain: payload.entry_domain,
        active_tenant_id: payload.active_tenant_id,
        tenant_selection_required: Boolean(payload.tenant_selection_required),
        tenant_permission_context: payload.tenant_permission_context || null
      };

      setSessionState(resolvedSession);
      setTenantOptions(options);
      setOtpCode('');
      setPassword('');
      setFieldErrors({ phone: '', password: '', otpCode: '' });

      if (resolvedSession.entry_domain === 'tenant') {
        if (options.length > 0) {
          const firstTenant = options[0].tenant_id;
          setTenantSelectionValue(firstTenant);
          setTenantSwitchValue(resolvedSession.active_tenant_id || firstTenant);
        }

        if (resolvedSession.tenant_selection_required) {
          setScreen('tenant-select');
          setGlobalMessage({
            type: 'success',
            text: '登录成功，请先选择组织后进入工作台'
          });
        } else {
          setScreen('dashboard');
          setGlobalMessage({
            type: 'success',
            text: '登录成功'
          });
        }
      } else {
        setScreen('dashboard');
        setGlobalMessage({
          type: 'success',
          text: '登录成功'
        });
      }
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
      setSessionState(null);
      setScreen('login');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleTenantSelect = async () => {
    if (!sessionState?.access_token) {
      return;
    }
    const accessToken = sessionState.access_token;
    const tenantId = String(tenantSelectionValue || '').trim();
    if (!tenantId) {
      setGlobalMessage({ type: 'error', text: '请选择组织后再继续' });
      return;
    }

    setIsTenantSubmitting(true);
    try {
      const payload = await requestJson({
        path: '/auth/tenant/select',
        method: 'POST',
        payload: { tenant_id: tenantId },
        accessToken
      });
      const { nextAccessToken, nextSessionState } = applyTenantMutationPayload(payload, tenantId);
      setScreen('dashboard');
      setGlobalMessage({ type: 'success', text: '组织选择成功，已进入工作台' });
      void refreshTenantContext(nextAccessToken || accessToken, {
        expectedSession: nextSessionState
      }).catch(() => {
        setGlobalMessage((previous) => ({
          type: 'error',
          text: previous?.type === 'success'
            ? `${previous.text}（注意：组织上下文刷新失败，权限视图可能过期）`
            : '组织上下文刷新失败，当前权限视图可能过期'
        }));
      });
    } catch (error) {
      const payload = error.payload || {};
      setGlobalMessage({
        type: 'error',
        text: formatRetryMessage(payload.detail)
      });
    } finally {
      setIsTenantSubmitting(false);
    }
  };

  const handleTenantSwitch = async () => {
    if (!sessionState?.access_token) {
      return;
    }
    const accessToken = sessionState.access_token;
    const tenantId = String(tenantSwitchValue || '').trim();
    if (!tenantId) {
      setGlobalMessage({ type: 'error', text: '请选择目标组织后再切换' });
      return;
    }

    setIsTenantSubmitting(true);
    try {
      const payload = await requestJson({
        path: '/auth/tenant/switch',
        method: 'POST',
        payload: { tenant_id: tenantId },
        accessToken
      });
      const { nextAccessToken, nextSessionState } = applyTenantMutationPayload(payload, tenantId);
      setGlobalMessage({ type: 'success', text: '组织切换成功，权限已即时生效' });
      void refreshTenantContext(nextAccessToken || accessToken, {
        expectedSession: nextSessionState
      }).catch(() => {
        setGlobalMessage((previous) => ({
          type: 'error',
          text: previous?.type === 'success'
            ? `${previous.text}（注意：组织上下文刷新失败，权限视图可能过期）`
            : '组织上下文刷新失败，当前权限视图可能过期'
        }));
      });
    } catch (error) {
      const payload = error.payload || {};
      setGlobalMessage({
        type: 'error',
        text: formatRetryMessage(payload.detail)
      });
    } finally {
      setIsTenantSubmitting(false);
    }
  };

  const refreshTenantPermissionContextFailClosed = useCallback(async () => {
    const currentSession = sessionStateRef.current;
    const accessToken = String(currentSession?.access_token || '').trim();
    if (!accessToken) {
      const error = new Error('当前会话无效，请重新登录');
      error.payload = {
        detail: '当前会话无效，请重新登录'
      };
      throw error;
    }

    try {
      await refreshTenantContext(accessToken, {
        expectedSession: currentSession
      });
    } catch (error) {
      setSessionState((previous) => {
        if (!previous) {
          return previous;
        }
        return {
          ...previous,
          tenant_permission_context: null
        };
      });
      setGlobalMessage({
        type: 'error',
        text: formatRetryMessage(
          error?.payload?.detail || '组织上下文刷新失败，已按 fail-closed 收敛权限'
        )
      });
      error.uiMessageHandled = true;
      throw error;
    }
  }, [refreshTenantContext]);

  const isTenantEntry = entryDomain === 'tenant';

  return (
    <main style={{ fontFamily: 'Inter, system-ui, sans-serif', padding: 24, maxWidth: 560 }}>
      <h1 data-testid="page-title">Neweast 登录</h1>
      <p>支持双入口域识别、密码/验证码登录与组织选择/切换。</p>

      {screen === 'login' ? (
        <>
          <section style={{ marginBottom: 16 }}>
            <p style={{ margin: '0 0 8px 0' }}>入口域</p>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                data-testid="entry-platform"
                type="button"
                onClick={() => handleEntryDomainSwitch('platform')}
                disabled={isSubmitting || isSendingOtp}
                style={{
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #d0d7de',
                  background: !isTenantEntry ? '#dbeafe' : '#fff'
                }}
              >
                平台入口
              </button>
              <button
                data-testid="entry-tenant"
                type="button"
                onClick={() => handleEntryDomainSwitch('tenant')}
                disabled={isSubmitting || isSendingOtp}
                style={{
                  padding: '8px 12px',
                  borderRadius: 6,
                  border: '1px solid #d0d7de',
                  background: isTenantEntry ? '#dbeafe' : '#fff'
                }}
              >
                组织入口
              </button>
            </div>
          </section>

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
        </>
      ) : null}

      {screen === 'tenant-select' ? (
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
            onChange={(event) => setTenantSelectionValue(event.target.value)}
            disabled={isTenantSubmitting}
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
            onClick={handleTenantSelect}
            disabled={isTenantSubmitting}
            style={{
              padding: '10px 14px',
              borderRadius: 6,
              border: '1px solid #1d4ed8',
              background: '#2563eb',
              color: '#fff'
            }}
          >
            {isTenantSubmitting ? '处理中...' : '确认进入'}
          </button>
        </section>
      ) : null}

      {screen === 'dashboard' ? (
        <section
          data-testid="dashboard-panel"
          style={{
            marginTop: 16,
            background: '#f6f8fa',
            borderRadius: 8,
            padding: 12,
            display: 'grid',
            gap: 12
          }}
        >
          <h2 style={{ margin: 0 }}>已登录工作台</h2>
          <p style={{ margin: 0 }}>入口域：{sessionState?.entry_domain || 'platform'}</p>
          <p style={{ margin: 0 }}>会话：{sessionState?.session_id || '-'}</p>
          {sessionState?.entry_domain === 'platform' ? (
            <section
              data-testid="platform-governance-panel"
              style={{
                display: 'grid',
                gap: 8,
                background: '#fff',
                borderRadius: 6,
                border: '1px solid #e5e7eb',
                padding: 10
              }}
            >
              <p style={{ margin: 0 }}>平台治理工作台（用户管理 + 角色管理）</p>
              <PlatformGovernanceWorkbench accessToken={sessionState?.access_token} />
            </section>
          ) : null}
          {sessionState?.entry_domain === 'tenant' ? (
            <>
              <p style={{ margin: 0 }}>
                当前组织：{sessionState?.active_tenant_id || '未选择'}
              </p>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <select
                  data-testid="tenant-switch"
                  value={tenantSwitchValue}
                  onChange={(event) => setTenantSwitchValue(event.target.value)}
                  disabled={isTenantSubmitting}
                  style={{
                    flex: 1,
                    padding: '8px 10px',
                    borderRadius: 6,
                    border: '1px solid #d0d7de'
                  }}
                >
                  {tenantOptions.map((option) => (
                    <option key={option.tenant_id} value={option.tenant_id}>
                      {option.tenant_name || option.tenant_id}
                    </option>
                  ))}
                </select>
                <button
                  data-testid="tenant-switch-confirm"
                  type="button"
                  onClick={handleTenantSwitch}
                  disabled={isTenantSubmitting || tenantOptions.length === 0}
                  style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
                >
                  {isTenantSubmitting ? '切换中...' : '切换组织'}
                </button>
              </div>
              <section
                data-testid="permission-panel"
                style={{
                  display: 'grid',
                  gap: 8,
                  background: '#fff',
                  borderRadius: 6,
                  border: '1px solid #e5e7eb',
                  padding: 10
                }}
              >
                <p data-testid="permission-scope" style={{ margin: 0 }}>
                  权限上下文：{permissionState.scope_label}
                </p>
                <nav aria-label="tenant-permission-menu">
                  <p style={{ margin: 0 }}>可见菜单</p>
                  <ul style={{ margin: '4px 0 0 20px', padding: 0 }}>
                    {permissionUiState.menu.member_admin ? (
                      <li data-testid="menu-member-admin">成员管理</li>
                    ) : null}
                    {permissionUiState.menu.billing ? (
                      <li data-testid="menu-billing">账单配置</li>
                    ) : null}
                    {!permissionUiState.menu.member_admin && !permissionUiState.menu.billing ? (
                      <li data-testid="menu-empty">当前无可见菜单</li>
                    ) : null}
                  </ul>
                </nav>
                {permissionUiState.action.member_admin ? (
                  <button
                    data-testid="permission-member-admin-button"
                    type="button"
                    style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
                  >
                    成员管理
                  </button>
                ) : null}
                {permissionUiState.action.billing ? (
                  <button
                    data-testid="permission-billing-button"
                    type="button"
                    style={{ padding: '8px 12px', borderRadius: 6, border: '1px solid #d0d7de' }}
                  >
                    账单配置
                  </button>
                ) : null}
              </section>
              {permissionUiState.menu.member_admin ? (
                <section
                  data-testid="tenant-governance-panel"
                  style={{
                    display: 'grid',
                    gap: 8,
                    background: '#fff',
                    borderRadius: 6,
                    border: '1px solid #e5e7eb',
                    padding: 10
                  }}
                >
                  <p style={{ margin: 0 }}>组织治理工作台（成员管理 + 角色管理）</p>
                  <TenantGovernanceWorkbench
                    accessToken={sessionState?.access_token}
                    onTenantPermissionContextRefresh={refreshTenantPermissionContextFailClosed}
                  />
                </section>
              ) : (
                <section
                  data-testid="tenant-governance-panel"
                  style={{
                    display: 'grid',
                    gap: 8,
                    background: '#fff',
                    borderRadius: 6,
                    border: '1px solid #e5e7eb',
                    padding: 10
                  }}
                >
                  <p style={{ margin: 0 }}>当前组织无成员治理权限，治理工作台已按 fail-closed 隐藏。</p>
                </section>
              )}
            </>
          ) : null}
        </section>
      ) : null}

      {globalMessage ? (
        <p
          data-testid="message-global"
          style={{ marginTop: 16, color: globalMessage.type === 'error' ? '#dc2626' : '#16a34a' }}
        >
          {globalMessage.text}
        </p>
      ) : null}
    </main>
  );
}
