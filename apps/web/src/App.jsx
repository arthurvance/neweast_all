import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Button,
  Card,
  Flex,
  Form,
  Grid,
  Image,
  Input,
  message,
  Space,
  Typography
} from 'antd';
import {
  resolveTenantMutationUiState,
  resolveTenantRefreshUiState,
  resolveTenantMutationPermissionContext,
  resolveTenantMutationSessionState,
  readSessionIdFromAccessToken,
  isTenantRefreshResultBoundToCurrentSession
} from './tenant-mutation.mjs';
import { createLatestRequestExecutor } from './latest-request.mjs';
import PlatformManagementLayoutPage from './features/platform-management/PlatformManagementLayoutPage';
import TenantGovernanceWorkbench from './features/tenant-governance/TenantGovernanceWorkbench';

const API_BASE_URL = String(import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const OTP_RESEND_UNTIL_STORAGE_KEY_PREFIX = 'neweast.auth.otp.resend_until_ms';
const AUTH_SESSION_STORAGE_KEY = 'neweast.auth.session.v1';
const GLOBAL_TOAST_DURATION_SECONDS = 3;
const PHONE_PATTERN = /^1\d{10}$/;
const OTP_PATTERN = /^\d{6}$/;
const LOGIN_ENTRY_DOMAIN_PATH_PATTERN = /^\/login\/(platform|tenant)\/?$/i;
const TENANT_TECH_ILLUSTRATION_DATA_URI = `data:image/svg+xml;utf8,${encodeURIComponent(`
  <svg width="1600" height="900" viewBox="0 0 1600 900" fill="none" xmlns="http://www.w3.org/2000/svg">
    <rect width="1600" height="900" fill="url(#bg)"/>
    <path d="M0 70L360 0H1600V140L1240 260L0 70Z" fill="url(#shapeA)" fill-opacity="0.42"/>
    <path d="M0 820L340 660H1600V900H0V820Z" fill="url(#shapeB)" fill-opacity="0.45"/>
    <path d="M0 240L170 140V220L0 320V240Z" fill="#E7EFF9" fill-opacity="0.78"/>
    <path d="M1260 650L1600 480V590L1390 760L1260 650Z" fill="#E8F1FB" fill-opacity="0.8"/>
    <ellipse cx="560" cy="640" rx="360" ry="108" fill="url(#shadow)"/>
    <ellipse cx="560" cy="600" rx="290" ry="92" fill="#F9FCFF" stroke="#DCE7F4" stroke-width="8"/>
    <ellipse cx="560" cy="600" rx="228" ry="72" fill="#EDF4FF" stroke="#C8D8EE" stroke-width="6"/>
    <ellipse cx="560" cy="600" rx="160" ry="50" fill="url(#ringMain)" stroke="#1677FF" stroke-width="8"/>
    <ellipse cx="560" cy="600" rx="96" ry="30" fill="#F8FBFF" stroke="#9EC6FF" stroke-width="4"/>
    <path d="M488 504L560 462L632 504V570L560 612L488 570V504Z" fill="url(#pillarTop)"/>
    <path d="M488 504L560 462L560 528L488 570V504Z" fill="url(#pillarLeft)"/>
    <path d="M632 504L560 462V528L632 570V504Z" fill="url(#pillarRight)"/>
    <path d="M322 445L400 394L468 438L388 490L322 445Z" fill="url(#panelLeft)"/>
    <path d="M652 418L738 366L816 416L730 468L652 418Z" fill="url(#panelMid)"/>
    <path d="M612 330L700 280L780 326L692 378L612 330Z" fill="url(#panelTop)"/>
    <path d="M388 490V560L322 515V445L388 490Z" fill="#DCE9FC"/>
    <path d="M730 468V538L652 490V418L730 468Z" fill="#D9E8FE"/>
    <path d="M692 378V448L612 400V330L692 378Z" fill="#D9E7FD"/>
    <rect x="350" y="444" width="86" height="4" rx="2" fill="#70AEFF"/>
    <rect x="350" y="456" width="70" height="4" rx="2" fill="#B9D9FF"/>
    <rect x="680" y="418" width="98" height="4" rx="2" fill="#4096FF"/>
    <rect x="680" y="430" width="84" height="4" rx="2" fill="#8FC4FF"/>
    <path d="M644 330H744" stroke="#76B2FF" stroke-width="5" stroke-linecap="round"/>
    <path d="M664 344H734" stroke="#BDDFFF" stroke-width="5" stroke-linecap="round"/>
    <circle cx="874" cy="420" r="42" fill="url(#botBody)"/>
    <circle cx="874" cy="420" r="30" fill="#F7FBFF"/>
    <circle cx="874" cy="420" r="14" fill="#1677FF"/>
    <path d="M858 466H890" stroke="#CEDFF4" stroke-width="8" stroke-linecap="round"/>
    <path d="M398 706L450 680L510 716L458 742L398 706Z" fill="#E4EEFA"/>
    <path d="M398 706V742L458 778V742L398 706Z" fill="#D6E3F6"/>
    <path d="M458 742V778L510 752V716L458 742Z" fill="#C5D6EF"/>
    <!-- Floating Tech Orbs -->
    <circle cx="1060" cy="300" r="10" fill="#69B1FF"/>
    <circle cx="990" cy="250" r="8" fill="#A6D0FF"/>
    <circle cx="280" cy="510" r="9" fill="#C8E0FF"/>
    <circle cx="700" cy="250" r="7" fill="#8FC2FF"/>
    <circle cx="150" cy="280" r="16" fill="url(#botBody)" opacity="0.6"/>
    <circle cx="1380" cy="180" r="24" fill="url(#panelMid)" opacity="0.4"/>
    <circle cx="420" cy="120" r="6" fill="#1677FF" opacity="0.5"/>
    <circle cx="1200" cy="780" r="18" fill="url(#botBody)" opacity="0.7"/>

    <!-- Floating Panels -->
    <path d="M140 400L220 350L280 390L200 440Z" fill="url(#panelLeft)" opacity="0.5"/>
    <path d="M200 440V460L140 420V400Z" fill="#DCE9FC" opacity="0.5"/>
    <path d="M280 390V410L200 460V440Z" fill="#D9E8FE" opacity="0.5"/>
    
    <path d="M1250 240L1350 180L1430 230L1330 290Z" fill="url(#panelMid)" opacity="0.6"/>
    <path d="M1330 290V310L1250 260V240Z" fill="#DCE9FC" opacity="0.6"/>
    <path d="M1430 230V250L1330 310V290Z" fill="#D9E8FE" opacity="0.6"/>

    <!-- Abstract Data Tracks -->
    <path d="M-100 600 Q 300 800 600 500 T 1700 300" stroke="url(#panelTop)" stroke-width="2" fill="none" opacity="0.3" stroke-dasharray="10 10"/>
    <path d="M-100 640 Q 300 840 600 540 T 1700 340" stroke="url(#panelMid)" stroke-width="1" fill="none" opacity="0.2"/>
    <defs>
      <linearGradient id="bg" x1="800" y1="0" x2="800" y2="900" gradientUnits="userSpaceOnUse">
        <stop stop-color="#F7FAFF"/>
        <stop offset="1" stop-color="#EDF3FB"/>
      </linearGradient>
      <linearGradient id="shapeA" x1="1400" y1="0" x2="0" y2="300" gradientUnits="userSpaceOnUse">
        <stop stop-color="#DBE8FA"/>
        <stop offset="1" stop-color="#EFF4FC"/>
      </linearGradient>
      <linearGradient id="shapeB" x1="1600" y1="640" x2="0" y2="900" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E2EDFB"/>
        <stop offset="1" stop-color="#EEF4FC"/>
      </linearGradient>
      <radialGradient id="shadow" cx="0" cy="0" r="1" gradientUnits="userSpaceOnUse" gradientTransform="translate(560 640) rotate(90) scale(108 360)">
        <stop stop-color="#8FA9CC" stop-opacity="0.26"/>
        <stop offset="1" stop-color="#8FA9CC" stop-opacity="0"/>
      </radialGradient>
      <linearGradient id="ringMain" x1="420" y1="560" x2="720" y2="640" gradientUnits="userSpaceOnUse">
        <stop stop-color="#1677FF"/>
        <stop offset="1" stop-color="#0958D9"/>
      </linearGradient>
      <linearGradient id="pillarTop" x1="560" y1="462" x2="560" y2="612" gradientUnits="userSpaceOnUse">
        <stop stop-color="#FFFFFF"/>
        <stop offset="1" stop-color="#EBF2FE"/>
      </linearGradient>
      <linearGradient id="pillarLeft" x1="524" y1="470" x2="500" y2="570" gradientUnits="userSpaceOnUse">
        <stop stop-color="#F6FAFF"/>
        <stop offset="1" stop-color="#DFE9F9"/>
      </linearGradient>
      <linearGradient id="pillarRight" x1="596" y1="470" x2="620" y2="570" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E9F1FF"/>
        <stop offset="1" stop-color="#D2E1F8"/>
      </linearGradient>
      <linearGradient id="panelLeft" x1="468" y1="400" x2="318" y2="492" gradientUnits="userSpaceOnUse">
        <stop stop-color="#4096FF"/>
        <stop offset="1" stop-color="#91CAFF"/>
      </linearGradient>
      <linearGradient id="panelMid" x1="816" y1="370" x2="646" y2="472" gradientUnits="userSpaceOnUse">
        <stop stop-color="#1677FF"/>
        <stop offset="1" stop-color="#74B2FF"/>
      </linearGradient>
      <linearGradient id="panelTop" x1="780" y1="285" x2="608" y2="382" gradientUnits="userSpaceOnUse">
        <stop stop-color="#69B1FF"/>
        <stop offset="1" stop-color="#B7DCFF"/>
      </linearGradient>
      <linearGradient id="botBody" x1="832" y1="378" x2="916" y2="462" gradientUnits="userSpaceOnUse">
        <stop stop-color="#E4F0FF"/>
        <stop offset="1" stop-color="#CFE3FF"/>
      </linearGradient>
    </defs>
  </svg>
`)}`;

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
const normalizeEntryDomain = (value) =>
  String(value || '').trim().toLowerCase() === 'tenant' ? 'tenant' : 'platform';

const readEntryDomainFromLocation = (locationLike) => {
  if (!locationLike || typeof locationLike !== 'object') {
    return 'tenant';
  }

  const pathname = String(locationLike.pathname || '');
  const pathMatch = pathname.match(LOGIN_ENTRY_DOMAIN_PATH_PATTERN);
  if (pathMatch) {
    return normalizeEntryDomain(pathMatch[1]);
  }

  return 'tenant';
};

const readExplicitEntryDomainFromLocation = (locationLike) => {
  if (!locationLike || typeof locationLike !== 'object') {
    return null;
  }
  const pathname = String(locationLike.pathname || '');
  const pathMatch = pathname.match(LOGIN_ENTRY_DOMAIN_PATH_PATTERN);
  if (!pathMatch) {
    return null;
  }
  return normalizeEntryDomain(pathMatch[1]);
};

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

const normalizeUserName = (value) => {
  const normalized = String(value || '').trim();
  return normalized || null;
};

const clearPersistedAuthSession = () => {
  if (typeof window === 'undefined') {
    return;
  }
  window.sessionStorage.removeItem(AUTH_SESSION_STORAGE_KEY);
};

const readPersistedAuthSession = () => {
  if (typeof window === 'undefined') {
    return null;
  }
  const raw = window.sessionStorage.getItem(AUTH_SESSION_STORAGE_KEY);
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw);
    const snapshot = parsed && typeof parsed === 'object' ? parsed : {};
    const rawSession = snapshot.sessionState && typeof snapshot.sessionState === 'object'
      ? snapshot.sessionState
      : null;
    const accessToken = String(rawSession?.access_token || '').trim();
    if (!accessToken) {
      clearPersistedAuthSession();
      return null;
    }
    const sessionState = {
      access_token: accessToken,
      session_id: rawSession?.session_id ? String(rawSession.session_id) : null,
      entry_domain: normalizeEntryDomain(rawSession?.entry_domain),
      user_name: normalizeUserName(rawSession?.user_name),
      active_tenant_id: rawSession?.active_tenant_id ? String(rawSession.active_tenant_id).trim() : null,
      tenant_selection_required: Boolean(rawSession?.tenant_selection_required),
      platform_permission_context:
        rawSession?.platform_permission_context
        && typeof rawSession.platform_permission_context === 'object'
          ? rawSession.platform_permission_context
          : null,
      tenant_permission_context:
        rawSession?.tenant_permission_context && typeof rawSession.tenant_permission_context === 'object'
          ? rawSession.tenant_permission_context
          : null
    };
    const explicitEntryDomain = readExplicitEntryDomainFromLocation(window.location);
    if (explicitEntryDomain && explicitEntryDomain !== sessionState.entry_domain) {
      clearPersistedAuthSession();
      return null;
    }
    const tenantOptions = asTenantOptions(snapshot.tenantOptions);
    const fallbackTenantId = String(sessionState.active_tenant_id || '').trim()
      || (tenantOptions[0] ? tenantOptions[0].tenant_id : '');
    const tenantSelectionValue = String(snapshot.tenantSelectionValue || '').trim() || fallbackTenantId;
    const tenantSwitchValue = String(snapshot.tenantSwitchValue || '').trim() || fallbackTenantId;
    return {
      sessionState,
      tenantOptions,
      tenantSelectionValue,
      tenantSwitchValue
    };
  } catch (_error) {
    clearPersistedAuthSession();
    return null;
  }
};

const persistAuthSession = ({
  sessionState,
  tenantOptions,
  tenantSelectionValue,
  tenantSwitchValue
}) => {
  if (typeof window === 'undefined') {
    return;
  }
  const accessToken = String(sessionState?.access_token || '').trim();
  if (!accessToken) {
    clearPersistedAuthSession();
    return;
  }
  const snapshot = {
    sessionState: {
      access_token: accessToken,
      session_id: sessionState?.session_id ? String(sessionState.session_id) : null,
      entry_domain: normalizeEntryDomain(sessionState?.entry_domain),
      user_name: normalizeUserName(sessionState?.user_name),
      active_tenant_id: sessionState?.active_tenant_id ? String(sessionState.active_tenant_id).trim() : null,
      tenant_selection_required: Boolean(sessionState?.tenant_selection_required),
      platform_permission_context:
        sessionState?.platform_permission_context
        && typeof sessionState.platform_permission_context === 'object'
          ? sessionState.platform_permission_context
          : null,
      tenant_permission_context:
        sessionState?.tenant_permission_context && typeof sessionState.tenant_permission_context === 'object'
          ? sessionState.tenant_permission_context
          : null
    },
    tenantOptions: asTenantOptions(tenantOptions),
    tenantSelectionValue: String(tenantSelectionValue || '').trim(),
    tenantSwitchValue: String(tenantSwitchValue || '').trim()
  };
  window.sessionStorage.setItem(AUTH_SESSION_STORAGE_KEY, JSON.stringify(snapshot));
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
  const [initialPersistedAuth] = useState(() => readPersistedAuthSession());
  const screens = Grid.useBreakpoint();
  const [mode, setMode] = useState('password');
  const [entryDomain] = useState(() =>
    typeof window === 'undefined' ? 'tenant' : readEntryDomainFromLocation(window.location)
  );
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
  const [screen, setScreen] = useState(() => {
    const restoredSession = initialPersistedAuth?.sessionState;
    if (!restoredSession) {
      return 'login';
    }
    if (restoredSession.entry_domain === 'tenant' && restoredSession.tenant_selection_required) {
      return 'tenant-select';
    }
    return 'dashboard';
  });
  const [sessionState, setSessionState] = useState(() => initialPersistedAuth?.sessionState || null);
  const [tenantOptions, setTenantOptions] = useState(() => initialPersistedAuth?.tenantOptions || []);
  const [tenantSelectionValue, setTenantSelectionValue] = useState(
    () => initialPersistedAuth?.tenantSelectionValue || ''
  );
  const [tenantSwitchValue, setTenantSwitchValue] = useState(
    () => initialPersistedAuth?.tenantSwitchValue || ''
  );
  const latestPhoneRef = useRef('');
  const sessionStateRef = useRef(initialPersistedAuth?.sessionState || null);
  const tenantContextRefreshExecutorRef = useRef(createLatestRequestExecutor());
  const permissionState = readTenantPermissionState(sessionState);
  const permissionUiState = selectPermissionUiState(permissionState);
  const [messageApi, messageContextHolder] = message.useMessage();

  useEffect(() => {
    latestPhoneRef.current = normalizePhone(phone);
  }, [phone]);

  useEffect(() => {
    sessionStateRef.current = sessionState;
  }, [sessionState]);

  useEffect(() => {
    if (!globalMessage) {
      return;
    }
    messageApi.open({
      key: 'auth-global-feedback',
      type: globalMessage.type === 'error' ? 'error' : 'success',
      duration: GLOBAL_TOAST_DURATION_SECONDS,
      content: <span data-testid="message-global">{globalMessage.text}</span>
    });
  }, [globalMessage, messageApi]);

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

  const clearAuthSession = useCallback((nextGlobalMessage = null) => {
    clearPersistedAuthSession();
    sessionStateRef.current = null;
    setSessionState(null);
    setScreen('login');
    setTenantOptions([]);
    setTenantSelectionValue('');
    setTenantSwitchValue('');
    setPhone('');
    setPassword('');
    setOtpCode('');
    setFieldErrors({ phone: '', password: '', otpCode: '' });
    setOtpResendUntilMs(0);
    setOtpCountdownSeconds(0);
    setIsSendingOtp(false);
    setIsSubmitting(false);
    setIsTenantSubmitting(false);
    setGlobalMessage(nextGlobalMessage);
  }, []);

  const handleLogout = useCallback(async () => {
    const accessToken = String(sessionStateRef.current?.access_token || '').trim();
    if (accessToken) {
      try {
        await requestJson({
          path: '/auth/logout',
          method: 'POST',
          accessToken
        });
      } catch (_error) {
        // Ignore logout API errors and prioritize local session cleanup.
      }
    }
    clearAuthSession({
      type: 'success',
      text: '已退出登录'
    });
  }, [clearAuthSession]);

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

  const refreshTenantContext = useCallback(async (accessToken, options = {}) => {
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
          user_name: Object.prototype.hasOwnProperty.call(payload, 'user_name')
            ? normalizeUserName(payload.user_name)
            : normalizeUserName(previous?.user_name),
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
  }, []);

  useEffect(() => {
    persistAuthSession({
      sessionState,
      tenantOptions,
      tenantSelectionValue,
      tenantSwitchValue
    });
  }, [sessionState, tenantOptions, tenantSelectionValue, tenantSwitchValue]);

  useEffect(() => {
    const restoredSession = initialPersistedAuth?.sessionState;
    if (!restoredSession || restoredSession.entry_domain !== 'tenant') {
      return;
    }
    const restoredAccessToken = String(restoredSession.access_token || '').trim();
    if (!restoredAccessToken) {
      clearAuthSession({
        type: 'error',
        text: '会话信息无效，请重新登录'
      });
      return;
    }
    void refreshTenantContext(restoredAccessToken, {
      expectedSession: restoredSession
    }).catch(() => {
      clearAuthSession({
        type: 'error',
        text: '会话已失效，请重新登录'
      });
    });
  }, [clearAuthSession, initialPersistedAuth, refreshTenantContext]);

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

  const handleSubmit = async () => {
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
        user_name: normalizeUserName(payload.user_name),
        active_tenant_id: payload.active_tenant_id,
        tenant_selection_required: Boolean(payload.tenant_selection_required),
        platform_permission_context: payload.platform_permission_context || null,
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
  const loginTitle = isTenantEntry ? '登录' : '平台登录';
  const loginSubtitle = isTenantEntry
    ? null
    : '面向平台运营与治理管理，登录后进入平台控制台进行用户与角色治理。';
  const loginPanel = (
    <Card
      styles={{ body: { padding: '40px 32px' } }}
      style={{
        width: '100%',
        maxWidth: 420,
        height: 480,
        borderRadius: 12,
        boxShadow: screens.lg ? '0 12px 32px rgba(0, 0, 0, 0.04)' : 'none',
        border: screens.lg ? '1px solid #EBF1F9' : 'none',
      }}
    >
      <Space direction="vertical" size={16} style={{ width: '100%' }}>
        <Space direction="vertical" size={8} style={{ width: '100%' }}>
          <Typography.Title level={2} data-testid="page-title" style={{ margin: 0 }}>
            {loginTitle}
          </Typography.Title>
          {loginSubtitle ? (
            <Typography.Paragraph style={{ margin: 0 }}>
              {loginSubtitle}
            </Typography.Paragraph>
          ) : null}
        </Space>

        <Space>
          <Button
            data-testid="mode-password"
            type={mode === 'password' ? 'primary' : 'default'}
            onClick={() => handleModeSwitch('password')}
            disabled={isSubmitting || isSendingOtp}
          >
            密码登录
          </Button>
          <Button
            data-testid="mode-otp"
            type={mode === 'otp' ? 'primary' : 'default'}
            onClick={() => handleModeSwitch('otp')}
            disabled={isSubmitting || isSendingOtp}
          >
            验证码登录
          </Button>
        </Space>

        <Form layout="vertical" requiredMark={false} onFinish={handleSubmit}>
          <Form.Item
            label="手机号"
            validateStatus={fieldErrors.phone ? 'error' : ''}
            help={fieldErrors.phone || null}
          >
            <Input
              data-testid="input-phone"
              value={phone}
              onChange={(event) => setPhone(event.target.value)}
              placeholder="请输入 11 位手机号"
              autoComplete="tel"
              disabled={isSubmitting || isSendingOtp}
            />
          </Form.Item>

          {mode === 'password' ? (
            <Form.Item
              label="密码"
              validateStatus={fieldErrors.password ? 'error' : ''}
              help={fieldErrors.password || null}
            >
              <Input.Password
                data-testid="input-password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                placeholder="请输入密码"
                autoComplete="current-password"
                disabled={isSubmitting || isSendingOtp}
              />
            </Form.Item>
          ) : (
            <Form.Item
              label="验证码"
              validateStatus={fieldErrors.otpCode ? 'error' : ''}
              help={fieldErrors.otpCode || null}
            >
              <Space.Compact style={{ width: '100%' }}>
                <Input
                  data-testid="input-otp-code"
                  value={otpCode}
                  onChange={(event) => setOtpCode(event.target.value)}
                  placeholder="请输入 6 位验证码"
                  autoComplete="one-time-code"
                  disabled={isSubmitting}
                />
                <Button
                  data-testid="button-send-otp"
                  onClick={handleSendOtp}
                  disabled={isSendingOtp || isSubmitting || otpCountdownSeconds > 0}
                  loading={isSendingOtp}
                >
                  {otpCountdownSeconds > 0 ? `${otpCountdownSeconds}s 后重试` : '发送验证码'}
                </Button>
              </Space.Compact>
            </Form.Item>
          )}

          <Form.Item style={{ marginBottom: 0 }}>
            <Button
              data-testid="button-submit-login"
              type="primary"
              htmlType="submit"
              loading={isSubmitting}
              disabled={isSendingOtp}
              block
            >
              {isSubmitting ? '提交中...' : '登录'}
            </Button>
          </Form.Item>
        </Form>

      </Space>
    </Card>
  );

  const isTenantLoginScreen = screen === 'login' && isTenantEntry;
  const loginShellPadding = isTenantLoginScreen ? 0 : screen === 'login' ? (screens.lg ? 12 : 8) : 24;
  const loginMinHeight = isTenantLoginScreen
    ? '100vh'
    : screens.lg
      ? `calc(100vh - ${loginShellPadding * 2}px)`
      : 'auto';
  const tenantVisualMinHeight = isTenantLoginScreen ? '100vh' : screens.lg ? loginMinHeight : 280;
  const isPlatformDashboardScreen = screen === 'dashboard' && sessionState?.entry_domain === 'platform';

  return (
    <main
      style={{
        padding: isPlatformDashboardScreen ? 0 : loginShellPadding,
        maxWidth: screen === 'login' || isPlatformDashboardScreen ? '100%' : 560,
        margin: screen === 'login' || isPlatformDashboardScreen ? 0 : '0 auto',
        width: '100%',
        height: isTenantLoginScreen ? '100vh' : 'auto',
        overflow: isTenantLoginScreen ? 'hidden' : 'visible'
      }}
    >
      {messageContextHolder}
      {screen === 'login' ? (
        isTenantEntry ? (
          <Card
            bordered={false}
            styles={{ body: { padding: 0, height: '100%' } }}
            style={{
              position: 'relative',
              minHeight: tenantVisualMinHeight,
              width: '100%',
              borderRadius: 0,
              overflow: 'hidden'
            }}
          >
            <Flex style={{ width: '100%', height: '100%', minHeight: tenantVisualMinHeight }}>
              <Image
                preview={false}
                src={TENANT_TECH_ILLUSTRATION_DATA_URI}
                alt="组织登录科技感插图"
                width="100%"
                height="100%"
                style={{ width: '100%', height: '100%', objectFit: 'cover' }}
              />
            </Flex>
            <Flex
              style={{
                position: 'absolute',
                inset: 0,
                justifyContent: screens.lg ? 'flex-end' : 'center',
                alignItems: 'center',
                padding: screens.lg ? '0 clamp(56px, 9vw, 136px) 0 0' : 12,
                background: screens.lg
                  ? 'linear-gradient(270deg, rgba(250, 252, 255, 0.78) 0%, rgba(250, 252, 255, 0.34) 44%, rgba(250, 252, 255, 0) 76%)'
                  : 'rgba(248, 251, 255, 0.45)'
              }}
            >
              <Flex
                style={{
                  width: screens.lg ? 'min(520px, 42vw)' : '100%',
                  maxWidth: screens.lg ? 520 : 560
                }}
              >
                {loginPanel}
              </Flex>
            </Flex>
          </Card>
        ) : (
          <Flex align="center" justify="center" style={{ minHeight: 'calc(100vh - 48px)' }}>
            <Flex style={{ width: '100%', maxWidth: 520 }}>
              {loginPanel}
            </Flex>
          </Flex>
        )
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
        sessionState?.entry_domain === 'platform' ? (
          <PlatformManagementLayoutPage
            accessToken={sessionState?.access_token}
            userName={sessionState?.user_name}
            platformPermissionContext={sessionState?.platform_permission_context || null}
            onLogout={handleLogout}
          />
        ) : (
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
            <p style={{ margin: 0 }}>会话：{sessionState?.session_id || '-'}</p>
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
        )
      ) : null}

    </main>
  );
}
