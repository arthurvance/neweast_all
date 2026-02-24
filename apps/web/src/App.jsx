import { useCallback, useEffect, useRef, useState } from 'react';
import { message } from 'antd';
import AuthApp from './features/auth/AuthApp';
import PlatformApp from './features/platform-management/PlatformApp';
import TenantApp from './features/tenant-management/TenantApp';
import {
  APP_SCREEN_DASHBOARD,
  APP_SCREEN_LOGIN,
  APP_SCREEN_TENANT_SWITCH,
  resolveInitialScreen,
  resolvePathForScreen,
  resolvePreferredScreenFromPathname
} from './features/app-shell/app-screen';
import {
  readTenantPermissionState,
  selectPermissionUiState
} from './features/tenant-management/tenant-permission-state';
import { useTenantSessionFlow } from './features/tenant-management/useTenantSessionFlow';
import {
  clearPersistedAuthSession,
  persistAuthSession,
  readEntryDomainFromLocation,
  readPersistedAuthSession
} from './features/auth/auth-session-storage';

const API_BASE_URL = String(import.meta.env.VITE_API_BASE_URL || '/api').replace(/\/$/, '');
const GLOBAL_TOAST_DURATION_SECONDS = 3;

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

export default function App() {
  const [initialPersistedAuth] = useState(() => readPersistedAuthSession());
  const [preferredScreen] = useState(() =>
    typeof window === 'undefined'
      ? APP_SCREEN_LOGIN
      : resolvePreferredScreenFromPathname(window.location.pathname)
  );
  const [entryDomain] = useState(() =>
    typeof window === 'undefined' ? 'tenant' : readEntryDomainFromLocation(window.location)
  );
  const [screen, setScreen] = useState(() =>
    resolveInitialScreen({
      restoredSession: initialPersistedAuth?.sessionState || null,
      preferredScreen
    })
  );
  const [sessionState, setSessionState] = useState(() => initialPersistedAuth?.sessionState || null);
  const [tenantOptions, setTenantOptions] = useState(() => initialPersistedAuth?.tenantOptions || []);
  const [tenantSelectionValue, setTenantSelectionValue] = useState(
    () => initialPersistedAuth?.tenantSelectionValue || ''
  );
  const [tenantSwitchValue, setTenantSwitchValue] = useState(
    () => initialPersistedAuth?.tenantSwitchValue || ''
  );
  const [isTenantSubmitting, setIsTenantSubmitting] = useState(false);
  const [globalMessage, setGlobalMessage] = useState(null);
  const sessionStateRef = useRef(initialPersistedAuth?.sessionState || null);
  const permissionState = readTenantPermissionState(sessionState);
  const permissionUiState = selectPermissionUiState(permissionState);
  const [messageApi, messageContextHolder] = message.useMessage();

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

  const clearAuthSession = useCallback((nextGlobalMessage = null) => {
    clearPersistedAuthSession();
    sessionStateRef.current = null;
    setSessionState(null);
    setScreen(APP_SCREEN_LOGIN);
    setTenantOptions([]);
    setTenantSelectionValue('');
    setTenantSwitchValue('');
    setIsTenantSubmitting(false);
    setGlobalMessage(nextGlobalMessage);
  }, []);

  const handleLoginFailure = useCallback(() => {
    sessionStateRef.current = null;
    setSessionState(null);
    setScreen(APP_SCREEN_LOGIN);
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

  const {
    applyLoginPayload,
    handleTenantSelect,
    refreshTenantPermissionContextFailClosed,
    handleTenantSwitchFromDashboard,
    handleOpenTenantSwitchPage,
    handleTenantSwitchFromSwitchPage
  } = useTenantSessionFlow({
    initialPersistedAuth,
    sessionState,
    sessionStateRef,
    tenantOptions,
    tenantSelectionValue,
    tenantSwitchValue,
    isTenantSubmitting,
    setSessionState,
    setTenantOptions,
    setTenantSelectionValue,
    setTenantSwitchValue,
    setIsTenantSubmitting,
    setScreen,
    setGlobalMessage,
    requestJson,
    formatRetryMessage,
    clearAuthSession
  });

  useEffect(() => {
    persistAuthSession({
      sessionState,
      tenantOptions,
      tenantSelectionValue,
      tenantSwitchValue
    });
  }, [sessionState, tenantOptions, tenantSelectionValue, tenantSwitchValue]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return;
    }
    const nextPathname = resolvePathForScreen({
      screen,
      entryDomain,
      sessionState
    });
    const normalizedCurrentPathname = String(window.location.pathname || '/').trim() || '/';
    if (normalizedCurrentPathname === nextPathname) {
      return;
    }
    window.history.replaceState(
      window.history.state,
      '',
      `${nextPathname}${window.location.search || ''}${window.location.hash || ''}`
    );
  }, [entryDomain, screen, sessionState]);

  const isLoginScreen = screen === APP_SCREEN_LOGIN;
  const loginShellPadding = isLoginScreen ? 0 : 24;
  const isPlatformDashboardScreen = screen === APP_SCREEN_DASHBOARD && sessionState?.entry_domain === 'platform';
  const isTenantSwitchScreen = screen === APP_SCREEN_TENANT_SWITCH;
  const isTenantManagementDashboardScreen = Boolean(
    screen === APP_SCREEN_DASHBOARD
    && sessionState?.entry_domain === 'tenant'
    && (
      permissionUiState.menu.user_management
      || permissionUiState.menu.role_management
    )
  );

  return (
    <main
      style={{
        padding: isPlatformDashboardScreen || isTenantManagementDashboardScreen ? 0 : loginShellPadding,
        maxWidth:
          screen === APP_SCREEN_LOGIN
            || isPlatformDashboardScreen
            || isTenantManagementDashboardScreen
            || isTenantSwitchScreen
            ? '100%'
            : 560,
        margin:
          screen === APP_SCREEN_LOGIN
            || isPlatformDashboardScreen
            || isTenantManagementDashboardScreen
            || isTenantSwitchScreen
            ? 0
            : '0 auto',
        width: '100%',
        height: isLoginScreen ? '100vh' : 'auto',
        overflow: isLoginScreen ? 'hidden' : 'visible'
      }}
    >
      {messageContextHolder}

      <AuthApp
        visible={screen === APP_SCREEN_LOGIN}
        entryDomain={entryDomain}
        postJson={postJson}
        formatRetryMessage={formatRetryMessage}
        onLoginPayload={applyLoginPayload}
        onGlobalMessage={setGlobalMessage}
        onLoginFailure={handleLoginFailure}
      />

      <PlatformApp
        screen={screen}
        sessionState={sessionState}
        onLogout={handleLogout}
      />

      <TenantApp
        screen={screen}
        sessionState={sessionState}
        tenantOptions={tenantOptions}
        tenantSelectionValue={tenantSelectionValue}
        onTenantSelectionChange={setTenantSelectionValue}
        onTenantSelectConfirm={handleTenantSelect}
        tenantSwitchValue={tenantSwitchValue}
        onTenantSwitchValueChange={setTenantSwitchValue}
        isTenantSubmitting={isTenantSubmitting}
        permissionState={permissionState}
        permissionUiState={permissionUiState}
        isTenantManagementDashboardScreen={isTenantManagementDashboardScreen}
        onLogout={handleLogout}
        onTenantPermissionContextRefresh={refreshTenantPermissionContextFailClosed}
        onTenantSwitchFromDashboard={handleTenantSwitchFromDashboard}
        onOpenTenantSwitchPage={handleOpenTenantSwitchPage}
        onTenantSwitchFromSwitchPage={handleTenantSwitchFromSwitchPage}
      />

    </main>
  );
}
