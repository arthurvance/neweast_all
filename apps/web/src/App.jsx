import { useCallback, useEffect, useRef, useState } from 'react';
import { message } from 'antd';
import AuthApp from './features/auth/AuthApp';
import { createApiRequest } from './shared-kernel/http/request-json.mjs';
import { PlatformApp } from './domains/platform/index.mjs';
import {
  TenantApp,
  readTenantPermissionState,
  selectPermissionUiState,
  useTenantSessionFlow
} from './domains/tenant/index.mjs';
import {
  APP_SCREEN_DASHBOARD,
  APP_SCREEN_LOGIN,
  APP_SCREEN_TENANT_SWITCH,
  resolveInitialScreen,
  resolvePathForScreen,
  resolvePreferredScreenFromPathname
} from './features/app-shell/app-screen';
import {
  clearPersistedAuthSession,
  persistAuthSession,
  readEntryDomainFromLocation,
  readPersistedAuthSession
} from './features/auth/auth-session-storage';

const GLOBAL_TOAST_DURATION_SECONDS = 3;
const requestJson = createApiRequest();

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
    refreshTenantPermissionContextFailClosed,
    handleTenantSwitchFromDashboard,
    handleOpenTenantSwitchPage,
    handleTenantSwitchFromSwitchPage
  } = useTenantSessionFlow({
    initialPersistedAuth,
    sessionState,
    sessionStateRef,
    tenantOptions,
    tenantSwitchValue,
    isTenantSubmitting,
    setSessionState,
    setTenantOptions,
    setTenantSwitchValue,
    setIsTenantSubmitting,
    setScreen,
    setGlobalMessage,
    requestJson,
    formatRetryMessage,
    clearAuthSession
  });

  const refreshPlatformPermissionContextFailClosed = useCallback(async () => {
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
      const payload = await requestJson({
        path: '/auth/platform/options',
        method: 'GET',
        accessToken
      });
      setSessionState((previous) => {
        const nextUserName = Object.prototype.hasOwnProperty.call(payload, 'user_name')
          ? String(payload.user_name || '').trim() || null
          : String(previous?.user_name || '').trim() || null;
        const nextSessionState = {
          ...(previous || {}),
          session_id: payload.session_id || previous?.session_id || null,
          entry_domain: payload.entry_domain || previous?.entry_domain || 'platform',
          active_tenant_id: Object.prototype.hasOwnProperty.call(payload, 'active_tenant_id')
            ? payload.active_tenant_id
            : previous?.active_tenant_id ?? null,
          user_name: nextUserName,
          platform_permission_context: payload.platform_permission_context || null
        };
        sessionStateRef.current = nextSessionState;
        return nextSessionState;
      });
    } catch (error) {
      setSessionState((previous) => {
        if (!previous) {
          return previous;
        }
        const nextSessionState = {
          ...previous,
          platform_permission_context: null
        };
        sessionStateRef.current = nextSessionState;
        return nextSessionState;
      });
      setGlobalMessage({
        type: 'error',
        text: formatRetryMessage(
          error?.payload?.detail || '平台上下文刷新失败，已按 fail-closed 收敛权限'
        )
      });
      error.uiMessageHandled = true;
      throw error;
    }
  }, [formatRetryMessage, setGlobalMessage, setSessionState]);

  useEffect(() => {
    persistAuthSession({
      sessionState,
      tenantOptions,
      tenantSwitchValue
    });
  }, [sessionState, tenantOptions, tenantSwitchValue]);

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
        onPlatformPermissionContextRefresh={refreshPlatformPermissionContextFailClosed}
      />

      <TenantApp
        screen={screen}
        sessionState={sessionState}
        tenantOptions={tenantOptions}
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
