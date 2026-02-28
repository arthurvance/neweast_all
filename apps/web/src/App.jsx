import { useCallback, useEffect, useRef, useState } from 'react';
import { message } from 'antd';
import AuthApp from './features/auth/AuthApp';
import {
  createApiRequest,
  configureAuthRequestHooks
} from './shared-kernel/http/request-json.mjs';
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
import { asTenantOptions, normalizeUserName } from './features/auth/session-model';

const GLOBAL_TOAST_DURATION_SECONDS = 3;
const ACCESS_TOKEN_REFRESH_LEAD_TIME_MS = 60 * 1000;
const ACCESS_TOKEN_REFRESH_RETRY_DELAY_MS = 30 * 1000;
const AUTH_INVALID_ACCESS_ERROR_CODE = 'AUTH-401-INVALID-ACCESS';
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

const isInvalidAccessProblem = (error) =>
  String(error?.payload?.error_code || '').trim().toUpperCase() === AUTH_INVALID_ACCESS_ERROR_CODE;

const decodeJwtPayload = (token) => {
  const normalizedToken = String(token || '').trim();
  if (!normalizedToken) {
    return null;
  }
  const parts = normalizedToken.split('.');
  if (parts.length < 2) {
    return null;
  }
  try {
    const normalizedPayload = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const paddedPayload = normalizedPayload.padEnd(
      Math.ceil(normalizedPayload.length / 4) * 4,
      '='
    );
    const decodedPayload = typeof window !== 'undefined' && typeof window.atob === 'function'
      ? window.atob(paddedPayload)
      : '';
    if (!decodedPayload) {
      return null;
    }
    return JSON.parse(decodedPayload);
  } catch (_error) {
    return null;
  }
};

const resolveJwtExpirationAtMs = (token) => {
  const payload = decodeJwtPayload(token);
  const exp = Number(payload?.exp);
  if (!Number.isFinite(exp) || exp <= 0) {
    return 0;
  }
  return Math.floor(exp * 1000);
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
  const refreshInFlightRef = useRef(null);
  const accessTokenRefreshTimerRef = useRef(null);
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
    if (accessTokenRefreshTimerRef.current) {
      clearTimeout(accessTokenRefreshTimerRef.current);
      accessTokenRefreshTimerRef.current = null;
    }
    refreshInFlightRef.current = null;
    configureAuthRequestHooks();
    clearPersistedAuthSession();
    sessionStateRef.current = null;
    setSessionState(null);
    setScreen(APP_SCREEN_LOGIN);
    setTenantOptions([]);
    setTenantSwitchValue('');
    setIsTenantSubmitting(false);
    setGlobalMessage(nextGlobalMessage);
  }, []);

  const applyRefreshedAuthPayload = useCallback((payload = {}) => {
    const normalizedPayload = payload && typeof payload === 'object' ? payload : {};
    const hasUserNameField = Object.prototype.hasOwnProperty.call(
      normalizedPayload,
      'user_name'
    );
    const hasActiveTenantIdField = Object.prototype.hasOwnProperty.call(
      normalizedPayload,
      'active_tenant_id'
    );
    const hasTenantPermissionContextField = Object.prototype.hasOwnProperty.call(
      normalizedPayload,
      'tenant_permission_context'
    );
    const hasPlatformPermissionContextField = Object.prototype.hasOwnProperty.call(
      normalizedPayload,
      'platform_permission_context'
    );
    const hasTenantSelectionRequiredField = Object.prototype.hasOwnProperty.call(
      normalizedPayload,
      'tenant_selection_required'
    );
    const hasTenantOptionsField = Array.isArray(normalizedPayload.tenant_options);
    const nextTenantOptions = hasTenantOptionsField
      ? asTenantOptions(normalizedPayload.tenant_options)
      : null;

    setSessionState((previous) => {
      const previousSession = previous && typeof previous === 'object' ? previous : {};
      const nextSessionState = {
        ...previousSession,
        access_token: String(
          normalizedPayload.access_token || previousSession.access_token || ''
        ).trim() || null,
        refresh_token: String(
          normalizedPayload.refresh_token || previousSession.refresh_token || ''
        ).trim() || null,
        session_id: String(
          normalizedPayload.session_id || previousSession.session_id || ''
        ).trim() || null,
        entry_domain: String(
          normalizedPayload.entry_domain || previousSession.entry_domain || 'tenant'
        ).trim().toLowerCase() === 'tenant'
          ? 'tenant'
          : 'platform',
        user_name: hasUserNameField
          ? normalizeUserName(normalizedPayload.user_name)
          : normalizeUserName(previousSession.user_name),
        active_tenant_id: hasActiveTenantIdField
          ? (String(normalizedPayload.active_tenant_id || '').trim() || null)
          : (String(previousSession.active_tenant_id || '').trim() || null),
        tenant_selection_required: hasTenantSelectionRequiredField
          ? Boolean(normalizedPayload.tenant_selection_required)
          : Boolean(previousSession.tenant_selection_required),
        tenant_permission_context: hasTenantPermissionContextField
          ? (normalizedPayload.tenant_permission_context || null)
          : (previousSession.tenant_permission_context || null),
        platform_permission_context: hasPlatformPermissionContextField
          ? (normalizedPayload.platform_permission_context || null)
          : (previousSession.platform_permission_context || null)
      };
      sessionStateRef.current = nextSessionState;
      return nextSessionState;
    });

    if (hasTenantOptionsField && nextTenantOptions) {
      setTenantOptions(nextTenantOptions);
      setTenantSwitchValue((previous) => {
        const normalizedPrevious = String(previous || '').trim();
        const normalizedActiveTenantId = String(
          normalizedPayload.active_tenant_id || ''
        ).trim();
        if (
          normalizedActiveTenantId
          && nextTenantOptions.some(
            (option) => String(option?.tenant_id || '').trim() === normalizedActiveTenantId
          )
        ) {
          return normalizedActiveTenantId;
        }
        if (
          normalizedPrevious
          && nextTenantOptions.some(
            (option) => String(option?.tenant_id || '').trim() === normalizedPrevious
          )
        ) {
          return normalizedPrevious;
        }
        return String(nextTenantOptions[0]?.tenant_id || '').trim();
      });
    }
  }, [setSessionState, setTenantOptions, setTenantSwitchValue]);

  const refreshAccessTokenIfPossible = useCallback(async ({
    reason = 'manual',
    silent = false
  } = {}) => {
    const currentSession = sessionStateRef.current;
    const refreshToken = String(currentSession?.refresh_token || '').trim();
    if (!refreshToken) {
      const error = new Error('当前会话无 refresh_token，无法续期');
      error.payload = {
        detail: '当前会话无 refresh_token，无法续期'
      };
      throw error;
    }

    if (refreshInFlightRef.current) {
      return refreshInFlightRef.current;
    }

    const refreshPromise = (async () => {
      try {
        const payload = await requestJson({
          path: '/auth/refresh',
          method: 'POST',
          payload: {
            refresh_token: refreshToken
          },
          accessToken: ''
        });
        const nextAccessToken = String(payload?.access_token || '').trim();
        if (!nextAccessToken) {
          throw new Error('refresh 返回缺少 access_token');
        }
        applyRefreshedAuthPayload(payload);
        return nextAccessToken;
      } catch (error) {
        if (isInvalidAccessProblem(error) || Number(error?.status) === 401) {
          clearAuthSession({
            type: 'error',
            text: '会话已失效，请重新登录'
          });
        } else if (!silent) {
          setGlobalMessage({
            type: 'error',
            text: formatRetryMessage(error?.payload?.detail || '会话续期失败')
          });
        }
        throw error;
      }
    })().finally(() => {
      refreshInFlightRef.current = null;
    });

    refreshInFlightRef.current = refreshPromise;
    return refreshPromise;
  }, [applyRefreshedAuthPayload, clearAuthSession, setGlobalMessage]);

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
    recoverInvalidAccess: async () => {
      await refreshAccessTokenIfPossible({
        reason: 'tenant-session-recover',
        silent: true
      });
    },
    formatRetryMessage,
    clearAuthSession
  });

  useEffect(() => {
    configureAuthRequestHooks({
      getAccessToken: () => String(sessionStateRef.current?.access_token || '').trim(),
      refreshAccessToken: async () =>
        refreshAccessTokenIfPossible({
          reason: 'api-auto-refresh',
          silent: true
        })
    });
    return () => {
      configureAuthRequestHooks();
    };
  }, [refreshAccessTokenIfPossible]);

  useEffect(() => {
    if (accessTokenRefreshTimerRef.current) {
      clearTimeout(accessTokenRefreshTimerRef.current);
      accessTokenRefreshTimerRef.current = null;
    }

    const accessToken = String(sessionState?.access_token || '').trim();
    const refreshToken = String(sessionState?.refresh_token || '').trim();
    if (!accessToken || !refreshToken) {
      return;
    }

    const expiresAtMs = resolveJwtExpirationAtMs(accessToken);
    if (expiresAtMs <= 0) {
      return;
    }

    const refreshDelayMs = expiresAtMs - Date.now() - ACCESS_TOKEN_REFRESH_LEAD_TIME_MS;
    if (refreshDelayMs <= 0) {
      void refreshAccessTokenIfPossible({
        reason: 'startup-expired-access',
        silent: true
      }).catch((error) => {
        if (!(isInvalidAccessProblem(error) || Number(error?.status) === 401)) {
          setGlobalMessage({
            type: 'error',
            text: formatRetryMessage(error?.payload?.detail || '会话续期失败')
          });
        }
      });
      return;
    }

    accessTokenRefreshTimerRef.current = setTimeout(() => {
      void refreshAccessTokenIfPossible({
        reason: 'scheduled-refresh',
        silent: true
      }).catch((error) => {
        if (isInvalidAccessProblem(error) || Number(error?.status) === 401) {
          return;
        }
        setGlobalMessage({
          type: 'error',
          text: formatRetryMessage(error?.payload?.detail || '会话续期失败')
        });
        accessTokenRefreshTimerRef.current = setTimeout(() => {
          void refreshAccessTokenIfPossible({
            reason: 'scheduled-refresh-retry',
            silent: true
          }).catch(() => {});
        }, ACCESS_TOKEN_REFRESH_RETRY_DELAY_MS);
      });
    }, refreshDelayMs);

    return () => {
      if (accessTokenRefreshTimerRef.current) {
        clearTimeout(accessTokenRefreshTimerRef.current);
        accessTokenRefreshTimerRef.current = null;
      }
    };
  }, [sessionState, refreshAccessTokenIfPossible]);

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
      permissionUiState.menu.session_management
      || permissionUiState.menu.customer_management
      || permissionUiState.menu.account_management
      || permissionUiState.menu.user_management
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
