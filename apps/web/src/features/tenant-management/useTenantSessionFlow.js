import { useCallback, useEffect, useRef } from 'react';
import {
  resolveTenantMutationPermissionContext,
  resolveTenantMutationSessionState,
  resolveTenantMutationUiState,
  resolveTenantRefreshUiState,
  readSessionIdFromAccessToken,
  isTenantRefreshResultBoundToCurrentSession
} from '../../tenant-mutation.mjs';
import { createLatestRequestExecutor } from '../../latest-request.mjs';
import { asTenantOptions, normalizeUserName } from '../auth/session-model';
import {
  APP_SCREEN_DASHBOARD,
  APP_SCREEN_TENANT_SELECT,
  APP_SCREEN_TENANT_SWITCH
} from '../app-shell/app-screen';

const normalizeTenantMutationPayload = (payload) =>
  payload && typeof payload === 'object' ? payload : {};

export const useTenantSessionFlow = ({
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
}) => {
  const tenantContextRefreshExecutorRef = useRef(createLatestRequestExecutor());

  useEffect(() => {
    sessionStateRef.current = sessionState;
  }, [sessionState, sessionStateRef]);

  const refreshTenantContext = useCallback(async (accessToken, options = {}) => {
    const requestSessionId = readSessionIdFromAccessToken(accessToken);
    const expectedSession = options.expectedSession || null;
    const forceApply = options.forceApply === true;
    const applyTenantContextPayload = (payload) => {
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
    };

    if (forceApply) {
      const payload = await requestJson({
        path: '/auth/tenant/options',
        method: 'GET',
        accessToken
      });
      applyTenantContextPayload(payload);
      return payload;
    }

    return tenantContextRefreshExecutorRef.current.run(
      () =>
        requestJson({
          path: '/auth/tenant/options',
          method: 'GET',
          accessToken
        }),
      applyTenantContextPayload,
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
  }, [requestJson, setSessionState, setTenantOptions, setTenantSelectionValue, setTenantSwitchValue, sessionStateRef]);

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

  const applyLoginPayload = useCallback((payload) => {
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

    sessionStateRef.current = resolvedSession;
    setSessionState(resolvedSession);
    setTenantOptions(options);

    if (resolvedSession.entry_domain === 'tenant') {
      if (options.length > 0) {
        const firstTenant = options[0].tenant_id;
        setTenantSelectionValue(firstTenant);
        setTenantSwitchValue(resolvedSession.active_tenant_id || firstTenant);
      }

      if (options.length > 1) {
        setScreen(APP_SCREEN_TENANT_SELECT);
        setGlobalMessage({
          type: 'success',
          text: '登录成功，请先选择组织后进入工作台'
        });
      } else {
        setScreen(APP_SCREEN_DASHBOARD);
        setGlobalMessage({
          type: 'success',
          text: '登录成功'
        });
      }
      return;
    }

    setScreen(APP_SCREEN_DASHBOARD);
    setGlobalMessage({
      type: 'success',
      text: '登录成功'
    });
  }, [setGlobalMessage, setScreen, setSessionState, setTenantOptions, setTenantSelectionValue, setTenantSwitchValue, sessionStateRef]);

  const applyTenantMutationPayload = useCallback((payload, fallbackTenantId) => {
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
  }, [sessionStateRef, setSessionState, setTenantOptions, setTenantSelectionValue, setTenantSwitchValue, tenantOptions]);

  const handleTenantSelect = useCallback(async () => {
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
      setScreen(APP_SCREEN_DASHBOARD);
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
  }, [applyTenantMutationPayload, formatRetryMessage, refreshTenantContext, requestJson, sessionState, setGlobalMessage, setIsTenantSubmitting, setScreen, tenantSelectionValue]);

  const handleTenantSwitch = useCallback(async (tenantIdOverride = null) => {
    if (!sessionState?.access_token) {
      return;
    }
    const accessToken = sessionState.access_token;
    const tenantId = String(tenantIdOverride ?? tenantSwitchValue ?? '').trim();
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
      setScreen(APP_SCREEN_DASHBOARD);
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
  }, [applyTenantMutationPayload, formatRetryMessage, refreshTenantContext, requestJson, sessionState, setGlobalMessage, setIsTenantSubmitting, setScreen, tenantSwitchValue]);

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
      let refreshResult = await refreshTenantContext(accessToken, {
        expectedSession: currentSession,
        forceApply: true
      });
      if (refreshResult === undefined) {
        const latestSession = sessionStateRef.current || currentSession;
        const latestAccessToken = String(latestSession?.access_token || accessToken).trim();
        refreshResult = await refreshTenantContext(latestAccessToken, {
          expectedSession: latestSession,
          forceApply: true
        });
      }
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
  }, [formatRetryMessage, refreshTenantContext, sessionStateRef, setGlobalMessage, setSessionState]);

  const handleTenantSwitchFromDashboard = useCallback((nextTenantId) => {
    if (isTenantSubmitting) {
      return;
    }
    const normalizedNextTenantId = String(nextTenantId ?? tenantSwitchValue ?? '').trim();
    if (!normalizedNextTenantId) {
      return;
    }
    setTenantSwitchValue(normalizedNextTenantId);
    if (normalizedNextTenantId === String(sessionState?.active_tenant_id || '').trim()) {
      return;
    }
    void handleTenantSwitch(normalizedNextTenantId);
  }, [handleTenantSwitch, isTenantSubmitting, sessionState, setTenantSwitchValue, tenantSwitchValue]);

  const handleOpenTenantSwitchPage = useCallback(() => {
    if (isTenantSubmitting) {
      return;
    }
    setScreen(APP_SCREEN_TENANT_SWITCH);
  }, [isTenantSubmitting, setScreen]);

  const handleTenantSwitchFromSwitchPage = useCallback((nextTenantId) => {
    const normalizedTenantId = String(nextTenantId || '').trim();
    if (!normalizedTenantId) {
      return;
    }
    setTenantSwitchValue(normalizedTenantId);
    if (normalizedTenantId === String(sessionState?.active_tenant_id || '').trim()) {
      setScreen(APP_SCREEN_DASHBOARD);
      return;
    }
    void handleTenantSwitch(normalizedTenantId);
  }, [handleTenantSwitch, sessionState, setScreen, setTenantSwitchValue]);

  return {
    applyLoginPayload,
    handleTenantSelect,
    refreshTenantPermissionContextFailClosed,
    handleTenantSwitchFromDashboard,
    handleOpenTenantSwitchPage,
    handleTenantSwitchFromSwitchPage
  };
};
