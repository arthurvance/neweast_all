import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  SendOutlined,
  ClockCircleOutlined,
  UserOutlined
} from '@ant-design/icons';
import {
  Alert,
  Avatar,
  Button,
  Empty,
  Input,
  List,
  Select,
  Space,
  Spin,
  Tabs,
  Typography,
  message,
  theme
} from 'antd';
import CustomCard from '../../../../components/CustomCard';
import {
  createTenantManagementApi,
  toProblemMessage
} from '../../../../api/tenant-management.mjs';
import { formatDateTimeMinute } from '../../../../utils/date-time.mjs';

const { Text } = Typography;
const { TextArea } = Input;

const SESSION_SCOPE_CONFIG = Object.freeze({
  my: {
    label: '我的会话',
    testId: 'tenant-session-tab-my',
    viewSnakeCase: 'can_view_session_scope_my',
    viewCamelCase: 'canViewSessionScopeMy'
  },
  assist: {
    label: '协管会话',
    testId: 'tenant-session-tab-assist',
    viewSnakeCase: 'can_view_session_scope_assist',
    viewCamelCase: 'canViewSessionScopeAssist'
  },
  all: {
    label: '全部会话',
    testId: 'tenant-session-tab-all',
    viewSnakeCase: 'can_view_session_scope_all',
    viewCamelCase: 'canViewSessionScopeAll'
  }
});

const SESSION_LIST_DEFAULT_PAGE_SIZE = 20;
const SESSION_MESSAGE_DEFAULT_LIMIT = 50;
const SESSION_MESSAGE_COMPOSER_HEIGHT = 172;
const SESSION_LIST_POLL_INTERVAL_MS = 5000;
const SESSION_DETAIL_POLL_INTERVAL_MS = 3000;

const readPermissionFlag = (permissionContext, snakeCase, camelCase) =>
  Boolean(permissionContext?.[snakeCase] || permissionContext?.[camelCase]);

const toNullableText = (value) => String(value == null ? '' : value).trim();

const toMessagePayloadPreview = (messageType, messagePayloadJson) => {
  if (messageType === 'text') {
    const text = toNullableText(
      messagePayloadJson?.text
      ?? messagePayloadJson?.content
      ?? messagePayloadJson?.message
    );
    return text || '';
  }
  if (messageType === 'image') {
    const imageUrl = toNullableText(
      messagePayloadJson?.url
      ?? messagePayloadJson?.image_url
      ?? messagePayloadJson?.src
    );
    return imageUrl ? `[图片] ${imageUrl}` : '[图片]';
  }
  const fallbackText = toNullableText(messagePayloadJson?.text);
  if (fallbackText) {
    return fallbackText;
  }
  try {
    return JSON.stringify(messagePayloadJson ?? {});
  } catch (_error) {
    return toNullableText(messagePayloadJson);
  }
};

const toAccountLabel = (record = {}) => {
  const nickname = toNullableText(
    record.account_nickname || record.accountNickname || record.account_name
  );
  const wechatId = toNullableText(
    record.account_wechat_id || record.accountWechatId || record.wechat_id || record.wechatId
  );
  if (nickname && wechatId) {
    return `${nickname}(${wechatId})`;
  }
  if (nickname) {
    return nickname;
  }
  if (wechatId) {
    return wechatId;
  }
  return '';
};

const toAccountNicknameFromLabel = (label) => {
  const normalizedLabel = toNullableText(label);
  if (!normalizedLabel) {
    return '';
  }
  if (normalizedLabel.endsWith(')')) {
    const openParenthesisIndex = normalizedLabel.lastIndexOf('(');
    if (openParenthesisIndex > 0) {
      return toNullableText(normalizedLabel.slice(0, openParenthesisIndex));
    }
  }
  return normalizedLabel;
};

const normalizeConversationRecord = (record = {}) => {
  const conversationId = toNullableText(
    record.conversation_id || record.conversationId || record.session_id || record.sessionId || record.id
  );
  const accountWechatId = toNullableText(
    record.account_wechat_id || record.accountWechatId || record.account_id || record.accountId
  );
  const messageType = toNullableText(
    record.message_type || record.messageType
  ).toLowerCase();
  const messagePayloadJson = record.message_payload_json ?? record.messagePayloadJson ?? null;
  const lastMessagePreview = toNullableText(
    record.last_message_preview
    || record.lastMessagePreview
    || toMessagePayloadPreview(messageType, messagePayloadJson)
  );
  return {
    conversation_id: conversationId,
    account_wechat_id: accountWechatId,
    account_nickname: toNullableText(record.account_nickname || record.accountNickname),
    account_label: toAccountLabel(record) || accountWechatId,
    conversation_name: toNullableText(record.conversation_name || record.conversationName || record.customer_nickname || record.customerNickname),
    conversation_type: toNullableText(record.conversation_type || record.conversationType || '-'),
    last_message_preview: lastMessagePreview,
    unread_count: Math.max(0, Number(record.unread_count ?? record.unreadCount ?? 0) || 0),
    last_message_time: toNullableText(record.last_message_time || record.lastMessageTime || record.updated_at || record.updatedAt),
    updated_at: toNullableText(record.updated_at || record.updatedAt || record.last_message_time || record.lastMessageTime),
    created_at: toNullableText(record.created_at || record.createdAt)
  };
};

const normalizeMessageRecord = (record = {}, fallbackIndex = 0) => {
  const messageType = toNullableText(
    record.message_type || record.messageType
  ).toLowerCase();
  const messagePayloadJson = record.message_payload_json ?? record.messagePayloadJson ?? null;
  const isSelfRaw = record.is_self ?? record.isSelf;
  const isSelf = isSelfRaw === null || isSelfRaw === undefined
    ? null
    : (Number(isSelfRaw) === 1 ? 1 : 0);
  return {
    message_id: toNullableText(record.message_id || record.messageId || `message-${fallbackIndex}`),
    conversation_id: toNullableText(record.conversation_id || record.conversationId),
    sender_name: toNullableText(
      record.sender_name
      || record.senderName
      || record.sendname
      || record.send_name
      || '-'
    ),
    message_type: messageType || 'text',
    message_payload_json: messagePayloadJson,
    message_time: toNullableText(record.message_time || record.messageTime || record.sent_at || record.sentAt || record.created_at || record.createdAt),
    created_at: toNullableText(record.created_at || record.createdAt || record.ingested_at || record.ingestedAt),
    ingested_at: toNullableText(record.ingested_at || record.ingestedAt || record.created_at || record.createdAt),
    is_self: isSelf,
    content_preview: toMessagePayloadPreview(messageType || 'text', messagePayloadJson)
  };
};

const toTimestamp = (value) => {
  const timestamp = Date.parse(String(value || '').trim());
  if (Number.isNaN(timestamp)) {
    return 0;
  }
  return timestamp;
};

const compareConversationByRecentDesc = (left = {}, right = {}) => {
  const byLastMessageTime =
    toTimestamp(right?.last_message_time) - toTimestamp(left?.last_message_time);
  if (byLastMessageTime !== 0) {
    return byLastMessageTime;
  }
  const byUpdatedAt = toTimestamp(right?.updated_at) - toTimestamp(left?.updated_at);
  if (byUpdatedAt !== 0) {
    return byUpdatedAt;
  }
  return String(right?.conversation_id || '').localeCompare(
    String(left?.conversation_id || '')
  );
};

const compareMessageByTimelineAsc = (left = {}, right = {}) => {
  const byMessageTime = toTimestamp(left?.message_time) - toTimestamp(right?.message_time);
  if (byMessageTime !== 0) {
    return byMessageTime;
  }
  const byCreatedAt =
    toTimestamp(left?.created_at || left?.ingested_at || left?.message_time)
    - toTimestamp(right?.created_at || right?.ingested_at || right?.message_time);
  if (byCreatedAt !== 0) {
    return byCreatedAt;
  }
  return String(left?.message_id || '').localeCompare(String(right?.message_id || ''));
};

const padTimeUnit = (value) => String(Number(value || 0)).padStart(2, '0');

const toDateInstance = (value) => {
  const timestamp = Date.parse(String(value || '').trim());
  if (Number.isNaN(timestamp)) {
    return null;
  }
  return new Date(timestamp);
};

const toDayStartTimestamp = (date) =>
  new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();

const formatMonthDay = (date) => `${padTimeUnit(date.getMonth() + 1)}-${padTimeUnit(date.getDate())}`;

const formatYearMonthDay = (date) =>
  `${date.getFullYear()}-${padTimeUnit(date.getMonth() + 1)}-${padTimeUnit(date.getDate())}`;

const formatHourMinute = (date) => `${padTimeUnit(date.getHours())}:${padTimeUnit(date.getMinutes())}`;

const formatConversationListTime = (value) => {
  const targetDate = toDateInstance(value);
  if (!targetDate) {
    return formatDateTimeMinute(value);
  }
  const nowDate = new Date();
  const dayDiff = Math.floor(
    (toDayStartTimestamp(nowDate) - toDayStartTimestamp(targetDate)) / (24 * 60 * 60 * 1000)
  );
  if (dayDiff === 0) {
    return formatHourMinute(targetDate);
  }
  if (dayDiff === 1) {
    return '昨天';
  }
  if (dayDiff > 1 && targetDate.getFullYear() === nowDate.getFullYear()) {
    return formatMonthDay(targetDate);
  }
  return formatYearMonthDay(targetDate);
};

const formatConversationMessageTime = (value) => {
  const targetDate = toDateInstance(value);
  if (!targetDate) {
    return formatDateTimeMinute(value);
  }
  const nowDate = new Date();
  const dayDiff = Math.floor(
    (toDayStartTimestamp(nowDate) - toDayStartTimestamp(targetDate)) / (24 * 60 * 60 * 1000)
  );
  const timeText = formatHourMinute(targetDate);
  if (dayDiff === 0) {
    return timeText;
  }
  if (dayDiff === 1) {
    return `昨天 ${timeText}`;
  }
  if (dayDiff > 1 && targetDate.getFullYear() === nowDate.getFullYear()) {
    return `${formatMonthDay(targetDate)} ${timeText}`;
  }
  return `${formatYearMonthDay(targetDate)} ${timeText}`;
};

const formatProblemText = (error, fallback) => {
  const text = toProblemMessage(error, fallback);
  const errorCode = String(error?.payload?.error_code || '').trim();
  if (!errorCode || text.includes(errorCode)) {
    return text;
  }
  return `${text}（${errorCode}）`;
};

const normalizeConversationDisplayName = (value) => {
  const normalizedValue = toNullableText(value);
  if (!normalizedValue) {
    return '';
  }
  const strippedValue = normalizedValue.replace(/-\d{8,}$/, '').trim();
  return strippedValue || normalizedValue;
};

const resolveConversationDisplayName = (conversationRecord = {}, messageList = []) => {
  const normalizedConversationName = normalizeConversationDisplayName(
    conversationRecord?.conversation_name
  );
  if (normalizedConversationName) {
    return normalizedConversationName;
  }
  const firstInboundMessage = (Array.isArray(messageList) ? messageList : []).find(
    (messageRecord) => Number(messageRecord?.is_self) !== 1
  );
  return toNullableText(firstInboundMessage?.sender_name) || '';
};

const renderMessageContent = (messageRecord = {}, { isOutbound = false } = {}) => {
  const messageType = String(messageRecord.message_type || '').trim().toLowerCase();
  const payload = messageRecord.message_payload_json;
  if (messageType === 'text') {
    const textValue = toNullableText(payload?.text ?? payload?.content ?? payload?.message);
    return <Text style={isOutbound ? { color: '#fff' } : undefined}>{textValue || '-'}</Text>;
  }
  if (messageType === 'image') {
    const imageUrl = toNullableText(payload?.url ?? payload?.image_url ?? payload?.src);
    if (!imageUrl) {
      return <Text style={isOutbound ? { color: '#fff' } : undefined}>[图片]</Text>;
    }
    return (
      <a
        href={imageUrl}
        target="_blank"
        rel="noreferrer noopener"
        style={isOutbound ? { color: '#fff' } : undefined}
      >
        [图片] {imageUrl}
      </a>
    );
  }
  return (
    <Text style={isOutbound ? { color: '#fff' } : undefined}>
      {messageRecord.content_preview || '-'}
    </Text>
  );
};

export default function TenantSessionCenterPage({
  accessToken,
  tenantPermissionContext = null
}) {
  const { token } = theme.useToken();
  const api = useMemo(
    () => createTenantManagementApi({ accessToken }),
    [accessToken]
  );
  const [messageApi, messageContextHolder] = message.useMessage();

  const [activeScope, setActiveScope] = useState('');
  const [sessionFilters, setSessionFilters] = useState({
    account_wechat_id: '',
    keyword: ''
  });
  const [keywordInput, setKeywordInput] = useState('');
  const [sessionTableRefreshToken, setSessionTableRefreshToken] = useState(0);
  const [conversationList, setConversationList] = useState([]);
  const [conversationListLoading, setConversationListLoading] = useState(false);
  const [conversationListPage, setConversationListPage] = useState(1);
  const [conversationListPageSize, setConversationListPageSize] = useState(
    SESSION_LIST_DEFAULT_PAGE_SIZE
  );
  const [conversationListTotal, setConversationListTotal] = useState(0);
  const [accountOptions, setAccountOptions] = useState([]);
  const [accountOptionsLoading, setAccountOptionsLoading] = useState(false);
  const [selectedConversation, setSelectedConversation] = useState(null);
  const [conversationMessages, setConversationMessages] = useState([]);
  const [conversationMessagesLoading, setConversationMessagesLoading] = useState(false);
  const [conversationMessagesLoadingMore, setConversationMessagesLoadingMore] = useState(false);
  const [conversationMessagesNextCursor, setConversationMessagesNextCursor] = useState('');
  const [conversationMessagesHasMore, setConversationMessagesHasMore] = useState(false);
  const [sendContent, setSendContent] = useState('');
  const [sendingMessage, setSendingMessage] = useState(false);
  const [moduleViewportHeight, setModuleViewportHeight] = useState(0);
  const [isPageVisible, setIsPageVisible] = useState(() => {
    if (typeof document === 'undefined') {
      return true;
    }
    return document.visibilityState !== 'hidden';
  });
  const latestMessageRequestRef = useRef({
    requestId: 0,
    conversationId: ''
  });
  const conversationListRef = useRef([]);
  const selectedConversationRef = useRef(null);
  const conversationMessageListRef = useRef(null);
  const sessionModuleRef = useRef(null);

  useEffect(() => {
    selectedConversationRef.current = selectedConversation || null;
  }, [selectedConversation]);
  useEffect(() => {
    conversationListRef.current = Array.isArray(conversationList)
      ? conversationList
      : [];
  }, [conversationList]);
  useEffect(() => {
    if (typeof document === 'undefined') {
      return undefined;
    }
    const syncPageVisibility = () => {
      setIsPageVisible(document.visibilityState !== 'hidden');
    };
    syncPageVisibility();
    document.addEventListener('visibilitychange', syncPageVisibility);
    return () => {
      document.removeEventListener('visibilitychange', syncPageVisibility);
    };
  }, []);

  const activeConversationDisplayName = useMemo(
    () => resolveConversationDisplayName(selectedConversation, conversationMessages),
    [selectedConversation, conversationMessages]
  );

  const hasTenantPermissionContext =
    tenantPermissionContext && typeof tenantPermissionContext === 'object';
  const canViewSessionManagement = Boolean(
    hasTenantPermissionContext
    && readPermissionFlag(
      tenantPermissionContext,
      'can_view_session_management',
      'canViewSessionManagement'
    )
  );
  const canOperateSessionManagement = Boolean(
    hasTenantPermissionContext
    && readPermissionFlag(
      tenantPermissionContext,
      'can_operate_session_management',
      'canOperateSessionManagement'
    )
  );

  const visibleScopes = useMemo(() => {
    if (!hasTenantPermissionContext || !canViewSessionManagement) {
      return [];
    }
    return Object.entries(SESSION_SCOPE_CONFIG)
      .filter(([_scopeKey, scopeMeta]) =>
        readPermissionFlag(
          tenantPermissionContext,
          scopeMeta.viewSnakeCase,
          scopeMeta.viewCamelCase
        )
      )
      .map(([scopeKey, scopeMeta]) => ({
        key: scopeKey,
        label: scopeMeta.label,
        testId: scopeMeta.testId
      }));
  }, [canViewSessionManagement, hasTenantPermissionContext, tenantPermissionContext]);

  useEffect(() => {
    const firstScopeKey = visibleScopes[0]?.key || '';
    if (!firstScopeKey) {
      if (activeScope) {
        setActiveScope('');
      }
      return;
    }
    const hasCurrentScope = visibleScopes.some((scope) => scope.key === activeScope);
    if (!hasCurrentScope) {
      setActiveScope(firstScopeKey);
    }
  }, [activeScope, visibleScopes]);

  useEffect(() => {
    if (typeof window === 'undefined') {
      return undefined;
    }
    const updateModuleViewportHeight = () => {
      const moduleTop = sessionModuleRef.current?.getBoundingClientRect?.().top;
      if (!Number.isFinite(moduleTop)) {
        return;
      }
      const nextHeight = Math.max(420, Math.floor(window.innerHeight - moduleTop - 12));
      setModuleViewportHeight((previousHeight) =>
        previousHeight === nextHeight ? previousHeight : nextHeight
      );
    };
    const rafId = window.requestAnimationFrame(updateModuleViewportHeight);
    window.addEventListener('resize', updateModuleViewportHeight);
    return () => {
      window.cancelAnimationFrame(rafId);
      window.removeEventListener('resize', updateModuleViewportHeight);
    };
  }, []);

  const notifySuccess = useCallback((text) => {
    const normalizedText = toNullableText(text);
    if (normalizedText) {
      messageApi.success(normalizedText);
    }
  }, [messageApi]);

  const notifyError = useCallback((error, fallback) => {
    messageApi.error(formatProblemText(error, fallback));
  }, [messageApi]);

  const invalidateMessageRequest = useCallback(() => {
    latestMessageRequestRef.current = {
      requestId: latestMessageRequestRef.current.requestId + 1,
      conversationId: ''
    };
  }, []);

  const loadAccountOptions = useCallback(async (scope) => {
    const normalizedScope = toNullableText(scope);
    if (!normalizedScope) {
      setAccountOptions([]);
      return;
    }
    setAccountOptionsLoading(true);
    try {
      const payload = await api.listSessionAccounts({ scope: normalizedScope });
      const accountList = Array.isArray(payload?.accounts)
        ? payload.accounts
        : (Array.isArray(payload?.items) ? payload.items : []);
      const options = [];
      const seenAccountWechatIds = new Set();
      for (const account of accountList) {
        const accountWechatId = toNullableText(
          account.account_wechat_id
          || account.accountWechatId
          || account.wechat_id
          || account.wechatId
          || account.account_id
          || account.accountId
        );
        if (!accountWechatId || seenAccountWechatIds.has(accountWechatId)) {
          continue;
        }
        seenAccountWechatIds.add(accountWechatId);
        const accountNickname = toNullableText(
          account.account_nickname
          || account.accountNickname
          || account.nickname
          || account.account_name
        );
        const accountLabel = toAccountLabel(account);
        options.push({
          value: accountWechatId,
          label: accountLabel || accountWechatId,
          nickname: accountNickname || toAccountNicknameFromLabel(accountLabel),
          wechat_id: accountWechatId
        });
      }
      options.sort((left, right) =>
        String(left.label || '').localeCompare(String(right.label || ''), 'zh-Hans-CN')
      );
      setAccountOptions(options);
      const selectedAccountWechatId = toNullableText(sessionFilters.account_wechat_id);
      const hasSelectedAccountWechatId = options.some(
        (option) => toNullableText(option?.value) === selectedAccountWechatId
      );
      const nextAccountWechatId = hasSelectedAccountWechatId
        ? selectedAccountWechatId
        : toNullableText(options[0]?.value);
      if (selectedAccountWechatId !== nextAccountWechatId) {
        setSessionFilters((previous) => ({
          ...previous,
          account_wechat_id: nextAccountWechatId
        }));
        setConversationListPage(1);
      }
    } catch (error) {
      setAccountOptions([]);
      notifyError(error, '加载会话账号筛选失败');
    } finally {
      setAccountOptionsLoading(false);
    }
  }, [api, notifyError, sessionFilters.account_wechat_id]);

  const resetConversationPanel = useCallback(() => {
    invalidateMessageRequest();
    setSelectedConversation(null);
    setConversationMessages([]);
    setConversationMessagesLoading(false);
    setConversationMessagesLoadingMore(false);
    setConversationMessagesNextCursor('');
    setConversationMessagesHasMore(false);
    setSendContent('');
  }, [invalidateMessageRequest]);

  const applyKeywordFilter = useCallback((keywordValue) => {
    const normalizedKeyword = toNullableText(keywordValue);
    setSessionFilters((previous) => {
      if (toNullableText(previous.keyword) === normalizedKeyword) {
        return previous;
      }
      return {
        ...previous,
        keyword: normalizedKeyword
      };
    });
    setConversationListPage(1);
    resetConversationPanel();
    setSessionTableRefreshToken((previous) => previous + 1);
  }, [resetConversationPanel]);

  useEffect(() => {
    if (!accessToken || !canViewSessionManagement || visibleScopes.length < 1) {
      setAccountOptions([]);
      return;
    }
    void loadAccountOptions(activeScope || visibleScopes[0]?.key || '');
  }, [accessToken, activeScope, canViewSessionManagement, loadAccountOptions, visibleScopes]);

  const loadConversationMessages = useCallback(async (
    conversationRecord,
    {
      appendOlder = false,
      cursor = '',
      silent = false
    } = {}
  ) => {
    const normalizedConversationId = toNullableText(conversationRecord?.conversation_id);
    const normalizedAccountWechatId = toNullableText(conversationRecord?.account_wechat_id);
    const normalizedScope = toNullableText(activeScope);
    if (!normalizedConversationId || !normalizedAccountWechatId || !normalizedScope) {
      invalidateMessageRequest();
      setConversationMessages([]);
      setConversationMessagesLoading(false);
      setConversationMessagesLoadingMore(false);
      setConversationMessagesNextCursor('');
      setConversationMessagesHasMore(false);
      return;
    }

    if (appendOlder) {
      if (!cursor || conversationMessagesLoading || conversationMessagesLoadingMore) {
        return;
      }
      setConversationMessagesLoadingMore(true);
    } else if (!silent) {
      setConversationMessages([]);
      setConversationMessagesLoading(true);
      setConversationMessagesLoadingMore(false);
      setConversationMessagesNextCursor('');
      setConversationMessagesHasMore(false);
    }

    const requestId = latestMessageRequestRef.current.requestId + 1;
    latestMessageRequestRef.current = {
      requestId,
      conversationId: normalizedConversationId
    };
    try {
      const payload = await api.getSessionMessages({
        conversationId: normalizedConversationId,
        scope: normalizedScope,
        account_wechat_id: normalizedAccountWechatId,
        cursor: appendOlder ? cursor : undefined,
        limit: SESSION_MESSAGE_DEFAULT_LIMIT
      });
      const messageList = Array.isArray(payload?.messages)
        ? payload.messages
        : (Array.isArray(payload?.items) ? payload.items : []);
      const nextCursor = toNullableText(payload?.next_cursor || payload?.nextCursor);
      const normalizedMessages = messageList
        .map((sessionMessage, index) => normalizeMessageRecord(sessionMessage, index))
        .sort((left, right) => compareMessageByTimelineAsc(left, right));
      const latestRequest = latestMessageRequestRef.current;
      if (
        latestRequest.requestId !== requestId
        || latestRequest.conversationId !== normalizedConversationId
      ) {
        return;
      }
      if (appendOlder) {
        setConversationMessages((previousMessages) => {
          const mergedMessageMap = new Map();
          for (const messageRecord of normalizedMessages) {
            mergedMessageMap.set(messageRecord.message_id, messageRecord);
          }
          for (const messageRecord of previousMessages) {
            mergedMessageMap.set(messageRecord.message_id, messageRecord);
          }
          return [...mergedMessageMap.values()].sort((left, right) =>
            compareMessageByTimelineAsc(left, right)
          );
        });
      } else {
        setConversationMessages(normalizedMessages);
      }
      setConversationMessagesNextCursor(nextCursor);
      setConversationMessagesHasMore(Boolean(nextCursor));
    } catch (error) {
      const latestRequest = latestMessageRequestRef.current;
      if (
        latestRequest.requestId !== requestId
        || latestRequest.conversationId !== normalizedConversationId
      ) {
        return;
      }
      if (!appendOlder) {
        if (!silent) {
          setConversationMessages([]);
          setConversationMessagesNextCursor('');
          setConversationMessagesHasMore(false);
        }
      }
      if (!silent) {
        notifyError(error, '加载会话消息失败');
      }
    } finally {
      const latestRequest = latestMessageRequestRef.current;
      if (
        latestRequest.requestId === requestId
        && latestRequest.conversationId === normalizedConversationId
      ) {
        if (appendOlder) {
          setConversationMessagesLoadingMore(false);
        } else if (!silent) {
          setConversationMessagesLoading(false);
        }
      }
    }
  }, [
    activeScope,
    api,
    conversationMessagesLoading,
    conversationMessagesLoadingMore,
    invalidateMessageRequest,
    notifyError
  ]);

  const loadConversationList = useCallback(async ({
    page = conversationListPage,
    pageSize = conversationListPageSize,
    append = false
  } = {}) => {
    const currentScope = toNullableText(activeScope);
    const accountWechatId = toNullableText(sessionFilters.account_wechat_id);
    const hasSelectedAccountOption = accountOptions.some(
      (option) => toNullableText(option?.value) === accountWechatId
    );
    if (!currentScope || !accountWechatId || !hasSelectedAccountOption) {
      setConversationList([]);
      setConversationListTotal(0);
      setConversationListLoading(false);
      return;
    }

    setConversationListLoading(true);
    try {
      const payload = await api.listSessions({
        page,
        pageSize,
        scope: currentScope,
        account_wechat_id: accountWechatId,
        keyword: sessionFilters.keyword
      });
      const sourceChats = Array.isArray(payload?.chats)
        ? payload.chats
        : (Array.isArray(payload?.sessions) ? payload.sessions : []);
      const accountOptionByWechatId = new Map(
        accountOptions.map((option) => [
          toNullableText(option?.value),
          option
        ])
      );
      const normalizedConversations = sourceChats
        .map((chatRecord) => normalizeConversationRecord(chatRecord))
        .map((chatRecord) => {
          const accountOption = accountOptionByWechatId.get(
            toNullableText(chatRecord?.account_wechat_id)
          );
          const fallbackAccountLabel = toNullableText(accountOption?.label);
          const fallbackAccountNickname = toNullableText(accountOption?.nickname)
            || toAccountNicknameFromLabel(fallbackAccountLabel);
          return {
            ...chatRecord,
            account_nickname:
              toNullableText(chatRecord?.account_nickname)
              || fallbackAccountNickname,
            account_label:
              toNullableText(chatRecord?.account_label)
              || fallbackAccountLabel
              || toNullableText(chatRecord?.account_wechat_id)
          };
        })
        .map((chatRecord) => ({ ...chatRecord, key: chatRecord.conversation_id }));
      const resolvedTotal = Number.isFinite(Number(payload?.total))
        ? Number(payload.total)
        : (
          (page - 1) * pageSize
          + sourceChats.length
          + (sourceChats.length === pageSize ? 1 : 0)
        );
      const nextConversationList = append
        ? (() => {
          const mergedMap = new Map(
            conversationListRef.current.map((conversationRecord) => [
              toNullableText(conversationRecord?.conversation_id),
              conversationRecord
            ])
          );
          for (const conversationRecord of normalizedConversations) {
            mergedMap.set(
              toNullableText(conversationRecord?.conversation_id),
              conversationRecord
            );
          }
          return [...mergedMap.values()];
        })()
        : normalizedConversations;
      const sortedConversationList = [...nextConversationList].sort((left, right) =>
        compareConversationByRecentDesc(left, right)
      );
      setConversationList(sortedConversationList);
      setConversationListTotal(resolvedTotal);
      const selectedConversationId = toNullableText(
        selectedConversationRef.current?.conversation_id
      );
      if (selectedConversationId) {
        const matchedConversation = sortedConversationList.find(
          (conversation) => toNullableText(conversation?.conversation_id) === selectedConversationId
        );
        if (matchedConversation) {
          setSelectedConversation((previous) => {
            const previousConversationId = toNullableText(previous?.conversation_id);
            if (previousConversationId !== selectedConversationId) {
              return previous;
            }
            const hasSameSummary =
              toNullableText(previous?.conversation_name)
                === toNullableText(matchedConversation?.conversation_name)
              && toNullableText(previous?.last_message_preview)
                === toNullableText(matchedConversation?.last_message_preview)
              && toNullableText(previous?.last_message_time)
                === toNullableText(matchedConversation?.last_message_time)
              && toNullableText(previous?.account_nickname)
                === toNullableText(matchedConversation?.account_nickname)
              && toNullableText(previous?.account_label)
                === toNullableText(matchedConversation?.account_label);
            if (hasSameSummary) {
              return previous;
            }
            return {
              ...previous,
              ...matchedConversation
            };
          });
          return;
        }
        if (append) {
          return;
        }
        invalidateMessageRequest();
        setConversationMessages([]);
        setConversationMessagesLoading(false);
        setConversationMessagesLoadingMore(false);
        setConversationMessagesNextCursor('');
        setConversationMessagesHasMore(false);
        setSendContent('');
        setSelectedConversation(null);
      }
    } catch (error) {
      if (!append) {
        setConversationList([]);
        setConversationListTotal(0);
      }
      notifyError(error, '加载会话列表失败');
    } finally {
      setConversationListLoading(false);
    }
  }, [
    activeScope,
    accountOptions,
    api,
    conversationListPage,
    conversationListPageSize,
    invalidateMessageRequest,
    notifyError,
    sessionFilters.account_wechat_id,
    sessionFilters.keyword
  ]);

  useEffect(() => {
    if (!accessToken || !canViewSessionManagement || visibleScopes.length < 1) {
      setConversationList([]);
      setConversationListTotal(0);
      setConversationListLoading(false);
      return;
    }
    void loadConversationList({
      page: conversationListPage,
      pageSize: conversationListPageSize,
      append: conversationListPage > 1
    });
  }, [
    accessToken,
    canViewSessionManagement,
    conversationListPage,
    conversationListPageSize,
    loadConversationList,
    sessionTableRefreshToken,
    visibleScopes.length
  ]);

  useEffect(() => {
    if (
      typeof window === 'undefined'
      || !accessToken
      || !canViewSessionManagement
      || !isPageVisible
      || visibleScopes.length < 1
      || conversationListPage !== 1
    ) {
      return undefined;
    }
    const currentScope = toNullableText(activeScope);
    const accountWechatId = toNullableText(sessionFilters.account_wechat_id);
    if (!currentScope || !accountWechatId) {
      return undefined;
    }
    const timerId = window.setInterval(() => {
      if (conversationListLoading) {
        return;
      }
      void loadConversationList({
        page: 1,
        pageSize: conversationListPageSize,
        append: false
      });
    }, SESSION_LIST_POLL_INTERVAL_MS);
    return () => {
      window.clearInterval(timerId);
    };
  }, [
    accessToken,
    activeScope,
    canViewSessionManagement,
    conversationListLoading,
    conversationListPage,
    conversationListPageSize,
    isPageVisible,
    loadConversationList,
    sessionFilters.account_wechat_id,
    visibleScopes.length
  ]);

  useEffect(() => {
    if (
      typeof window === 'undefined'
      || !accessToken
      || !canViewSessionManagement
      || !isPageVisible
    ) {
      return undefined;
    }
    const selectedConversationId = toNullableText(selectedConversation?.conversation_id);
    if (!selectedConversationId) {
      return undefined;
    }
    const timerId = window.setInterval(() => {
      if (conversationMessagesLoading || conversationMessagesLoadingMore) {
        return;
      }
      const targetConversation = selectedConversationRef.current;
      if (!toNullableText(targetConversation?.conversation_id)) {
        return;
      }
      void loadConversationMessages(targetConversation, {
        silent: true
      });
    }, SESSION_DETAIL_POLL_INTERVAL_MS);
    return () => {
      window.clearInterval(timerId);
    };
  }, [
    accessToken,
    canViewSessionManagement,
    conversationMessagesLoading,
    conversationMessagesLoadingMore,
    isPageVisible,
    loadConversationMessages,
    selectedConversation?.conversation_id
  ]);

  const loadOlderConversationMessages = useCallback(async () => {
    if (
      !conversationMessagesHasMore
      || conversationMessagesLoading
      || conversationMessagesLoadingMore
    ) {
      return;
    }
    const cursor = toNullableText(conversationMessagesNextCursor);
    if (!cursor) {
      return;
    }
    const container = conversationMessageListRef.current;
    const previousScrollTop = container?.scrollTop || 0;
    const previousScrollHeight = container?.scrollHeight || 0;
    const targetConversation = selectedConversationRef.current;
    await loadConversationMessages(targetConversation, {
      appendOlder: true,
      cursor
    });
    if (container) {
      requestAnimationFrame(() => {
        const nextScrollHeight = container.scrollHeight || 0;
        const scrollDelta = nextScrollHeight - previousScrollHeight;
        container.scrollTop = Math.max(0, previousScrollTop + scrollDelta);
      });
    }
  }, [
    conversationMessagesHasMore,
    conversationMessagesLoading,
    conversationMessagesLoadingMore,
    conversationMessagesNextCursor,
    loadConversationMessages
  ]);

  const handleSendMessage = useCallback(async () => {
    const normalizedConversationId = toNullableText(selectedConversation?.conversation_id);
    const selectedAccountWechatId = toNullableText(sessionFilters.account_wechat_id);
    const normalizedAccountWechatId =
      toNullableText(selectedConversation?.account_wechat_id)
      || selectedAccountWechatId;
    const selectedAccountOption = accountOptions.find(
      (option) => toNullableText(option?.value) === normalizedAccountWechatId
    );
    const fallbackAccountLabel = toNullableText(
      selectedAccountOption?.label || selectedConversation?.account_label
    );
    const normalizedAccountNickname =
      toNullableText(selectedConversation?.account_nickname)
      || toNullableText(selectedAccountOption?.nickname)
      || toAccountNicknameFromLabel(fallbackAccountLabel)
      || normalizedAccountWechatId;
    const normalizedConversationName =
      toNullableText(selectedConversation?.conversation_name)
      || normalizedConversationId;
    const normalizedContent = toNullableText(sendContent);
    if (
      !normalizedConversationId
      || !normalizedAccountWechatId
      || !normalizedAccountNickname
      || !normalizedContent
    ) {
      return;
    }
    setSendingMessage(true);
    try {
      await api.sendSessionMessage({
        payload: {
          account_wechat_id: normalizedAccountWechatId,
          account_nickname: normalizedAccountNickname,
          conversation_id: normalizedConversationId,
          conversation_name: normalizedConversationName,
          message_type: 'text',
          message_payload_json: {
            text: normalizedContent
          }
        }
      });
      setSendContent('');
      notifySuccess('消息已入队');
      setSessionTableRefreshToken((previous) => previous + 1);
      await loadConversationMessages({
        ...selectedConversation,
        account_wechat_id: normalizedAccountWechatId
      });
    } catch (error) {
      notifyError(error, '发送消息失败');
    } finally {
      setSendingMessage(false);
    }
  }, [
    accountOptions,
    api,
    loadConversationMessages,
    notifyError,
    notifySuccess,
    selectedConversation,
    sendContent,
    sessionFilters.account_wechat_id
  ]);

  const selectedAccountWechatId = toNullableText(sessionFilters.account_wechat_id) || undefined;

  if (!accessToken) {
    return (
      <section data-testid="tenant-sessions-no-session" style={{ marginTop: 12 }}>
        <Alert type="warning" message="当前会话缺失 access_token，无法加载会话中心。" showIcon />
      </section>
    );
  }

  if (!canViewSessionManagement) {
    return (
      <section data-testid="tenant-sessions-no-view-permission" style={{ marginTop: 12 }}>
        <Alert
          type="warning"
          showIcon
          message="当前角色缺少会话管理查看权限，无法访问会话中心。"
        />
      </section>
    );
  }

  return (
    <section
      ref={sessionModuleRef}
      data-testid="tenant-sessions-module"
      style={{
        display: 'flex',
        flexDirection: 'column',
        height: moduleViewportHeight > 0 ? moduleViewportHeight : '100%',
        minHeight: 0,
        overflow: 'hidden'
      }}
    >
      {messageContextHolder}

      {visibleScopes.length > 0 ? (
        <Tabs
          activeKey={activeScope}
          style={{ margin: '-12px 0 0 0' }}
          tabBarStyle={{ margin: '0 0 12px 0' }}
          tabBarExtraContent={(
            <Select
              data-testid="tenant-session-filter-account-id"
              value={selectedAccountWechatId}
              showSearch
              options={accountOptions}
              loading={accountOptionsLoading}
              placeholder="请选择账号"
              style={{ width: 260 }}
              filterOption={(input, option) =>
                String(option?.label || '').toLowerCase().includes(String(input || '').toLowerCase())
              }
              onChange={(value) => {
                const nextAccountWechatId = toNullableText(value);
                setSessionFilters((previous) => ({
                  ...previous,
                  account_wechat_id: nextAccountWechatId
                }));
                setConversationListPage(1);
                resetConversationPanel();
                setSessionTableRefreshToken((previous) => previous + 1);
              }}
            />
          )}
          onChange={(scope) => {
            setActiveScope(scope);
            setSessionFilters((previous) => ({
              ...previous,
              account_wechat_id: ''
            }));
            setConversationListPage(1);
            resetConversationPanel();
            setSessionTableRefreshToken((previous) => previous + 1);
          }}
          items={visibleScopes.map((scope) => ({
            key: scope.key,
            label: <span data-testid={scope.testId}>{scope.label}</span>
          }))}
        />
      ) : (
        <Alert
          type="warning"
          showIcon
          message="当前角色缺少会话范围权限，无法访问会话中心。"
        />
      )}

      {visibleScopes.length > 0 ? (
        <>
          <section
            style={{
              display: 'grid',
              gridTemplateColumns: 'minmax(280px, 360px) 1fr',
              gap: 12,
              alignItems: 'stretch',
              flex: 1,
              minHeight: 0,
              overflow: 'hidden'
            }}
          >
            <CustomCard
              title="会话列表"
              style={{
                display: 'flex',
                flexDirection: 'column',
                marginBottom: 0,
                height: '100%',
                minWidth: 0,
                boxShadow: '0 0 0 1px #e5e5e5, 0 2px 8px rgba(0, 0, 0, 0.06)',
                background: '#fff'
              }}
              bodyStyle={{
                flex: 1,
                overflow: 'hidden',
                display: 'flex',
                flexDirection: 'column',
                padding: 12
              }}
            >
              <section style={{ marginBottom: 12 }}>
                <Input.Search
                  data-testid="tenant-session-filter-keyword"
                  value={keywordInput}
                  allowClear
                  placeholder="请输入"
                  enterButton={false}
                  onChange={(event) => {
                    const nextKeywordInput = event.target.value;
                    setKeywordInput(nextKeywordInput);
                    if (!toNullableText(nextKeywordInput)) {
                      applyKeywordFilter('');
                    }
                  }}
                  onSearch={(value) => {
                    setKeywordInput(value);
                    applyKeywordFilter(value);
                  }}
                />
              </section>
              {conversationList.length > 0 ? (
                <div
                  id="tenant-session-list-scrollable"
                  style={{ flex: 1, overflowY: 'auto', position: 'relative' }}
                  onScroll={(e) => {
                    const { scrollHeight, scrollTop, clientHeight } = e.currentTarget;
                    if (scrollHeight - scrollTop - clientHeight < 50 && !conversationListLoading) {
                      if (conversationList.length < conversationListTotal) {
                        setConversationListPage((prev) => prev + 1);
                      }
                    }
                  }}
                >
                  <List
                    itemLayout="horizontal"
                    dataSource={conversationList}
                    pagination={false}
                    renderItem={(conversationRecord) => {
                      const conversationId = toNullableText(conversationRecord?.conversation_id);
                      const isSelected = conversationId
                        && conversationId === toNullableText(selectedConversation?.conversation_id);
                      return (
                        <List.Item
                          data-testid={`tenant-session-id-${conversationId}`}
                          onClick={() => {
                            invalidateMessageRequest();
                            setSelectedConversation(conversationRecord);
                            setSendContent('');
                            void loadConversationMessages(conversationRecord);
                          }}
                          style={{
                            cursor: 'pointer',
                            padding: '10px 12px',
                            borderRadius: 0,
                            marginBottom: 0,
                            background: isSelected ? '#f2f2f2' : '#fff',
                            borderBottom: '1px solid #f0f0f0'
                          }}
                        >
                          <List.Item.Meta
                            avatar={(
                              <Avatar
                                icon={<UserOutlined />}
                                style={{
                                  background: isSelected ? token.colorPrimary : '#d9d9d9'
                                }}
                              />
                            )}
                            title={(
                              <section
                                style={{
                                  display: 'flex',
                                  alignItems: 'center',
                                  justifyContent: 'space-between',
                                  gap: 8
                                }}
                              >
                                <Text strong ellipsis style={{ maxWidth: 170 }}>
                                  {resolveConversationDisplayName(conversationRecord) || '未命名会话'}
                                </Text>
                                <Space size={4}>
                                  <ClockCircleOutlined style={{ color: '#bfbfbf', fontSize: 12 }} />
                                  <Text type="secondary" style={{ fontSize: 12 }}>
                                    {formatConversationListTime(conversationRecord?.last_message_time)}
                                  </Text>
                                </Space>
                              </section>
                            )}
                            description={(
                              <section style={{ display: 'grid', gap: 4 }}>
                                <Text type="secondary" ellipsis style={{ maxWidth: 240 }}>
                                  {toNullableText(conversationRecord?.last_message_preview) || '暂无消息'}
                                </Text>
                              </section>
                            )}
                          />
                        </List.Item>
                      );
                    }}
                  >
                    {conversationListLoading ? (
                      <div style={{ textAlign: 'center', padding: '10px 0' }}>
                        <Spin size="small" />
                      </div>
                    ) : null}
                  </List>
                </div>
              ) : conversationListLoading ? (
                <section
                  style={{
                    flex: 1,
                    minHeight: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  <Spin size="small" />
                </section>
              ) : (
                <section
                  style={{
                    flex: 1,
                    minHeight: 0,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                  }}
                >
                  <Empty description="暂无会话" />
                </section>
              )}
            </CustomCard>

            <section data-testid="tenant-session-detail-panel" style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0, minWidth: 0, overflow: 'hidden', gap: 12 }}>
              <CustomCard
                style={{ display: 'flex', flexDirection: 'column', marginBottom: 0, height: '100%' }}
                bodyStyle={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column', padding: 12 }}
                title={(
                  <section style={{ minHeight: 28, display: 'flex', alignItems: 'center', minWidth: 0 }}>
                    <Text
                      strong
                      ellipsis
                      style={{ fontSize: 16, display: 'block', maxWidth: '100%' }}
                    >
                      {activeConversationDisplayName || '会话详情'}
                    </Text>
                  </section>
                )}
              >
                <section style={{ display: 'flex', flexDirection: 'column', height: '100%', minHeight: 0 }}>
                  <section style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
                    <section
                      ref={conversationMessageListRef}
                      style={{
                        flex: 1,
                        overflowY: 'auto',
                        padding: '12px 16px',
                        background: '#f5f5f5',
                        borderRadius: '8px 8px 0 0'
                      }}
                      onScroll={(event) => {
                        if (event.currentTarget.scrollTop <= 40) {
                          void loadOlderConversationMessages();
                        }
                      }}
                    >
                      {toNullableText(selectedConversation?.conversation_id) ? (
                        conversationMessagesLoading ? (
                          <section style={{ height: '100%', minHeight: 0, display: 'grid', placeItems: 'center' }}>
                            <Spin size="small" />
                          </section>
                        ) : conversationMessages.length > 0 ? (
                          <>
                            {conversationMessagesLoadingMore ? (
                              <section style={{ display: 'grid', placeItems: 'center', marginBottom: 8 }}>
                                <Spin size="small" />
                              </section>
                            ) : null}
                            {conversationMessages.map((conversationMessage, index) => {
                            const isOutbound = conversationMessage.is_self === 1;
                            return (
                              <article
                                key={`${conversationMessage.message_id}-${index}`}
                                data-testid={`tenant-session-message-${index}`}
                                style={{ marginBottom: 12 }}
                              >
                                <section
                                  style={{
                                    display: 'grid',
                                    justifyContent: 'center',
                                    marginBottom: 8
                                  }}
                                >
                                  <Text type="secondary" style={{ fontSize: 12 }}>
                                    {formatConversationMessageTime(conversationMessage.message_time)}
                                  </Text>
                                </section>
                                <section
                                  style={{
                                    display: 'flex',
                                    justifyContent: isOutbound ? 'flex-end' : 'flex-start'
                                  }}
                                >
                                  <section
                                    style={{
                                      display: 'flex',
                                      alignItems: 'flex-start',
                                      gap: 8,
                                      maxWidth: '72%'
                                    }}
                                  >
                                    {isOutbound ? (
                                      <section
                                        style={{
                                          maxWidth: '100%',
                                          border: `1px solid ${token.colorPrimary}`,
                                          borderRadius: '10px 2px 10px 10px',
                                          padding: '8px 10px',
                                          background: token.colorPrimary,
                                          color: '#fff'
                                        }}
                                      >
                                        {renderMessageContent(conversationMessage, { isOutbound: true })}
                                      </section>
                                    ) : (
                                      <>
                                        <Avatar
                                          icon={<UserOutlined />}
                                          style={{ background: '#d9d9d9' }}
                                        />
                                        <section
                                          style={{
                                            maxWidth: '100%',
                                            border: '1px solid #e8e8e8',
                                            borderRadius: '2px 10px 10px 10px',
                                            padding: '8px 10px',
                                            background: '#fff',
                                            color: 'inherit'
                                          }}
                                        >
                                          <Text type="secondary" style={{ fontSize: 12 }}>
                                            {conversationMessage.sender_name || '-'}
                                          </Text>
                                          <section style={{ marginTop: 4 }}>
                                            {renderMessageContent(conversationMessage, { isOutbound: false })}
                                          </section>
                                        </section>
                                      </>
                                    )}
                                    {isOutbound ? (
                                      <Avatar
                                        icon={<UserOutlined />}
                                        style={{ background: token.colorPrimary }}
                                      />
                                    ) : null}
                                  </section>
                                </section>
                              </article>
                            );
                            })}
                          </>
                        ) : (
                          <section style={{ height: '100%', minHeight: 0, display: 'grid', placeItems: 'center' }}>
                            <Text data-testid="tenant-session-detail-empty" type="secondary">
                              暂无消息记录
                            </Text>
                          </section>
                        )
                      ) : (
                        <section style={{ height: '100%', minHeight: 0, display: 'grid', placeItems: 'center' }}>
                          <Empty description="请选择左侧会话" />
                        </section>
                      )}
                    </section>
                  </section>

                  <section
                    style={{
                      borderTop: '1px solid #e8e8e8',
                      background: '#f5f5f5',
                      padding: '12px 16px',
                      borderRadius: '0 0 8px 8px',
                      position: 'relative',
                      display: 'flex',
                      flexDirection: 'column',
                      flex: `0 0 ${SESSION_MESSAGE_COMPOSER_HEIGHT}px`,
                      height: SESSION_MESSAGE_COMPOSER_HEIGHT,
                      minHeight: SESSION_MESSAGE_COMPOSER_HEIGHT,
                      maxHeight: SESSION_MESSAGE_COMPOSER_HEIGHT
                    }}
                  >
                    <TextArea
                      data-testid="tenant-session-send-input"
                      value={sendContent}
                      onChange={(event) => {
                        setSendContent(event.target.value);
                      }}
                      autoSize={false}
                      placeholder="请输入消息"
                      disabled={!selectedConversation?.conversation_id || !canOperateSessionManagement}
                      maxLength={2000}
                      bordered={false}
                      style={{
                        background: 'transparent',
                        padding: 0,
                        boxShadow: 'none',
                        resize: 'none',
                        height: SESSION_MESSAGE_COMPOSER_HEIGHT - 44,
                        marginBottom: 32
                      }}
                    />
                    {!canOperateSessionManagement ? (
                      <Text data-testid="tenant-session-send-disabled-hint" type="secondary" style={{ position: 'absolute', bottom: 12, left: 16 }}>
                        当前角色缺少会话管理操作权限
                      </Text>
                    ) : null}
                    <Button
                      data-testid="tenant-session-send-submit"
                      type="text"
                      icon={<SendOutlined style={{ fontSize: 20, color: (sendContent.trim() && canOperateSessionManagement) ? token.colorPrimary : '#bfbfbf' }} />}
                      loading={sendingMessage}
                      style={{
                        position: 'absolute',
                        bottom: 8,
                        right: 8,
                        padding: '4px 8px',
                      }}
                      disabled={
                        sendingMessage
                        || !canOperateSessionManagement
                        || !toNullableText(selectedConversation?.conversation_id)
                      }
                      onClick={() => {
                        void handleSendMessage();
                      }}
                    />
                  </section>
                </section>
              </CustomCard>
            </section>
          </section>
        </>
      ) : null}
    </section>
  );
}
