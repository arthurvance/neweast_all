import React, { useCallback } from 'react';
import { Breadcrumb, Button, Row, Col, Space, Tabs, Typography, theme } from 'antd';
import type { BreadcrumbProps, TabsProps } from 'antd';
import { ArrowLeftOutlined } from '@ant-design/icons';

const { Title, Text } = Typography;

export interface CustomPageProps {
  title?: React.ReactNode;
  subTitle?: React.ReactNode;
  tags?: React.ReactNode;
  extra?: React.ReactNode;
  avatar?: React.ReactNode;
  content?: React.ReactNode;
  extraContent?: React.ReactNode;
  breadcrumbItems?: BreadcrumbProps['items'];
  breadcrumbRender?: (items: BreadcrumbProps['items']) => React.ReactNode;
  showBreadcrumb?: boolean;
  ghost?: boolean;
  tabList?: TabsProps['items'];
  tabActiveKey?: string;
  onTabChange?: (key: string) => void;
  tabBarExtraContent?: React.ReactNode;
  tabProps?: Omit<TabsProps, 'items' | 'activeKey' | 'onChange' | 'tabBarExtraContent'>;
  footer?: React.ReactNode;
  contentVariant?: 'default' | 'advanced';
  children?: React.ReactNode;
  style?: React.CSSProperties;
  headerStyle?: React.CSSProperties;
  bodyStyle?: React.CSSProperties;
  showBack?: boolean;
}

const CustomPage: React.FC<CustomPageProps> = ({
  title,
  subTitle,
  tags,
  extra,
  avatar,
  content,
  extraContent,
  breadcrumbItems,
  breadcrumbRender,
  showBreadcrumb = false,
  ghost = true,
  tabList,
  tabActiveKey,
  onTabChange,
  tabBarExtraContent,
  tabProps,
  footer,
  contentVariant = 'default',
  children,
  style,
  headerStyle,
  bodyStyle,
  showBack = false,
}) => {
  const { token } = theme.useToken();

  const handleBack = useCallback(() => {
    if (typeof window !== 'undefined') {
      window.history.back();
    }
  }, []);

  const hasBreadcrumb = Boolean((breadcrumbItems && breadcrumbItems.length > 0) || breadcrumbRender);
  const shouldShowBreadcrumb = showBreadcrumb && hasBreadcrumb;
  const hasTitleInfo = Boolean(title || subTitle || tags || avatar || showBack);
  const hasActions = Boolean(extra);
  const showTitleRow = hasTitleInfo || hasActions;
  const hasHeader = Boolean(title || subTitle || tags || extra || avatar || content || extraContent || (tabList && tabList.length > 0) || footer || showBack);

  const renderBreadcrumb = () => {
    if (breadcrumbRender) return breadcrumbRender(breadcrumbItems || []);
    if (!breadcrumbItems || breadcrumbItems.length === 0) return null;
    return <Breadcrumb items={breadcrumbItems} />;
  };

  const renderTitle = () => {
    if (!title && !subTitle && !tags) return null;
    return (
      <Space size={8} align="center" wrap>
        {title && <Title level={4} style={{ margin: 0 }}>{title}</Title>}
        {subTitle && <Text type="secondary">{subTitle}</Text>}
        {tags}
      </Space>
    );
  };

  const renderContentRow = (offsetTop: boolean) => {
    if (!content && !extraContent) return null;
    const contentStyle = offsetTop ? { marginTop: 16 } : undefined;
    if (content && extraContent) {
      return (
        <Row gutter={24} style={contentStyle}>
          <Col flex="auto">{content}</Col>
          <Col>{extraContent}</Col>
        </Row>
      );
    }
    if (content) return <div style={contentStyle}>{content}</div>;
    return <div style={{ ...contentStyle, display: 'flex', justifyContent: 'flex-end' }}>{extraContent}</div>;
  };

  return (
    <div style={{ minWidth: 0, ...style }}>
      {shouldShowBreadcrumb && (
        <div style={{ background: token.colorBgLayout, borderRadius: token.borderRadiusLG, marginBottom: token.margin }}>
          {renderBreadcrumb()}
        </div>
      )}
      <div style={{
        background: contentVariant === 'advanced' ? token.colorBgLayout : token.colorBgContainer,
        borderRadius: token.borderRadiusLG,
        padding: contentVariant === 'advanced' ? 0 : 24,
      }}>
        {hasHeader && (
          <div style={{ background: ghost ? 'transparent' : token.colorBgContainer, borderRadius: ghost ? 0 : token.borderRadiusLG, ...headerStyle }}>
            {showTitleRow && (
              <div style={{ display: 'flex', justifyContent: hasTitleInfo && hasActions ? 'space-between' : hasTitleInfo ? 'flex-start' : 'flex-end', alignItems: 'center', gap: 16 }}>
                {hasTitleInfo && (
                  <Space size={12} align="center">
                    {showBack && <Button type="text" icon={<ArrowLeftOutlined />} onClick={handleBack} aria-label="返回上一页" />}
                    {avatar}
                    {renderTitle()}
                  </Space>
                )}
                {hasActions && <Space size={12} align="center" wrap>{extra}</Space>}
              </div>
            )}
            {renderContentRow(showTitleRow)}
            {tabList && tabList.length > 0 && (
              <Tabs items={tabList} activeKey={tabActiveKey} onChange={onTabChange} tabBarExtraContent={tabBarExtraContent} style={{ marginTop: 16 }} {...tabProps} />
            )}
            {footer && <div style={{ marginTop: 8 }}>{footer}</div>}
          </div>
        )}
        <div style={{ marginTop: hasHeader ? 16 : 0, ...bodyStyle }}>{children}</div>
      </div>
    </div>
  );
};

export default CustomPage;
