import React, { useState, useMemo, useEffect } from 'react';
import {
  Layout,
  Breadcrumb,
  Menu,
  Avatar,
  Dropdown,
  Button,
  Badge,
  Select,
  Typography,
  FloatButton,
  theme,
} from 'antd';
import type { MenuProps } from 'antd';
import {
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  UserOutlined,
  BellOutlined,
  SettingOutlined,
  LogoutOutlined,
  DownOutlined,
  FileTextOutlined,
} from '@ant-design/icons';

const { Header, Sider, Content, Footer } = Layout;
const { Text } = Typography;

export interface RouteItem {
  path: string;
  name: string;
  icon?: React.ReactNode;
  children?: RouteItem[];
}

export interface CustomLayoutProps {
  logo?: React.ReactNode | string;
  title?: string;
  menuItems?: MenuProps['items'];
  layout?: 'side' | 'top' | 'mix';
  navTheme?: 'light' | 'dark';
  fixedHeader?: boolean;
  fixSiderbar?: boolean;
  defaultCollapsed?: boolean;
  siderWidth?: number;
  collapsedWidth?: number;
  headerHeight?: number;
  selectedKeys?: string[];
  openKeys?: string[];
  onMenuClick?: MenuProps['onClick'];
  breadcrumbItems?: { key: string; title: React.ReactNode; onClick?: () => void }[];
  breadcrumbRender?: (items: any[]) => React.ReactNode;
  showBreadcrumb?: boolean;
  rightContentRender?: () => React.ReactNode;
  userInfo?: { name?: string; avatar?: string };
  userMenuItems?: MenuProps['items'];
  onUserMenuClick?: MenuProps['onClick'];
  footerRender?: (() => React.ReactNode) | false;
  children?: React.ReactNode;
  contentStyle?: React.CSSProperties;
  showNotification?: boolean;
  notificationCount?: number;
  onNotificationClick?: () => void;
  showOrgSwitch?: boolean;
  orgOptions?: { value: string; label: React.ReactNode }[];
  orgValue?: string;
  defaultOrgValue?: string;
  onOrgChange?: (value: string) => void;
  showPrdButton?: boolean;
}

const CustomLayout: React.FC<CustomLayoutProps> = ({
  logo,
  title = '系统名称',
  menuItems = [],
  layout = 'side',
  navTheme = 'light',
  fixedHeader = true,
  fixSiderbar = true,
  defaultCollapsed = false,
  siderWidth = 208,
  collapsedWidth = 64,
  headerHeight = 56,
  selectedKeys = [],
  openKeys,
  onMenuClick,
  rightContentRender,
  userInfo = { name: '用户' },
  userMenuItems,
  onUserMenuClick,
  footerRender,
  children,
  contentStyle,
  showNotification = true,
  notificationCount = 0,
  onNotificationClick,
  showOrgSwitch = false,
  orgOptions,
  orgValue,
  defaultOrgValue = 'default',
  onOrgChange,
  breadcrumbItems,
  breadcrumbRender,
  showBreadcrumb = true,
  showPrdButton = false,
}) => {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const [internalOpenKeys, setInternalOpenKeys] = useState<string[]>(openKeys || []);
  const [activeOrg, setActiveOrg] = useState(defaultOrgValue);
  const { token } = theme.useToken();

  const resolvedOrgOptions = orgOptions ?? [
    { value: 'default', label: '默认组织' },
  ];
  const resolvedOrgValue = orgValue ?? activeOrg;

  const handleOrgChange = (value: string) => {
    if (orgValue === undefined) setActiveOrg(value);
    onOrgChange?.(value);
  };

  const currentSiderWidth = collapsed ? collapsedWidth : siderWidth;

  const defaultUserMenuItems: MenuProps['items'] = [
    { key: 'settings', icon: <SettingOutlined />, label: '个人设置' },
    { type: 'divider' },
    { key: 'logout', icon: <LogoutOutlined />, label: '退出登录' },
  ];

  const currentOpenKeys = internalOpenKeys;

  const handleOpenChange = (keys: string[]) => {
    setInternalOpenKeys(keys);
  };

  useEffect(() => {
    if (openKeys !== undefined) setInternalOpenKeys(openKeys);
  }, [openKeys]);

  const topMenuItems = useMemo(() => {
    return (menuItems || []).map((item: any) => ({
      key: item.key,
      icon: item.icon,
      label: item.label,
    }));
  }, [menuItems]);

  const topSelectedKeys = useMemo(() => {
    const currentKey = selectedKeys[0];
    if (!currentKey) return [];
    for (const item of menuItems || []) {
      const menuItem = item as any;
      if (!menuItem?.key) continue;
      const normalizedKey = String(menuItem.key).replace(/\/$/, '');
      if (currentKey === menuItem.key || currentKey.startsWith(normalizedKey)) {
        return [menuItem.key];
      }
    }
    return [];
  }, [menuItems, selectedKeys]);

  const siderMenuItems = useMemo(() => {
    if (!selectedKeys[0]) return [];
    for (const item of menuItems || []) {
      const menuItem = item as any;
      if (menuItem.children && selectedKeys[0].startsWith(menuItem.key?.replace(/\/$/, '') || '')) {
        return menuItem.children;
      }
      if (menuItem.key === selectedKeys[0]) {
        return menuItem.children || [];
      }
    }
    return [];
  }, [menuItems, selectedKeys]);

  const renderLogo = (isCollapsed: boolean = false, isDark: boolean = false) => {
    const logoContent = typeof logo === 'string' ? (
      <img src={logo} alt="logo" style={{ width: 32, height: 32, objectFit: 'contain' }} />
    ) : (
      logo || (
        <div style={{
          width: 32,
          height: 32,
          background: token.colorPrimary,
          borderRadius: 8,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          color: '#fff',
          fontWeight: 'bold',
          fontSize: 16,
        }}>
          L
        </div>
      )
    );

    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: isCollapsed ? 'center' : 'flex-start',
        padding: isCollapsed ? 0 : '0 16px',
        height: headerHeight,
        overflow: 'hidden',
        cursor: 'pointer',
      }}>
        {logoContent}
        {!isCollapsed && (
          <Text strong ellipsis style={{
            marginLeft: 12,
            fontSize: 16,
            whiteSpace: 'nowrap',
            color: isDark ? 'rgba(255, 255, 255, 0.85)' : undefined,
          }}>
            {title}
          </Text>
        )}
      </div>
    );
  };

  const renderRightContent = (isDark: boolean = false) => {
    if (rightContentRender) return rightContentRender();
    const avatarSrc = userInfo.avatar?.trim();

    return (
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, height: headerHeight }}>
        {showOrgSwitch && (
          <Select
            value={resolvedOrgValue}
            onChange={handleOrgChange}
            options={resolvedOrgOptions}
            size="middle"
            style={{ width: 160 }}
          />
        )}
        {showNotification && (
          <Badge count={notificationCount} size="small" offset={[-4, 4]}>
            <Button
              type="text"
              icon={<BellOutlined style={{ fontSize: 18 }} />}
              onClick={onNotificationClick}
              style={{ width: 32, height: 32, color: isDark ? 'rgba(255, 255, 255, 0.85)' : undefined }}
            />
          </Badge>
        )}
        <Dropdown
          menu={{ items: userMenuItems || defaultUserMenuItems, onClick: onUserMenuClick }}
          placement="bottomRight"
        >
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '0 12px', cursor: 'pointer' }}>
            <Avatar size="small" src={avatarSrc || undefined} icon={!avatarSrc && <UserOutlined />} />
            <Text style={isDark ? { color: 'rgba(255, 255, 255, 0.85)' } : undefined}>{userInfo.name}</Text>
            <DownOutlined style={{ fontSize: 12, color: isDark ? 'rgba(255, 255, 255, 0.65)' : undefined }} />
          </span>
        </Dropdown>
      </div>
    );
  };

  const renderFooter = () => {
    if (footerRender === false) return null;
    if (footerRender) {
      return <Footer style={{ textAlign: 'center', padding: '24px 50px', background: 'transparent' }}>{footerRender()}</Footer>;
    }
    return (
      <Footer style={{ textAlign: 'center', padding: '24px 50px', background: 'transparent' }}>
        <Text type="secondary">© {new Date().getFullYear()} {title}</Text>
      </Footer>
    );
  };

  const renderCollapseButton = (isDark: boolean = false) => (
    <Button
      type="text"
      icon={collapsed ? <MenuUnfoldOutlined /> : <MenuFoldOutlined />}
      onClick={() => setCollapsed(!collapsed)}
      style={isDark ? { color: 'rgba(255, 255, 255, 0.85)' } : undefined}
    />
  );

  const renderBreadcrumb = () => {
    if (!showBreadcrumb) return null;
    if (breadcrumbRender) return breadcrumbRender(breadcrumbItems || []);
    if (!breadcrumbItems || breadcrumbItems.length === 0) return null;
    return <Breadcrumb items={breadcrumbItems} />;
  };

  const breadcrumbNode = renderBreadcrumb();

  // 侧边栏布局
  const renderSideLayout = () => (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        collapsible collapsed={collapsed} onCollapse={setCollapsed}
        width={siderWidth} collapsedWidth={collapsedWidth}
        theme={navTheme} trigger={null}
        style={{
          overflow: 'auto',
          height: fixSiderbar ? '100vh' : 'auto',
          position: fixSiderbar ? 'fixed' : 'relative',
          left: 0, top: 0, bottom: 0, zIndex: 100,
        }}
      >
        {renderLogo(collapsed, navTheme === 'dark')}
        <Menu
          mode="inline" theme={navTheme}
          selectedKeys={selectedKeys}
          openKeys={currentOpenKeys}
          onOpenChange={handleOpenChange}
          items={menuItems}
          onClick={onMenuClick}
          style={{ borderInlineEnd: 'none' }}
        />
      </Sider>
      <Layout style={{
        marginLeft: fixSiderbar ? currentSiderWidth : 0,
        paddingTop: fixedHeader ? headerHeight : 0,
      }}>
        <Header style={{
          padding: '0 24px',
          background: token.colorBgContainer,
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          height: headerHeight,
          boxShadow: '0 1px 4px rgba(0, 21, 41, 0.08)',
          position: fixedHeader ? 'fixed' : 'static',
          top: 0,
          left: fixSiderbar ? currentSiderWidth : undefined,
          right: 0,
          zIndex: 99,
          width: fixSiderbar ? `calc(100% - ${currentSiderWidth}px)` : undefined,
        }}>
          <div style={{ display: 'flex', alignItems: 'center' }}>{renderCollapseButton()}</div>
          {renderRightContent()}
        </Header>
        <Content style={{
          margin: 24, padding: 0,
          background: token.colorBgLayout,
          borderRadius: token.borderRadiusLG,
          minHeight: 280,
          minWidth: 0,
          ...contentStyle,
        }}>
          {breadcrumbNode && <div style={{ paddingBottom: token.padding }}>{breadcrumbNode}</div>}
          {children}
        </Content>
        {renderFooter()}
      </Layout>
      {showPrdButton && (
        <FloatButton
          icon={<FileTextOutlined />}
          type="primary"
          tooltip={{ title: '查看 PRD 文档', placement: 'left' }}
          onClick={() => window.open('/prd', '_blank')}
          style={{ right: 24, bottom: 24 }}
        />
      )}
    </Layout>
  );

  // 顶部布局
  const renderTopLayout = () => (
    <Layout style={{ minHeight: '100vh', paddingTop: fixedHeader ? headerHeight : 0 }}>
      <Header style={{
        padding: '0 24px',
        background: navTheme === 'dark' ? '#001529' : token.colorBgContainer,
        display: 'flex',
        alignItems: 'center',
        height: headerHeight,
        boxShadow: '0 1px 4px rgba(0, 21, 41, 0.08)',
        position: fixedHeader ? 'fixed' : 'static',
        top: 0, left: 0, right: 0, zIndex: 99,
      }}>
        {renderLogo(false, navTheme === 'dark')}
        <Menu
          mode="horizontal" theme={navTheme}
          selectedKeys={selectedKeys}
          items={menuItems}
          onClick={onMenuClick}
          style={{ flex: 1, minWidth: 0, borderBottom: 'none' }}
        />
        {renderRightContent(navTheme === 'dark')}
      </Header>
      <Content style={{
        margin: 24, padding: 0,
        background: token.colorBgLayout,
        borderRadius: token.borderRadiusLG,
        minHeight: 280,
        minWidth: 0,
        ...contentStyle,
      }}>
        {breadcrumbNode && <div style={{ paddingBottom: token.padding }}>{breadcrumbNode}</div>}
        {children}
      </Content>
      {renderFooter()}
      {showPrdButton && (
        <FloatButton
          icon={<FileTextOutlined />}
          type="primary"
          tooltip={{ title: '查看 PRD 文档', placement: 'left' }}
          onClick={() => window.open('/prd', '_blank')}
          style={{ right: 24, bottom: 24 }}
        />
      )}
    </Layout>
  );

  // 混合布局
  const renderMixLayout = () => {
    const hasSiderMenu = siderMenuItems.length > 0;
    const isDark = navTheme === 'dark';

    return (
      <Layout style={{ minHeight: '100vh' }}>
        <Header style={{
          padding: '0 24px',
          background: isDark ? '#001529' : token.colorBgContainer,
          display: 'flex',
          alignItems: 'center',
          height: headerHeight,
          position: fixedHeader ? 'fixed' : 'static',
          top: 0, left: 0, right: 0, zIndex: 101,
        }}>
          {renderLogo(false, isDark)}
          <Menu
            mode="horizontal" theme={navTheme}
            selectedKeys={topSelectedKeys}
            items={topMenuItems}
            onClick={onMenuClick}
            style={{ flex: 1, minWidth: 0, borderBottom: 'none', background: 'transparent' }}
          />
          {renderRightContent(isDark)}
        </Header>
        <Layout style={{ marginTop: fixedHeader ? headerHeight : 0 }}>
          {hasSiderMenu && (
            <Sider
              collapsible collapsed={collapsed} onCollapse={setCollapsed}
              width={siderWidth} collapsedWidth={collapsedWidth}
              theme="light" trigger={null}
              style={{
                overflow: 'auto',
                height: fixSiderbar ? `calc(100vh - ${headerHeight}px)` : 'auto',
                position: fixSiderbar ? 'fixed' : 'relative',
                left: 0, top: headerHeight, bottom: 0, zIndex: 100,
                borderRight: '1px solid rgba(0, 0, 0, 0.06)',
              }}
            >
              <Menu
                mode="inline"
                selectedKeys={selectedKeys}
                openKeys={currentOpenKeys}
                onOpenChange={handleOpenChange}
                items={siderMenuItems}
                onClick={onMenuClick}
                style={{ borderInlineEnd: 'none' }}
              />
            </Sider>
          )}
          <Layout style={{ marginLeft: hasSiderMenu && fixSiderbar ? currentSiderWidth : 0 }}>
                        <Content style={{
                            padding: 0,
                            background: token.colorBgLayout,
                            borderRadius: token.borderRadiusLG,
                            minHeight: 280,
                            minWidth: 0,
                            ...contentStyle,
                          }}>              {breadcrumbNode && <div style={{ paddingBottom: token.padding }}>{breadcrumbNode}</div>}
              {children}
            </Content>
            {renderFooter()}
          </Layout>
        </Layout>
        {showPrdButton && (
          <FloatButton
            icon={<FileTextOutlined />}
            type="primary"
            tooltip={{ title: '查看 PRD 文档', placement: 'left' }}
            onClick={() => window.open('/prd', '_blank')}
            style={{ right: 24, bottom: 24 }}
          />
        )}
      </Layout>
    );
  };

  switch (layout) {
    case 'top': return renderTopLayout();
    case 'mix': return renderMixLayout();
    default: return renderSideLayout();
  }
};

export default CustomLayout;