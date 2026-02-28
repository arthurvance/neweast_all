import React, { useMemo } from 'react';
import { Button, Card, Dropdown, Modal, Popconfirm, Space, theme } from 'antd';

export type ToolBarItem = {
  key: string;
  label: React.ReactNode;
  onClick?: () => void;
  disabled?: boolean;
  danger?: boolean;
  icon?: React.ReactNode;
  type?: 'default' | 'primary' | 'link';
  placement?: 'visible' | 'more';
  confirm?: { title?: React.ReactNode; okText?: string; cancelText?: string };
};

export type CustomCardProps = {
  title?: React.ReactNode;
  toolBarItems?: ToolBarItem[];
  extra?: React.ReactNode;
  marginBottom?: number;
  children?: React.ReactNode;
  style?: React.CSSProperties;
  bodyStyle?: React.CSSProperties;
  className?: string;
};

const DEFAULT_CONFIRM_TEXT = '确认执行该操作吗？';

const CustomCard: React.FC<CustomCardProps> = ({
  title, toolBarItems, extra, marginBottom, children, style, bodyStyle, className,
}) => {
  const { token } = theme.useToken();
  const hasHeader = Boolean(title || (toolBarItems && toolBarItems.length) || extra);
  const resolvedMarginBottom = marginBottom ?? token.marginLG;

  const { visibleItems, moreItems } = useMemo(() => {
    const items = toolBarItems ?? [];
    return {
      visibleItems: items.filter((item) => item.placement !== 'more'),
      moreItems: items.filter((item) => item.placement === 'more'),
    };
  }, [toolBarItems]);

  const handleMoreClick = (key: string) => {
    const target = moreItems.find((item) => item.key === key);
    if (!target || !target.onClick || target.disabled) return;
    if (target.confirm) {
      Modal.confirm({
        title: target.confirm.title ?? DEFAULT_CONFIRM_TEXT,
        okText: target.confirm.okText ?? '确定',
        cancelText: target.confirm.cancelText ?? '取消',
        onOk: () => target.onClick?.(),
      });
      return;
    }
    target.onClick();
  };

  const renderActionButton = (item: ToolBarItem) => {
    const button = (
      <Button type={item.type ?? 'default'} danger={item.danger} disabled={item.disabled} icon={item.icon} onClick={item.confirm ? undefined : item.onClick}>
        {item.label}
      </Button>
    );
    if (!item.confirm) return button;
    return (
      <Popconfirm title={item.confirm.title ?? DEFAULT_CONFIRM_TEXT} okText={item.confirm.okText ?? '确定'} cancelText={item.confirm.cancelText ?? '取消'} onConfirm={item.onClick}>
        {button}
      </Popconfirm>
    );
  };

  const extraNode = (visibleItems.length > 0 || moreItems.length > 0 || extra) ? (
    <Space size={token.marginXS} align="center">
      {visibleItems.map((item) => <React.Fragment key={item.key}>{renderActionButton(item)}</React.Fragment>)}
      {moreItems.length > 0 && (
        <Dropdown menu={{ items: moreItems.map((item) => ({ key: item.key, label: item.label, danger: item.danger, disabled: item.disabled })), onClick: ({ key }) => handleMoreClick(String(key)) }}>
          <Button>更多</Button>
        </Dropdown>
      )}
      {extra}
    </Space>
  ) : null;

  return (
    <Card
      title={hasHeader ? title : null}
      extra={hasHeader ? extraNode : null}
      variant="borderless"
      style={{ marginBottom: resolvedMarginBottom, overflow: 'hidden', ...style }}
      styles={{
        header: { paddingInline: token.padding },
        body: { padding: token.padding, ...bodyStyle }
      }}
      className={className}
    >
      {children}
    </Card>
  );
};

export default CustomCard;
