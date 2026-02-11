import React, { useMemo } from 'react';
import { Button, Dropdown, Modal, Popconfirm, Space, Typography, theme } from 'antd';

const { Title } = Typography;

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

export type CustomPanelProps = {
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

const CustomPanel: React.FC<CustomPanelProps> = ({
    title, toolBarItems, extra, marginBottom, children, style, bodyStyle, className,
}) => {
    const { token } = theme.useToken();
    const hasHeader = Boolean(title || (toolBarItems && toolBarItems.length) || extra);
    const resolvedMarginBottom = marginBottom ?? 0;

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

    return (
        <div style={{ marginBottom: resolvedMarginBottom, ...style }} className={className}>
            {hasHeader && (
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingBlock: token.padding, paddingInline: 0 }}>
                    <div>{title && <Title level={5} style={{ margin: 0 }}>{title}</Title>}</div>
                    {(visibleItems.length > 0 || moreItems.length > 0 || extra) && (
                        <Space size={token.marginXS} align="center">
                            {visibleItems.map((item) => <React.Fragment key={item.key}>{renderActionButton(item)}</React.Fragment>)}
                            {moreItems.length > 0 && (
                                <Dropdown menu={{ items: moreItems.map((item) => ({ key: item.key, label: item.label, danger: item.danger, disabled: item.disabled })), onClick: ({ key }) => handleMoreClick(String(key)) }}>
                                    <Button>更多</Button>
                                </Dropdown>
                            )}
                            {extra}
                        </Space>
                    )}
                </div>
            )}
            <div style={{ paddingInline: 0, paddingBlock: 0, ...bodyStyle }}>{children}</div>
        </div>
    );
};

export default CustomPanel;