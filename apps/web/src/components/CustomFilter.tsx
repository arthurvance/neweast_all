import React, { useEffect, useMemo, useRef, useState } from 'react';
import { Form, Button, Space, theme } from 'antd';
import type { FormInstance, FormProps } from 'antd';
import { DownOutlined, UpOutlined } from '@ant-design/icons';

export interface CustomFilterProps extends Pick<FormProps, 'initialValues' | 'onFinish' | 'onFinishFailed' | 'onValuesChange'> {
  mode?: 'query' | 'light';
  form?: FormInstance;
  layout?: FormProps['layout'];
  labelAlign?: FormProps['labelAlign'];
  labelCol?: FormProps['labelCol'];
  gutter?: number | [number, number];
  collapsible?: boolean;
  defaultCollapsed?: boolean;
  collapsed?: boolean;
  onCollapseChange?: (collapsed: boolean) => void;
  collapseCount?: number;
  showReset?: boolean;
  showSubmit?: boolean;
  submitText?: string;
  resetText?: string;
  expandText?: string;
  collapseText?: string;
  onReset?: () => void;
  extra?: React.ReactNode;
  children?: React.ReactNode;
  style?: React.CSSProperties;
  formStyle?: React.CSSProperties;
  actionsStyle?: React.CSSProperties;
}

const MIN_COLUMN_WIDTH = 360;

const CustomFilter: React.FC<CustomFilterProps> = ({
  mode = 'query',
  form,
  layout,
  labelAlign = 'right',
  labelCol = { flex: '0 0 80px' },
  gutter,
  collapsible = true,
  defaultCollapsed = true,
  collapsed,
  onCollapseChange,
  collapseCount,
  showReset = true,
  showSubmit = true,
  submitText = '查询',
  resetText = '重置',
  expandText = '展开',
  collapseText = '收起',
  onReset,
  extra,
  children,
  style,
  formStyle,
  actionsStyle,
  initialValues,
  onFinish,
  onFinishFailed,
  onValuesChange,
}) => {
  const { token } = theme.useToken();
  const [internalForm] = Form.useForm();
  const [internalCollapsed, setInternalCollapsed] = useState(defaultCollapsed);
  const [columnCount, setColumnCount] = useState(1);
  const gridRef = useRef<HTMLDivElement | null>(null);

  const mergedForm = form || internalForm;
  const isCollapsed = collapsed !== undefined ? collapsed : internalCollapsed;

  const items = useMemo(() => React.Children.toArray(children).filter(Boolean), [children]);
  const resolvedGutter: [number, number] = Array.isArray(gutter) ? gutter : [gutter ?? token.marginLG, 16];

  const normalizedItems = useMemo(() => {
    return items.map((item) => {
      if (!React.isValidElement<{ style?: React.CSSProperties }>(item)) return item;
      const itemStyle = (item.props as { style?: React.CSSProperties }).style;
      return React.cloneElement(item, { style: { width: '100%', marginBottom: 0, ...itemStyle } });
    });
  }, [items]);

  const baseActionArea = showReset || showSubmit || Boolean(extra);
  const columnsPerRow = Math.max(1, columnCount);
  const fallbackCollapseCount = Math.max(1, columnsPerRow - (baseActionArea ? 1 : 0));
  const collapseBasis = collapseCount ?? fallbackCollapseCount;
  const needsCollapse = collapsible && items.length > collapseBasis;
  const hasActionArea = baseActionArea || needsCollapse;
  const defaultCollapseCount = Math.max(1, columnsPerRow - (hasActionArea ? 1 : 0));
  const resolvedCollapseCount = mode === 'query' ? Math.max(1, collapseCount ?? defaultCollapseCount) : Math.max(1, collapseCount ?? 3);
  const visibleItems = isCollapsed ? normalizedItems.slice(0, resolvedCollapseCount) : normalizedItems;
  const showCollapseButton = collapsible && items.length > resolvedCollapseCount;

  const handleCollapse = () => {
    const nextCollapsed = !isCollapsed;
    if (collapsed === undefined) setInternalCollapsed(nextCollapsed);
    onCollapseChange?.(nextCollapsed);
  };

  const handleReset = () => {
    mergedForm.resetFields();
    onReset?.();
  };

  useEffect(() => {
    const element = gridRef.current;
    if (!element) return undefined;

    const updateColumnCount = (width: number) => {
      const nextCount = Math.max(1, Math.floor(width / MIN_COLUMN_WIDTH));
      setColumnCount((prev) => (prev === nextCount ? prev : nextCount));
    };

    const resizeObserver = new ResizeObserver((entries) => {
      const entry = entries[0];
      if (!entry) return;
      updateColumnCount(entry.contentRect.width);
    });

    resizeObserver.observe(element);
    updateColumnCount(element.getBoundingClientRect().width);

    return () => resizeObserver.disconnect();
  }, []);

  const actions = (showReset || showSubmit || showCollapseButton || extra) ? (
    <Space size={token.margin} align="center" style={actionsStyle}>
      <Space size={token.marginXS} align="center">
        {extra}
        {showReset && <Button onClick={handleReset}>{resetText}</Button>}
        {showSubmit && <Button type="primary" htmlType="submit">{submitText}</Button>}
      </Space>
      {showCollapseButton && (
        <Button type="link" onClick={handleCollapse} style={{ paddingInline: 0 }}>
          <span style={{ display: 'inline-flex', alignItems: 'center', gap: token.marginXS }}>
            {isCollapsed ? expandText : collapseText}
            {isCollapsed ? <DownOutlined /> : <UpOutlined />}
          </span>
        </Button>
      )}
    </Space>
  ) : null;

  const containerStyle: React.CSSProperties = {
    background: mode === 'query' ? token.colorBgContainer : undefined,
    borderRadius: mode === 'query' ? token.borderRadiusLG : undefined,
    padding: 0,
    marginBottom: 0,
    ...style,
  };

  if (mode === 'light') {
    return (
      <div style={containerStyle}>
        <Form form={mergedForm} layout={layout || 'inline'} labelAlign={labelAlign} labelCol={labelCol} onFinish={onFinish} onFinishFailed={onFinishFailed} onValuesChange={onValuesChange} initialValues={initialValues} style={formStyle}>
          <Space size={[token.marginLG, 16]} wrap style={{ width: '100%' }}>
            {visibleItems}
            {actions && <div style={{ marginLeft: 'auto' }}>{actions}</div>}
          </Space>
        </Form>
      </div>
    );
  }

  const actionPlacement = (() => {
    if (!actions) return { align: 'end', columnStart: columnsPerRow };
    if (columnsPerRow <= 1) return { align: 'start', columnStart: 1 };
    const remainder = visibleItems.length % columnsPerRow;
    const placeAtStart = remainder === 0;
    return { align: placeAtStart ? 'start' : 'end', columnStart: placeAtStart ? 1 : columnsPerRow };
  })();

  const actionStyle: React.CSSProperties = {
    display: 'flex',
    alignItems: 'center',
    justifyContent: actionPlacement.align === 'start' ? 'flex-start' : 'flex-end',
    justifySelf: actionPlacement.align === 'start' ? 'start' : 'end',
    whiteSpace: 'nowrap',
    gridColumn: `${actionPlacement.columnStart} / ${actionPlacement.columnStart + 1}`,
  };

  const gridStyle: React.CSSProperties = {
    display: 'grid',
    gridTemplateColumns: `repeat(${columnsPerRow}, minmax(0, 1fr))`,
    columnGap: resolvedGutter[0],
    rowGap: resolvedGutter[1],
    alignItems: 'center',
  };

  return (
    <div style={containerStyle}>
      <Form form={mergedForm} layout={layout || 'horizontal'} labelAlign={labelAlign} labelCol={labelCol} onFinish={onFinish} onFinishFailed={onFinishFailed} onValuesChange={onValuesChange} initialValues={initialValues} style={formStyle}>
        <div ref={gridRef} style={gridStyle}>
          {visibleItems.map((item, index) => <div key={index}>{item}</div>)}
          {actions && <div style={actionStyle}>{actions}</div>}
        </div>
      </Form>
    </div>
  );
};

export default CustomFilter;
