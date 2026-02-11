import React, { useMemo } from 'react';
import { Button, Col, Form, Row, theme } from 'antd';
import type { ButtonProps, ColProps, FormItemProps, FormProps, RowProps } from 'antd';

export type CustomFormSubmitter = {
  align?: 'left' | 'center' | 'right';
  searchConfig?: { submitText?: string; resetText?: string };
  submitButtonProps?: ButtonProps;
  resetButtonProps?: ButtonProps;
  render?: (props: { submit: () => void; reset: () => void }, defaultButtons: React.ReactNode[]) => React.ReactNode | React.ReactNode[] | false | null;
};

export type CustomFormProps = Omit<FormProps, 'children'> & {
  title?: React.ReactNode;
  extra?: React.ReactNode;
  fieldLayout?: 'vertical' | 'horizontal';
  grid?: boolean;
  rowProps?: RowProps;
  colProps?: ColProps;
  gutter?: RowProps['gutter'];
  submitter?: false | CustomFormSubmitter;
  onReset?: () => void;
  marginBottom?: number;
  containerStyle?: React.CSSProperties;
  children?: React.ReactNode;
};

export type CustomFormItemProps = FormItemProps & { colProps?: ColProps };

const CustomFormItem: React.FC<CustomFormItemProps> = ({ colProps: _colProps, ...rest }) => {
  return <Form.Item {...rest} />;
};

const CustomForm: React.FC<CustomFormProps> & { Item: typeof CustomFormItem } = ({
  title, extra, fieldLayout, grid = false, rowProps, colProps, gutter, submitter, onReset, marginBottom = 0, containerStyle, children, form, ...formProps
}) => {
  const { token } = theme.useToken();
  const [internalForm] = Form.useForm();
  const mergedForm = form ?? internalForm;
  const submitterConfig: CustomFormSubmitter | null = submitter === false ? null : (submitter ?? {});
  const resolvedLayout = formProps.layout ?? fieldLayout;
  const resolvedLabelCol = resolvedLayout === 'vertical' ? formProps.labelCol : (formProps.labelCol ?? { flex: '0 0 80px' });
  const resolvedLabelAlign = resolvedLayout === 'vertical' ? formProps.labelAlign : (formProps.labelAlign ?? 'left');
  const header = title || extra;

  const handleReset = () => {
    mergedForm.resetFields();
    onReset?.();
  };

  const defaultButtons = useMemo<React.ReactNode[]>(() => {
    if (!submitterConfig) return [];
    const submitText = submitterConfig.searchConfig?.submitText ?? '提交';
    const resetText = submitterConfig.searchConfig?.resetText ?? '重置';
    return [
      <Button key="reset" onClick={handleReset} {...submitterConfig.resetButtonProps}>{resetText}</Button>,
      <Button key="submit" type="primary" htmlType="submit" {...submitterConfig.submitButtonProps}>{submitText}</Button>,
    ];
  }, [handleReset, submitterConfig]);

  const renderSubmitter = () => {
    if (!submitterConfig) return null;
    const content = submitterConfig.render ? submitterConfig.render({ submit: () => mergedForm.submit(), reset: handleReset }, defaultButtons) : defaultButtons;
    if (!content) return null;
    if (Array.isArray(content) && content.length === 0) return null;
    const align = submitterConfig.align ?? 'right';
    const justifyContent = align === 'left' ? 'flex-start' : align === 'center' ? 'center' : 'flex-end';
    return (
      <Form.Item style={{ marginBottom: 0, marginTop: token.marginLG }}>
        <div style={{ display: 'flex', justifyContent, gap: 8 }}>{content}</div>
      </Form.Item>
    );
  };

  const normalizedItems = useMemo(() => {
    const items = React.Children.toArray(children).filter(Boolean);
    if (!grid) return items;
    return items.map((child, index) => {
      if (!React.isValidElement<{ colProps?: ColProps; style?: React.CSSProperties }>(child)) return child;
      const childColProps = (child.props as { colProps?: ColProps }).colProps;
      const mergedColProps: ColProps = childColProps ?? colProps ?? { xs: 24, sm: 12, md: 8 };
      const childStyle = (child.props as { style?: React.CSSProperties }).style;
      const normalizedChild = React.cloneElement(child, { style: { width: '100%', marginBottom: 0, ...(childStyle ?? {}) } });
      return <Col key={index} {...mergedColProps}>{normalizedChild}</Col>;
    });
  }, [children, grid, colProps]);

  const mergedGutter: RowProps['gutter'] = gutter ?? [token.marginLG, token.marginLG];
  const mergedContainerStyle: React.CSSProperties = { paddingTop: 0, paddingBottom: 0, paddingInline: 0, border: 'none', marginBottom, ...containerStyle };

  return (
    <div style={mergedContainerStyle}>
      {header && (
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: token.marginLG }}>
          <div style={{ fontSize: token.fontSizeLG, fontWeight: 600 }}>{title}</div>
          {extra}
        </div>
      )}
      <Form {...formProps} form={mergedForm} layout={resolvedLayout} labelCol={resolvedLabelCol} labelAlign={resolvedLabelAlign}>
        {grid ? <Row gutter={mergedGutter} {...rowProps}>{normalizedItems}</Row> : normalizedItems}
        {renderSubmitter()}
      </Form>
    </div>
  );
};

CustomForm.Item = CustomFormItem;

export default CustomForm;
