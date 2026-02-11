import React, { useCallback, useEffect, useState } from 'react';
import type { ReactNode } from 'react';
import { Table, theme, type TableProps } from 'antd';
import type { ColumnType, ColumnsType } from 'antd/es/table';
import CustomPanel, { type ToolBarItem } from './CustomPanel';

export type CustomPanelTableRequestResult<T> = { data: T[]; total: number; success?: boolean };
export type CustomPanelTableColumn<T> = ColumnType<T>;

export type CustomPanelTableProps<T extends object> = {
  title?: ReactNode;
  extra?: ReactNode;
  columns: CustomPanelTableColumn<T>[];
  rowKey?: TableProps<T>['rowKey'];
  dataSource?: T[];
  loading?: boolean;
  request?: (params: Record<string, unknown>) => Promise<CustomPanelTableRequestResult<T>>;
  pagination?: TableProps<T>['pagination'];
  onChange?: TableProps<T>['onChange'];
  rowSelection?: TableProps<T>['rowSelection'];
  scroll?: TableProps<T>['scroll'];
  onRow?: TableProps<T>['onRow'];
  toolBarItems?: ToolBarItem[];
  bordered?: boolean;
  className?: string;
  marginBottom?: number;
  size?: TableProps<T>['size'];
};

const DEFAULT_PAGE_SIZE = 10;

export default function CustomPanelTable<T extends object>({
  title, extra, columns, rowKey, dataSource, loading: propsLoading, request, pagination, onChange, rowSelection, scroll, onRow, toolBarItems, bordered = true, className, marginBottom = 0, size,
}: CustomPanelTableProps<T>) {
  const { token } = theme.useToken();
  const [internalLoading, setInternalLoading] = useState(false);
  const [tableData, setTableData] = useState<T[]>([]);
  const [total, setTotal] = useState(0);
  const [pageParams, setPageParams] = useState({ current: 1, pageSize: DEFAULT_PAGE_SIZE });

  const fetchData = useCallback(async () => {
    if (!request) return;
    setInternalLoading(true);
    try {
      const response = await request({ current: pageParams.current, pageSize: pageParams.pageSize });
      setTableData(response.data);
      setTotal(response.total);
    } finally {
      setInternalLoading(false);
    }
  }, [pageParams.current, pageParams.pageSize, request]);

  useEffect(() => { void fetchData(); }, [fetchData]);

  const handleTableChange: TableProps<T>['onChange'] = (paginationInfo, filters, sorter, extraInfo) => {
    if (onChange) {
      onChange(paginationInfo, filters, sorter, extraInfo);
    }
    if (request && paginationInfo) {
      setPageParams({ current: paginationInfo.current ?? 1, pageSize: paginationInfo.pageSize ?? DEFAULT_PAGE_SIZE });
    }
  };

  const defaultPaginationStyle: React.CSSProperties = { paddingTop: token.padding, paddingBottom: 0, paddingInline: 0, marginBlock: 0, marginInline: 0 };
  const defaultPagination: TableProps<T>['pagination'] = {
    showSizeChanger: true,
    showQuickJumper: true,
    showTotal: (totalCount) => `共 ${totalCount} 条`,
    locale: {
      items_per_page: '条/页',
      jump_to: '跳至',
      jump_to_confirm: '确定',
      page: '页',
      prev_page: '上一页',
      next_page: '下一页',
      prev_5: '向前 5 页',
      next_5: '向后 5 页',
      prev_3: '向前 3 页',
      next_3: '向后 3 页',
    },
  };

  const tablePagination: TableProps<T>['pagination'] = request
    ? { ...defaultPagination, total, current: pageParams.current, pageSize: pageParams.pageSize, style: defaultPaginationStyle, ...pagination }
    : pagination === false ? false : { ...defaultPagination, ...(pagination || {}), style: { ...defaultPaginationStyle, ...(typeof pagination === 'object' ? pagination.style : {}) } };

  const data = request ? tableData : dataSource;
  const loading = request ? internalLoading : propsLoading;
  const tableClassName = className;
  const tableSize = size ?? 'middle';

  return (
    <CustomPanel title={title} toolBarItems={toolBarItems} extra={extra} marginBottom={marginBottom}>
      <Table<T> rowKey={rowKey ?? 'id'} columns={columns as ColumnsType<T>} dataSource={data} loading={loading} pagination={tablePagination} onChange={handleTableChange} rowSelection={rowSelection} scroll={scroll} onRow={onRow} bordered={bordered} size={tableSize} className={tableClassName} />
    </CustomPanel>
  );
}
