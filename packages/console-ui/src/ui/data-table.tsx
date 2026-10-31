"use client";

import * as React from "react";
import { MoreHorizontal } from "lucide-react";
import { cn } from "../lib/utils";
import { Button } from "./button";
import { Checkbox } from "./checkbox";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./dropdown-menu";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "./table";

export interface DataTableColumn<T> {
  id: string;
  header: string;
  cell: (row: T) => React.ReactNode;
  className?: string;
}

export interface DataTableAction<T> {
  label: string;
  onClick: (row: T) => void;
  variant?: "default" | "destructive";
  icon?: React.ReactNode;
  testId?: string;
}

export interface DataTablePagination {
  page: number;
  pageSize: number;
  total: number;
}

export interface DataTableProps<T> {
  columns: DataTableColumn<T>[];
  data: T[];
  rowKey: (row: T) => string;
  selectable?: boolean;
  selectedRows?: T[];
  onSelectionChange?: (selectedRows: T[]) => void;
  actions?: (row: T) => DataTableAction<T>[];
  pagination?: DataTablePagination;
  onPageChange?: (page: number) => void;
  emptyMessage?: string;
  className?: string;
}

export function DataTable<T>({
  columns,
  data,
  rowKey,
  selectable = false,
  selectedRows = [],
  onSelectionChange,
  actions,
  pagination,
  onPageChange,
  emptyMessage = "No data found.",
  className,
}: DataTableProps<T>) {
  const selectedKeys = new Set(selectedRows.map(rowKey));

  const isAllSelected = data.length > 0 && data.every((row) => selectedKeys.has(rowKey(row)));
  const isSomeSelected = data.some((row) => selectedKeys.has(rowKey(row))) && !isAllSelected;

  const handleSelectAll = (checked: boolean) => {
    if (!onSelectionChange) return;
    if (checked) {
      onSelectionChange(data);
    } else {
      onSelectionChange([]);
    }
  };

  const handleSelectRow = (row: T, checked: boolean) => {
    if (!onSelectionChange) return;
    if (checked) {
      onSelectionChange([...selectedRows, row]);
    } else {
      onSelectionChange(selectedRows.filter((r) => rowKey(r) !== rowKey(row)));
    }
  };

  const totalPages = pagination ? Math.ceil(pagination.total / pagination.pageSize) : 1;
  const canGoPrevious = pagination ? pagination.page > 1 : false;
  const canGoNext = pagination ? pagination.page < totalPages : false;

  return (
    <div className={cn("space-y-4", className)}>
      <div className="rounded-md border">
        <Table>
          <TableHeader>
            <TableRow className="bg-muted/30">
              {selectable && (
                <TableHead className="w-[50px]">
                  <Checkbox
                    checked={isAllSelected}
                    ref={(el) => {
                      if (el) {
                        (el as HTMLButtonElement).dataset.state = isSomeSelected ? "indeterminate" : isAllSelected ? "checked" : "unchecked";
                      }
                    }}
                    onCheckedChange={handleSelectAll}
                    aria-label="Select all"
                  />
                </TableHead>
              )}
              {columns.map((column, index) => (
                <TableHead
                  key={column.id}
                  className={cn(
                    "text-muted-foreground font-medium",
                    // Add left padding to first column when not selectable for visual balance
                    index === 0 && !selectable && "pl-4",
                    column.className
                  )}
                >
                  {column.header}
                </TableHead>
              ))}
              {actions && <TableHead className="w-[50px]" />}
            </TableRow>
          </TableHeader>
          <TableBody>
            {data.length === 0 ? (
              <TableRow>
                <TableCell
                  colSpan={columns.length + (selectable ? 1 : 0) + (actions ? 1 : 0)}
                  className="h-24 text-center text-muted-foreground"
                >
                  {emptyMessage}
                </TableCell>
              </TableRow>
            ) : (
              data.map((row) => {
                const key = rowKey(row);
                const isSelected = selectedKeys.has(key);
                return (
                  <TableRow key={key} data-testid={`table-row-${key}`} data-state={isSelected ? "selected" : undefined}>
                    {selectable && (
                      <TableCell>
                        <Checkbox
                          checked={isSelected}
                          onCheckedChange={(checked) => handleSelectRow(row, checked as boolean)}
                          aria-label="Select row"
                        />
                      </TableCell>
                    )}
                    {columns.map((column, index) => (
                      <TableCell
                        key={column.id}
                        className={cn(
                          // Add left padding to first column when not selectable for visual balance
                          index === 0 && !selectable && "pl-4",
                          column.className
                        )}
                      >
                        {column.cell(row)}
                      </TableCell>
                    ))}
                    {actions && (
                      <TableCell>
                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="icon" className="h-8 w-8" data-testid={`table-row-actions-${key}`}>
                              <MoreHorizontal className="h-4 w-4" />
                              <span className="sr-only">Open menu</span>
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            {actions(row).map((action, index) => (
                              <DropdownMenuItem
                                key={index}
                                data-testid={action.testId}
                                onClick={() => action.onClick(row)}
                                variant={action.variant}
                                className="cursor-pointer"
                              >
                                {action.icon && <span className="mr-2">{action.icon}</span>}
                                {action.label}
                              </DropdownMenuItem>
                            ))}
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    )}
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </div>

      {/* Footer with selection count and pagination */}
      {(selectable || pagination) && (
        <div className="flex items-center justify-between text-sm text-muted-foreground">
          <div>
            {selectable && (
              <span>
                {selectedRows.length} of {pagination?.total ?? data.length} row(s) selected.
              </span>
            )}
          </div>
          {pagination && (
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPageChange?.(pagination.page - 1)}
                disabled={!canGoPrevious}
              >
                Previous
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onPageChange?.(pagination.page + 1)}
                disabled={!canGoNext}
              >
                Next
              </Button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
