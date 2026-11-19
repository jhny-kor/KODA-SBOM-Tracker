import { Children, Fragment, cloneElement, isValidElement, useRef, useState } from "react";
import type { ComponentPropsWithoutRef, PointerEvent, ReactNode } from "react";
import "./resizable-table.css";

type TableNodeProps = { children?: ReactNode; colSpan?: number; style?: React.CSSProperties };

function mapTag(children: ReactNode, tag: string, update: (props: TableNodeProps, index: number) => TableNodeProps) {
  return Children.map(children, (child, index) => (
    isValidElement<TableNodeProps>(child) && child.type === tag
      ? cloneElement(child, update(child.props, index))
      : child
  ));
}

function headerCells(children: ReactNode): ReactNode[] {
  return Children.toArray(children).flatMap(child =>
    isValidElement<TableNodeProps>(child) && child.type === Fragment
      ? headerCells(child.props.children)
      : [child]
  );
}

type ColumnDrag = { pointerId: number; index: number; x: number; widths: number[] };

export function ResizableTable({ children, className, style, ...props }: ComponentPropsWithoutRef<"table">) {
  const table = useRef<HTMLTableElement>(null);
  const drag = useRef<ColumnDrag | null>(null);
  const [ratios, setRatios] = useState<number[]>([]);

  function measure() {
    return Array.from(table.current?.tHead?.rows[0]?.cells ?? [], cell => cell.getBoundingClientRect().width);
  }

  function resize(widths: number[], index: number, delta: number) {
    const left = widths[index], right = widths[index + 1];
    const shift = Math.max(Math.min(48, left) - left, Math.min(right - Math.min(48, right), delta));
    const total = widths.reduce((sum, width) => sum + width, 0);
    if (!total) return;
    setRatios(widths.map((width, column) => (
      (width + (column === index ? shift : column === index + 1 ? -shift : 0)) / total * 100
    )));
  }

  function start(event: PointerEvent<HTMLButtonElement>, index: number) {
    if (event.button !== 0 || drag.current) return;
    event.stopPropagation();
    const widths = measure();
    drag.current = { pointerId: event.pointerId, index, x: event.clientX, widths };
    event.currentTarget.setPointerCapture(event.pointerId);
  }

  function move(event: PointerEvent<HTMLButtonElement>) {
    const current = drag.current;
    if (current?.pointerId === event.pointerId) {
      resize(current.widths, current.index, event.clientX - current.x);
    }
  }

  const content = mapTag(children, "thead", head => ({
    children: mapTag(head.children, "tr", row => {
      const cells = headerCells(row.children);
      if (cells.length < 2 || cells.some(cell => !isValidElement<TableNodeProps>(cell) || cell.type !== "th" || (cell.props.colSpan ?? 1) !== 1)) {
        return { children: row.children };
      }
      return {
        children: mapTag(cells, "th", (cell, index) => ({
          style: { ...cell.style, width: ratios.length === cells.length ? `${ratios[index]}%` : cell.style?.width },
          children: <>{cell.children}{index < cells.length - 1 && (
            <button type="button" className="column-resize-handle" aria-label={`열 ${index + 1}과 ${index + 2} 너비 조절`}
              onPointerDown={event => start(event, index)} onPointerMove={move}
              onLostPointerCapture={event => { if (drag.current?.pointerId === event.pointerId) drag.current = null; }}
              onClick={event => event.stopPropagation()}
              onKeyDown={event => {
                if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") return;
                event.preventDefault();
                event.stopPropagation();
                resize(measure(), index, event.key === "ArrowLeft" ? -12 : 12);
              }}
            ><span aria-hidden="true">|</span></button>
          )}</>,
        })),
      };
    }),
  }));

  return <table {...props} ref={table} className={`resizable-table${className ? ` ${className}` : ""}`}
    style={ratios.length ? { ...style, tableLayout: "fixed" } : style}>{content}</table>;
}
