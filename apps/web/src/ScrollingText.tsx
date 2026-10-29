import { useEffect, useRef, useState, type CSSProperties, type HTMLAttributes } from "react";
import "./scrolling-text.css";

/** Move only the text that exceeds its allocated space; keep the complete value in the DOM. */
export function ScrollingText({ children, className = "", focusable = true, title, ...props }: Omit<HTMLAttributes<HTMLSpanElement>, "children"> & {
  children: string | number; focusable?: boolean;
}) {
  const text = String(children);
  const viewport = useRef<HTMLSpanElement>(null);
  const content = useRef<HTMLSpanElement>(null);
  const [distance, setDistance] = useState(0);
  useEffect(() => {
    let active = true;
    const measure = () => {
      if (active) setDistance(Math.max(0, (content.current?.scrollWidth || 0) - (viewport.current?.clientWidth || 0)));
    };
    queueMicrotask(measure);
    const observer = typeof ResizeObserver === "undefined" ? null : new ResizeObserver(measure);
    if (viewport.current) observer?.observe(viewport.current);
    if (content.current) observer?.observe(content.current);
    if (!observer) window.addEventListener("resize", measure);
    void document.fonts?.ready.then(measure);
    return () => { active = false; observer?.disconnect(); window.removeEventListener("resize", measure); };
  }, [text]);
  const style = { "--text-travel": `${-distance}px`, "--text-duration": `${Math.max(8, distance / 18 + 4)}s`, ...props.style } as CSSProperties;
  return <span {...props} ref={viewport} className={`scrolling-text ${className}`} title={title ?? text}
    data-overflow={distance > 0} tabIndex={props.tabIndex ?? (distance > 0 && focusable ? 0 : undefined)} style={style}>
    <span key={text} className="scrolling-text-content" ref={content}>{text}</span>
  </span>;
}
