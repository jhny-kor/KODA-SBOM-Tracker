import { useEffect, useRef, useState, type ReactNode, type SelectHTMLAttributes } from "react";
import { Icon } from "./icons";
import { ScrollingText } from "./ScrollingText";

function selectedLabel(select: HTMLSelectElement | null) {
  const option = select?.options.item(select.selectedIndex);
  return option?.label || option?.textContent || "";
}

/** The real select owns keyboard interaction, validation, labels and submitted values. */
export function FlowSelect({ children, onChange, title, displayText, ...props }: SelectHTMLAttributes<HTMLSelectElement> & { displayText?: string }) {
  const select = useRef<HTMLSelectElement>(null);
  const [selectedText, setSelectedText] = useState("");
  useEffect(() => {
    let active = true;
    const sync = () => {
      if (active) setSelectedText(selectedLabel(select.current));
    };
    const reset = () => queueMicrotask(sync);
    reset();
    const observer = new MutationObserver(sync);
    if (select.current) observer.observe(select.current, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["label", "selected"] });
    const form = select.current?.form;
    form?.addEventListener("reset", reset);
    return () => { active = false; observer.disconnect(); form?.removeEventListener("reset", reset); };
  }, [children, props.value, props.defaultValue, props.form]);
  const text = displayText ?? selectedText;
  return <span className="flow-select" data-ready={Boolean(text)}>
    <select {...props} ref={select} title={title ?? text} onChange={event => {
      setSelectedText(selectedLabel(event.currentTarget));
      onChange?.(event);
      // React restores controlled values after the event, including rejected changes.
      queueMicrotask(() => { if (select.current) setSelectedText(selectedLabel(select.current)); });
    }}>{children}</select>
    <span className="flow-select-viewport" aria-hidden="true"><ScrollingText focusable={false}>{text}</ScrollingText></span>
    <Icon name="chevron" className="flow-select-chevron" />
  </span>;
}

/** Backwards-compatible adapter for the comparison pickers. */
export function ScrollingSelect({ value, text, label, onChange, children }: {
  value: string; text: string; label: string; onChange: (value: string) => void; children: ReactNode;
}) {
  return <FlowSelect value={value} displayText={text} aria-label={label} onChange={event => onChange(event.target.value)}>{children}</FlowSelect>;
}
