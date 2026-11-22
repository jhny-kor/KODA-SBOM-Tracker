import type { KeyboardEvent } from "react";
import { Icon } from "./icons";
import "./tab-list.css";

type TabOption<T extends string> = {
  id: T;
  label: string;
  icon?: string;
};

export function TabList<T extends string>({ label, idPrefix, items, value, onChange, level = "section" }: {
  label: string;
  idPrefix: string;
  items: readonly TabOption<T>[];
  value: T;
  onChange: (value: T) => void;
  level?: "page" | "section";
}) {
  if (items.length === 0) return null;
  const selected = items.find(item => item.id === value) ?? items[0];

  function move(event: KeyboardEvent<HTMLButtonElement>, index: number) {
    let nextIndex: number;
    switch (event.key) {
      case "ArrowLeft":
        nextIndex = (index + items.length - 1) % items.length;
        break;
      case "ArrowRight":
        nextIndex = (index + 1) % items.length;
        break;
      case "Home":
        nextIndex = 0;
        break;
      case "End":
        nextIndex = items.length - 1;
        break;
      default:
        return;
    }

    event.preventDefault();
    const next = items[nextIndex];
    event.currentTarget.parentElement?.querySelectorAll<HTMLButtonElement>("button[role=tab]")[nextIndex]?.focus();
    if (next.id !== value) onChange(next.id);
  }

  return <div className={`tab-list tab-list--${level}`} role="tablist" aria-label={label}>
    {items.map((item, index) => {
      const active = item.id === selected.id;
      return <button key={item.id} type="button" role="tab" id={`${idPrefix}-tab-${item.id}`}
        aria-selected={active} aria-controls={active ? `${idPrefix}-panel-${item.id}` : undefined}
        tabIndex={active ? 0 : -1} onClick={() => onChange(item.id)} onKeyDown={event => move(event, index)}>
        {item.icon && <Icon name={item.icon} />}
        <span>{item.label}</span>
      </button>;
    })}
  </div>;
}
