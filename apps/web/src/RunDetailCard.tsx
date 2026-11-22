import { useId, useState, type ReactNode } from "react";
import { Icon } from "./icons";

export function RunDetailCard({ title, label, className = "", initiallyExpanded = true, actions, children }: {
  title: ReactNode;
  label?: string;
  className?: string;
  initiallyExpanded?: boolean;
  actions?: ReactNode;
  children: ReactNode;
}) {
  const id = useId();
  const [state, setState] = useState<"expanded" | "collapsed" | "unopened">(initiallyExpanded ? "expanded" : "unopened");
  const expanded = state === "expanded";

  return <section className={`run-detail-card ${className}`} aria-label={label} aria-labelledby={label ? undefined : `${id}-title`}>
    <div className="run-detail-card-header">
      <h3 id={`${id}-title`}>
        <button type="button" aria-expanded={expanded} aria-controls={`${id}-body`} onClick={() => setState(value => value === "expanded" ? "collapsed" : "expanded")}>
          <Icon name="chevron" aria-hidden="true" />
          {title}
        </button>
      </h3>
      {actions && <div className="run-detail-card-actions" hidden={!expanded}>{actions}</div>}
    </div>
    <div className="run-detail-card-body" id={`${id}-body`} hidden={!expanded}>{state !== "unopened" && children}</div>
  </section>;
}
