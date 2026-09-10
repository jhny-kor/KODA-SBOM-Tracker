import type { SVGProps } from "react";

const paths: Record<string, React.ReactNode> = {
  menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
  dashboard: <><rect x="4" y="4" width="6" height="6" /><rect x="14" y="4" width="6" height="6" /><rect x="4" y="14" width="6" height="6" /><rect x="14" y="14" width="6" height="6" /></>,
  service: <><path d="m12 3 8 4.5v9L12 21l-8-4.5v-9L12 3Z" /><path d="m4.5 7.5 7.5 4.3 7.5-4.3M12 21v-9.2" /></>,
  runs: <><ellipse cx="12" cy="5" rx="8" ry="3" /><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6" /></>,
  compare: <><circle cx="5" cy="6" r="3" /><path d="M12 6h5a2 2 0 0 1 2 2v7" /><path d="m15 9-3-3 3-3" /><circle cx="19" cy="18" r="3" /><path d="M12 18H7a2 2 0 0 1-2-2V9" /><path d="m9 15 3 3-3 3" /></>,
  swap: <><path d="M4 7h16M4 7l3-3M4 7l3 3M20 17H4M20 17l-3-3M20 17l-3 3" /></>,
  vulnerability: <><rect x="8" y="7" width="8" height="13" rx="4" /><path d="M9 4l2 3m4-3-2 3M4 9l4 2m8 0 4-2M3 14h5m8 0h5M4 20l4-3m8 0 4 3M12 11v6" /></>,
  lock: <><rect x="5" y="10" width="14" height="11" rx="2" /><path d="M8 10V7a4 4 0 0 1 8 0v3M12 14v3" /></>,
  koda: <><image href="/KODA.ico" x="0" y="0" width="24" height="24" preserveAspectRatio="xMidYMid meet" /></>,
  audit: <><path d="M6 3h9l3 3v15H6z" /><path d="M15 3v4h4M9 11h6M9 15h4" /></>,
  guide: <><circle cx="12" cy="12" r="9" /><path d="M9.5 9a2.7 2.7 0 1 1 4.6 2c-1.4 1-2.1 1.6-2.1 3M12 17h.01" /></>,
  settings: <><path d="M21.952 11.020 L21.952 12.980 L19.656 14.322 L19.055 15.771 L19.730 18.344 L18.344 19.730 L15.771 19.055 L14.322 19.656 L12.980 21.952 L11.020 21.952 L9.678 19.656 L8.229 19.055 L5.656 19.730 L4.270 18.344 L4.945 15.771 L4.344 14.322 L2.048 12.980 L2.048 11.020 L4.344 9.678 L4.945 8.229 L4.270 5.656 L5.656 4.270 L8.229 4.945 L9.678 4.344 L11.020 2.048 L12.980 2.048 L14.322 4.344 L15.771 4.945 L18.344 4.270 L19.730 5.656 L19.055 8.229 L19.656 9.678Z" /><circle cx="12" cy="12" r="3" /></>,
  search: <><circle cx="11" cy="11" r="6" /><path d="m16 16 4 4" /></>,
  upload: <><path d="M12 16V4m0 0L7 9m5-5 5 5M5 15v5h14v-5" /></>,
  user: <><circle cx="12" cy="8" r="4" /><path d="M4 21c.8-4 3.5-6 8-6s7.2 2 8 6" /></>,
  chevron: <><path d="m8 10 4 4 4-4" /></>,
  reset: <><path d="M3 11a9 9 0 1 1 2.7 7.3M3 4v7h7" /></>,
  close: <><path d="m5 5 14 14M19 5 5 19" /></>,
  integration: <><path d="M8 3v5m8-5v5M6 8h12v3a6 6 0 0 1-12 0V8ZM12 17v4" /></>,
  external: <><path d="M14 4h6v6M20 4l-9 9" /><path d="M18 13v7H4V6h7" /></>,
};

export function Icon({ name, ...props }: SVGProps<SVGSVGElement> & { name: string }) {
  return (
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" {...props}>
      {paths[name]}
    </svg>
  );
}
