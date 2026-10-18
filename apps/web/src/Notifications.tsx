import { useEffect, useState } from "react";
import { fetchNotificationDeliveries, fetchNotifications, fetchNotificationSettings, markNotificationRead, previewMode, retryNotificationDelivery } from "./api";
import { formatSeoulDateTime } from "./format";
import { WorkflowPagination } from "./ReanalysisSchedule";
import type { InboxNotification, NotificationDelivery } from "./types";

export function NotificationsPanel({ canManage }: { canManage: boolean }) {
  const [inbox, setInbox] = useState<{items:InboxNotification[];total:number;unreadCount:number}>({items:[],total:0,unreadCount:0});
  const [deliveries, setDeliveries] = useState<{items:NotificationDelivery[];total:number}>({items:[],total:0});
  const [settings, setSettings] = useState<{webhookEnabled:boolean;webhookConfigured:boolean;webhookHost?:string;secretConfigured:boolean} | null>(null);
  const [loadState, setLoadState] = useState<"loading" | "ready" | "error">(previewMode ? "ready" : "loading");
  const [deliveryLoad, setDeliveryLoad] = useState<"loading" | "ready" | "error">(previewMode ? "ready" : "loading");
  const [page, setPage] = useState(1); const [deliveryPage, setDeliveryPage] = useState(1);
  const [reload, setReload] = useState(0); const [busy, setBusy] = useState(false); const [message, setMessage] = useState("");
  useEffect(() => {
    if (previewMode) return;
    let active = true;
    setLoadState("loading");
    void fetchNotifications(page).then((value) => { if (active) { setInbox(value); setLoadState("ready"); } }).catch((error: unknown) => { if (active) { setMessage(error instanceof Error ? error.message : "알림 조회에 실패했습니다."); setLoadState("error"); } });
    return () => { active = false; };
  }, [page, reload]);
  useEffect(() => {
    if (previewMode || !canManage) return;
    let active = true;
    setDeliveryLoad("loading");
    void Promise.all([fetchNotificationDeliveries(deliveryPage), fetchNotificationSettings()]).then(([items, configuration]) => { if (active) { setDeliveries(items); setSettings(configuration); setDeliveryLoad("ready"); } }).catch((error: unknown) => { if (active) { setMessage(error instanceof Error ? error.message : "전송 이력 조회에 실패했습니다."); setDeliveryLoad("error"); } });
    return () => { active = false; };
  }, [canManage, deliveryPage, reload]);
  async function act(id: string, retry: boolean) {
    setBusy(true); setMessage("");
    try { if (retry) await retryNotificationDelivery(id); else await markNotificationRead(id); setReload((value) => value + 1); setMessage(retry ? "알림 전송 재시도를 접수했습니다." : "알림을 읽음으로 표시했습니다."); }
    catch (error) { setMessage(error instanceof Error ? error.message : "알림 작업에 실패했습니다."); } finally { setBusy(false); }
  }
  return <section className="settings-panel workflow-panel" role="tabpanel" id="settings-panel-notifications" aria-labelledby="settings-tab-notifications"><div className="settings-panel-heading"><div><h2>알림함 · 안 읽음 {loadState === "ready" ? `${inbox.unreadCount}건` : "확인 중"}</h2><p>분석·정책·검토 이벤트를 확인합니다. 읽음 상태는 사용자별로 저장합니다.</p></div><button className="secondary" disabled={previewMode || busy} onClick={() => setReload((value) => value + 1)}>알림 새로고침</button></div>{previewMode && <p className="preview-note">샘플 모드에서는 실제 알림을 조회하거나 변경하지 않습니다.</p>}{message && <p className="form-message" role="status">{message}</p>}<div className="table-scroll"><table><thead><tr><th>생성 (서울)</th><th>알림</th><th>내용</th><th>상태</th></tr></thead><tbody>{loadState === "ready" && inbox.items.map((item) => <tr key={item.id}><td>{formatSeoulDateTime(item.createdAt)}</td><td>{item.title || item.kind || item.eventType}</td><td>{item.message}</td><td>{item.read || item.readAt ? "읽음" : <button className="secondary compact" disabled={busy || previewMode} onClick={() => void act(item.id, false)}>읽음 표시</button>}</td></tr>)}{loadState !== "ready" ? <tr><td colSpan={4}>{loadState === "error" ? "알림 조회에 실패했습니다. 알림 새로고침으로 재시도하세요." : "알림을 불러오는 중입니다."}</td></tr> : !inbox.items.length && <tr><td colSpan={4}>알림이 없습니다.</td></tr>}</tbody></table></div><WorkflowPagination page={page} total={inbox.total} label="알림" onPage={setPage} />
    {canManage && <><h3>외부 알림 전송</h3>{settings && <p>웹훅: {settings.webhookEnabled ? "활성" : "비활성"} · 연결 설정: {settings.webhookConfigured ? settings.webhookHost || "설정됨" : "없음"} · 서명 비밀값: {settings.secretConfigured ? "설정됨" : "없음"}</p>}<p>외부 웹훅 연결과 비밀값은 서버 환경 변수에서 설정합니다.</p><div className="table-scroll"><table><thead><tr><th>생성 (서울)</th><th>전송 상태</th><th>시도</th><th>최근 오류</th><th>작업</th></tr></thead><tbody>{deliveryLoad === "ready" && deliveries.items.map((item) => <tr key={item.id}><td>{formatSeoulDateTime(item.createdAt)}</td><td>{item.status}</td><td>{item.attempts}</td><td>{item.lastError || item.error || "-"}</td><td>{item.status === "failed" && <button className="secondary compact" disabled={busy || previewMode} onClick={() => void act(item.id, true)}>전송 재시도</button>}</td></tr>)}{deliveryLoad !== "ready" ? <tr><td colSpan={5}>{deliveryLoad === "error" ? "전송 이력 조회에 실패했습니다." : "전송 이력을 불러오는 중입니다."}</td></tr> : !deliveries.items.length && <tr><td colSpan={5}>전송 이력이 없습니다.</td></tr>}</tbody></table></div><WorkflowPagination page={deliveryPage} total={deliveries.total} label="알림 전송" onPage={setDeliveryPage} /></>}
  </section>;
}
