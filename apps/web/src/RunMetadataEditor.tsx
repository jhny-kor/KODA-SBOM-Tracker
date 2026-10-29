import { useEffect, useState } from "react";
import { previewMode } from "./api";
import { fetchRunEditPermission, updateRunMetadata, type RunEditPermission, type RunMetadata } from "./environment-admin-api";
import { FlowSelect } from "./ScrollingSelect";
import "./environment-administration.css";

export default function RunMetadataEditor({ runId, onSaved }: { runId: string; onSaved: () => Promise<void> | void }) {
  const [permission, setPermission] = useState<RunEditPermission | null>(null);
  const [draft, setDraft] = useState<RunMetadata | null>(null);
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    let active = true;
    void fetchRunEditPermission(runId).then(value => { if (active) { setPermission(value); setDraft(value.metadata); } }).catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "수정 권한을 확인하지 못했습니다."); });
    return () => { active = false; };
  }, [runId]);
  async function save() {
    if (!draft || busy) return;
    setBusy(true); setMessage(""); setError("");
    try {
      const patch = Object.fromEntries(Object.entries(draft).filter(([key, value]) => value !== permission?.metadata[key as keyof RunMetadata]));
      const result = await updateRunMetadata(runId, patch);
      setMessage(result.reanalysisPending ? "등록 정보를 저장하고 새 정책 분석을 예약했습니다. 이전 분석은 이력으로 보존됩니다." : "SBOM 등록 정보를 저장했습니다.");
      setOpen(false);
      setPermission(previous => previous && ({ ...previous, metadata: draft, canChangeScope: result.reanalysisPending ? false : previous.canChangeScope }));
      const [refresh, saved] = await Promise.allSettled([fetchRunEditPermission(runId), Promise.resolve().then(onSaved)]);
      if (refresh.status === "fulfilled") { setPermission(refresh.value); setDraft(refresh.value.metadata); }
      if (refresh.status === "rejected" || saved.status === "rejected") setError("저장은 완료했지만 화면을 갱신하지 못했습니다. 새로고침하여 최신 등록 정보를 확인하세요.");
    } catch (cause) { setError(cause instanceof Error ? cause.message : "등록 정보를 수정하지 못했습니다."); }
    finally { setBusy(false); }
  }
  const changed = draft && permission && Object.keys(draft).some(key => draft[key as keyof RunMetadata] !== permission.metadata[key as keyof RunMetadata]);
  const inactiveService = permission && !permission.services.some(item => item.id === draft?.serviceId);
  const inactiveEnvironment = permission && !permission.environments.some(item => item.id === draft?.environmentId);
  return <section className="run-metadata-section" aria-label="SBOM 등록 정보 수정">
    {error && <p role="alert" className="form-message">{error}</p>}
    {message && <p role="status" className="form-message">{message}</p>}
    {permission?.canEdit && <button className="secondary" type="button" disabled={busy} aria-expanded={open} onClick={() => { setOpen(value => !value); setError(""); }}>SBOM 등록 정보 수정</button>}
    {permission?.canEdit && open && draft && <form className="run-metadata-form" onSubmit={event => { event.preventDefault(); void save(); }}>
      <p className="muted">서비스·환경·릴리스 변경 시 정책을 다시 분석합니다. 원본 SBOM과 업로드 시각은 보존됩니다.</p>
      {previewMode && <p className="preview-note" role="note">샘플 모드에서는 항목을 확인할 수 있으며 저장하지 않습니다.</p>}
      {permission.reason && <p className="muted">{permission.reason}</p>}
      <div className="run-metadata-fields">
        <label>서비스<FlowSelect aria-label="수정 서비스" value={draft.serviceId} disabled={busy || permission.canChangeScope === false} onChange={event => setDraft({ ...draft, serviceId: event.target.value })}>{inactiveService && <option value={draft.serviceId}>기존 서비스</option>}{permission.services.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</FlowSelect></label>
        <label>환경<FlowSelect aria-label="수정 환경" value={draft.environmentId} disabled={busy || permission.canChangeScope === false} onChange={event => setDraft({ ...draft, environmentId: event.target.value })}>{inactiveEnvironment && <option value={draft.environmentId}>기존 환경</option>}{permission.environments.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</FlowSelect></label>
        <label>릴리스<input aria-label="수정 릴리스" value={draft.releaseVersion} maxLength={255} required disabled={busy || permission.canChangeScope === false} onChange={event => setDraft({ ...draft, releaseVersion: event.target.value })} /></label>
        <label className="run-note-field">메모<textarea aria-label="수정 메모" value={draft.note} maxLength={4000} disabled={busy} rows={3} onChange={event => setDraft({ ...draft, note: event.target.value })} /></label>
      </div>
      <div className="button-row"><button className="primary" disabled={previewMode || busy || !changed || !draft.releaseVersion.trim()}>{previewMode ? "샘플 모드 · 저장 안 함" : busy ? "저장 중…" : "등록 정보 저장"}</button><button className="secondary" type="button" disabled={busy} onClick={() => { setOpen(false); setDraft(permission.metadata); }}>취소</button></div>
    </form>}
  </section>;
}
