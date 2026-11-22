import { useState, type FormEvent } from "react";
import { addRunComponent } from "./environment-admin-api";

export default function ComponentAddForm({ id, runId, onCancel, onSaved }: {
  id: string;
  runId: string;
  onCancel: () => void;
  onSaved: () => void;
}) {
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const canSave = Boolean(name.trim() && version.trim());

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (busy || !canSave) return;
    setBusy(true);
    setError("");
    try {
      await addRunComponent(runId, { name: name.trim(), version: version.trim() });
      onSaved();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "구성요소를 추가하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }

  return <form id={id} className="component-add-form" aria-label="구성요소 추가"
    onSubmit={submit} onKeyDown={event => {
      if (event.key === "Escape" && !busy) {
        event.stopPropagation();
        onCancel();
      }
    }}>
    <label>이름<input value={name} maxLength={512} required disabled={busy} autoFocus
      onChange={event => setName(event.target.value)} /></label>
    <label>버전<input value={version} maxLength={255} required disabled={busy}
      onChange={event => setVersion(event.target.value)} /></label>
    <div className="component-edit-actions">
      <button type="submit" className="primary compact" disabled={busy || !canSave}>{busy ? "저장 중…" : "저장"}</button>
      <button type="button" className="secondary compact" disabled={busy} onClick={onCancel}>취소</button>
    </div>
    <p className="muted">취약점 분석에는 업로드한 원본 SBOM이 사용됩니다.</p>
    {error && <p role="alert" className="form-message">{error}</p>}
  </form>;
}
