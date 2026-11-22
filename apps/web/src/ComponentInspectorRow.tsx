import { useId, useState, type FormEvent, type KeyboardEvent } from "react";
import { AssetEvidence } from "./AssetEvidence";
import { correctRunComponent } from "./environment-admin-api";
import { ScrollingText } from "./ScrollingText";
import { IdentityAISuggestions } from "./SharedAI";
import type { ComponentSnapshot } from "./types";

type SavedCorrection = Awaited<ReturnType<typeof correctRunComponent>>;

export default function ComponentInspectorRow({
  runId, component, identifier, canEdit, editing, showCpeCandidates, onOpenLibrary, onEdit, onSaved,
}: {
  runId: string;
  component: ComponentSnapshot;
  identifier: string;
  canEdit: boolean;
  editing: boolean;
  showCpeCandidates: boolean;
  onOpenLibrary?: (query: string) => void;
  onEdit: (id: string) => void;
  onSaved: (id: string, saved: SavedCorrection) => void;
}) {
  const formId = useId();
  const [name, setName] = useState("");
  const [version, setVersion] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [showCandidates, setShowCandidates] = useState(false);
  const [confirmingRemoval, setConfirmingRemoval] = useState(false);
  const { id } = component;
  const originalName = component.originalName ?? component.name;
  const originalVersion = component.originalVersion ?? component.version ?? "";
  const corrected = component.name !== originalName || (component.version || "") !== originalVersion;

  function startEditing() {
    if (!id) return;
    setName(component.name);
    setVersion(component.version || "");
    setError("");
    setConfirmingRemoval(false);
    onEdit(id);
  }

  const expectedRevision = component.correctionRevision ?? 0;

  async function save(change: Parameters<typeof correctRunComponent>[2]) {
    if (!id || busy) return;
    setError("");
    setBusy(true);
    try {
      onSaved(id, await correctRunComponent(runId, id, change));
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "구성요소 변경을 저장하지 못했습니다.");
    } finally {
      setBusy(false);
    }
  }

  function remove() {
    if (confirmingRemoval) {
      void save({ removed: true, expectedRevision });
    } else {
      setConfirmingRemoval(true);
    }
  }

  function cancel() {
    if (confirmingRemoval) {
      setConfirmingRemoval(false);
    } else {
      onEdit("");
    }
  }

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (name.trim()) void save({ name: name.trim(), version: version.trim(), expectedRevision });
  }

  function cancelOnEscape(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "Escape" && !busy) {
      event.stopPropagation();
      cancel();
    }
  }

  return <tr>
    <td>
      <div className="component-name-cell">
        {editing ? <form id={formId} aria-label="구성요소 이름·버전 수정" onSubmit={submit}>
          <input aria-label="구성요소 이름" title={`원본 이름: ${originalName}`} value={name}
            required maxLength={512} disabled={busy} onChange={event => setName(event.target.value)} onKeyDown={cancelOnEscape} autoFocus />
        </form> : <div className="component-name-value">
          {onOpenLibrary && !component.manual && !component.removed ? <button type="button" className="environment-row-button" onClick={() => onOpenLibrary(originalName)}>
            <ScrollingText focusable={false}>{component.name}</ScrollingText>
          </button> : <ScrollingText>{component.name}</ScrollingText>}
          {component.manual && <small className="component-correction-label">수동 추가</small>}
          {corrected && <small className="component-correction-label" title={`원본: ${originalName} ${originalVersion}`}>표시 수정됨</small>}
          <AssetEvidence component={component} />
        </div>}
        {canEdit && id && (component.removed
          ? <button type="button" className="secondary compact component-correction-button" disabled={busy}
            aria-label={`${component.name} 복원`} onClick={() => void save({ removed: false, expectedRevision })}>복원</button>
          : editing
          ? <button type="submit" className="primary compact component-correction-button" form={formId} disabled={busy || !name.trim()}>저장</button>
          : <button type="button" className="secondary compact component-correction-button"
            aria-label={`${component.name} 이름·버전 수정`} onClick={event => { event.preventDefault(); startEditing(); }}>수정</button>)}
      </div>
      {editing && <>
        <div className="component-edit-secondary">
          {corrected && <button type="button" className="secondary compact" disabled={busy}
            onClick={() => void save({ name: null, version: null, expectedRevision })}>원본으로 되돌리기</button>}
          <span className="component-edit-actions">
            <button type="button" className="secondary compact" disabled={busy} onClick={cancel}>취소</button>
            <button type="button" className="danger compact" disabled={busy} onClick={remove}>
              {confirmingRemoval ? "삭제 확인" : "삭제"}
            </button>
          </span>
        </div>
        {confirmingRemoval && <p role="status" className="form-message">
          이 구성요소를 검사기에서 삭제할까요? 삭제된 항목에서 복원할 수 있습니다.
        </p>}
        <AssetEvidence component={component} />
      </>}
      {(editing || component.removed) && error && <p role="alert" className="form-message">{error}</p>}
    </td>
    <td>{editing ? <input className="component-version-input" form={formId} aria-label="구성요소 버전"
      title={`원본 버전: ${originalVersion || "미제공"}`} value={version} maxLength={255} disabled={busy}
      onChange={event => setVersion(event.target.value)} onKeyDown={cancelOnEscape} />
      : <ScrollingText>{component.version || "-"}</ScrollingText>}</td>
    <td className="mono"><ScrollingText>{identifier}</ScrollingText></td>
    <td>{component.licenses?.length ? component.licenses.map((license, index) => {
      const value = license as { license?: { id?: string; name?: string } };
      return <ScrollingText key={index}>{typeof license === "string" ? license : String(value.license?.id || value.license?.name || "식별 불가")}</ScrollingText>;
    }) : "-"}</td>
    <td className="component-cpe-cell">
      {showCpeCandidates && !component.manual && !component.removed ? <>
        <button type="button" className="secondary cpe-candidate-button"
          aria-label={`${component.name} CPE 식별 후보 ${showCandidates ? "접기" : "조회"}`}
          aria-expanded={showCandidates} onClick={() => setShowCandidates(value => !value)}>
          {showCandidates ? "후보 접기" : "후보 조회"}
        </button>
        {showCandidates && <IdentityAISuggestions runId={runId} identityKey={component.identityKey} />}
      </> : "—"}
    </td>
  </tr>;
}
