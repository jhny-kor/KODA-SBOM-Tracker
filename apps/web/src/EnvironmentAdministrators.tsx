import { ResizableTable } from "./ResizableTable";
import { useEffect, useState } from "react";
import { previewMode } from "./api";
import { ScrollingText } from "./ScrollingText";
import { fetchEnvironmentAdministrators, saveEnvironmentAdministrators, type EnvironmentAssignments } from "./environment-admin-api";
import "./environment-administration.css";

export default function EnvironmentAdministrators() {
  const [data, setData] = useState<EnvironmentAssignments | null>(null);
  const [selected, setSelected] = useState("");
  const [drafts, setDrafts] = useState<Record<string, string[]>>({});
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    let active = true;
    void fetchEnvironmentAdministrators().then(value => {
      if (!active) return;
      setData(value); setSelected(value.environments[0]?.id || "");
      setDrafts(Object.fromEntries(value.environments.map(env => [env.id, env.administrators.map(user => user.id)])));
    }).catch(cause => { if (active) setError(cause instanceof Error ? cause.message : "환경별 관리자를 불러오지 못했습니다."); });
    return () => { active = false; };
  }, [attempt]);
  const environment = data?.environments.find(item => item.id === selected);
  const current = drafts[selected] || [];
  const original = environment?.administrators.map(user => user.id) || [];
  const changed = current.length !== original.length || current.some(id => !original.includes(id));
  async function save() {
    if (!environment || busy || !changed) return;
    setBusy(true); setError(""); setMessage("");
    try {
      await saveEnvironmentAdministrators(environment.id, current);
      const candidates = [...(data?.users || []), ...environment.administrators];
      setData(previous => previous && ({ ...previous, environments: previous.environments.map(env => env.id === environment.id ? { ...env, administrators: current.map(id => candidates.find(user => user.id === id)).filter((user): user is NonNullable<typeof user> => Boolean(user)) } : env) }));
      setMessage(`${environment.name} 환경의 관리자 지정을 저장했습니다.`);
      try {
        const refreshed = await fetchEnvironmentAdministrators();
        setData(refreshed);
        const saved = refreshed.environments.find(env => env.id === environment.id);
        if (saved) setDrafts(previous => ({ ...previous, [environment.id]: saved.administrators.map(user => user.id) }));
      } catch { setError("저장은 완료했지만 최신 관리자 목록을 다시 불러오지 못했습니다. 화면을 새로고침해 확인하세요."); }
    } catch (cause) { setError(cause instanceof Error ? cause.message : "관리자 지정을 저장하지 못했습니다."); }
    finally { setBusy(false); }
  }
  return <section className="environment-admin-panel" aria-label="환경별 관리자 설정">
    <div className="page-heading"><div><h2>환경별 관리자</h2><p className="muted">전체 관리자는 모든 환경의 SBOM을 조회합니다. 다른 사용자는 SBOM 조회 권한이 있고 환경별 관리자로 지정된 환경의 SBOM만 조회할 수 있습니다.</p></div></div>
    {previewMode && <p className="preview-note" role="note">가상 사용자 샘플입니다. 실제 권한을 변경하거나 저장하지 않습니다.</p>}
    {error && <p role="alert" className="form-message">{error} {!data && <button className="secondary" onClick={() => { setError(""); setAttempt(value => value + 1); }}>다시 시도</button>}</p>}
    {message && <p role="status" className="form-message">{message}</p>}
    {!data && !error && <p role="status">환경과 사용자 정보를 불러오는 중…</p>}
    {data && <div className="environment-admin-grid">
      <div className="table-frame"><ResizableTable><thead><tr><th>환경</th><th>지정 관리자</th></tr></thead><tbody>{data.environments.map(env => <tr key={env.id} className={selected === env.id ? "selected" : ""}><td><button className="environment-row-button" aria-pressed={selected === env.id} disabled={busy} onClick={() => { setSelected(env.id); setMessage(""); setError(""); }}><ScrollingText focusable={false}>{`${env.name}${env.active === false ? " (비활성)" : ""}`}</ScrollingText></button></td><td><ScrollingText>{env.administrators.map(user => `${user.username}${user.active && user.status === "active" ? "" : " (권한 비활성)"}`).join(", ") || "미지정"}</ScrollingText></td></tr>)}</tbody></ResizableTable>{!data.environments.length && <p className="empty-state">등록된 환경이 없습니다. 서비스·환경에서 환경을 먼저 등록하세요.</p>}</div>
      {environment && <form className="environment-admin-editor" onSubmit={event => { event.preventDefault(); void save(); }}>
        <h3><ScrollingText>{`${environment.name} 환경 관리자 지정`}</ScrollingText></h3>
        <p className="muted">승인된 활성 사용자 중 여러 명을 지정할 수 있습니다. 지정된 사용자는 이 환경의 SBOM을 조회하고 등록 정보를 수정할 수 있습니다.</p>
        <fieldset disabled={busy || environment.active === false}><legend>관리자로 지정할 사용자</legend>
          {data.users.map(user => <label key={user.id} className="environment-user-choice"><input type="checkbox" checked={current.includes(user.id)} onChange={event => { const checked = event.target.checked; setDrafts(previous => ({ ...previous, [selected]: checked ? [...(previous[selected] || []), user.id] : (previous[selected] || []).filter(id => id !== user.id) })); setMessage(""); }} /><span><strong><ScrollingText focusable={false}>{user.username}</ScrollingText></strong><small>{({ admin: "전체 관리자", manager: "매니저", analyst: "분석자", uploader: "업로더", viewer: "조회자" } as Record<string, string>)[user.role] || user.role}</small></span></label>)}
          {!data.users.length && <p>지정 가능한 승인 사용자가 없습니다.</p>}
        </fieldset>
        {environment.administrators.filter(user => !data.users.some(candidate => candidate.id === user.id) && current.includes(user.id)).map(user => <p key={user.id} className="muted">{user.username} · 비활성 또는 미승인 <button type="button" className="secondary" disabled={busy} onClick={() => setDrafts(previous => ({ ...previous, [selected]: (previous[selected] || []).filter(id => id !== user.id) }))}>지정 해제</button></p>)}
        {environment.active === false && current.length > 0 && <button type="button" className="secondary" disabled={busy} onClick={() => setDrafts(previous => ({ ...previous, [selected]: [] }))}>비활성 환경의 모든 지정 해제</button>}
        <p className="muted">환경 이동에는 출발·도착 환경 모두의 관리 권한이 필요합니다. 관리자 지정 변경은 감사 로그에 기록됩니다.</p>
        <button className="primary" disabled={previewMode || busy || !changed || (environment.active === false && current.length > 0)}>{previewMode ? "샘플 모드 · 저장 안 함" : busy ? "저장 중…" : "환경 관리자 저장"}</button>
      </form>}
    </div>}
  </section>;
}
