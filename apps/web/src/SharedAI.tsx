import { useEffect, useState, type FormEvent } from "react";
import { request } from "./api";

type AISettings = { endpointConfigured: boolean; baseUrl: string | null; model: string | null; hasKey: boolean };

export function SharedAISettingsPanel() {
  const [settings, setSettings] = useState<AISettings | null>(null);
  const [baseUrl, setBaseUrl] = useState("");
  const [model, setModel] = useState("");
  const [apiKey, setApiKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void request<AISettings>("/api/v1/ai/settings", { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) {
        setSettings(value);
        setBaseUrl(value.baseUrl ?? "");
        setModel(value.model ?? "");
      }
    }).catch(cause => { if (!controller.signal.aborted) setError(cause.message); });
    return () => controller.abort();
  }, []);

  async function save(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setStatus(""); setError("");
    try {
      const value = await request<AISettings>("/api/v1/ai/settings", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ baseUrl: baseUrl.trim(), model, ...(apiKey ? { apiKey } : {}), clearKey }),
      });
      setSettings(value); setBaseUrl(value.baseUrl ?? ""); setClearKey(false);
      setStatus("KODA와 Tracker의 공통 AI 설정을 저장했습니다.");
    } catch (cause) { setError((cause as Error).message); }
    finally { setApiKey(""); setBusy(false); }
  }

  async function test() {
    setBusy(true); setStatus(""); setError("");
    try {
      await request("/api/v1/ai/test", { method: "POST" });
      setStatus("저장된 설정으로 사내 모델의 응답을 확인했습니다.");
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  const addressChanged = baseUrl.trim().replace(/\/+$/, "") !== (settings?.baseUrl ?? "");
  return <section className="card" aria-label="공통 AI 연결">
    <h2>공통 AI 연결</h2>
    <p>관리자가 등록한 사내 모델을 KODA와 Tracker의 점검 요약에 사용합니다.</p>
    {error && <p className="form-message" role="alert">{error}</p>}
    {status && <p className="form-message" role="status">{status}</p>}
    {settings && <form className="run-metadata-form" onSubmit={event => void save(event)}>
      <label className="shared-ai-server-field">사내 AI 서버 주소
        <input type="url" required value={baseUrl} maxLength={512} disabled={busy}
          placeholder="https://ai-gateway.internal/v1" onChange={event => { setBaseUrl(event.target.value); setClearKey(false); setApiKey(""); }} />
      </label>
      <p className="muted">사내 AI 서버의 /v1 주소를 입력하세요.</p>
      <div className="run-metadata-fields">
        <label>모델 ID<input required value={model} maxLength={128} disabled={busy} onChange={event => setModel(event.target.value)} /></label>
        <label>AI API 키<input type="password" autoComplete="new-password" value={apiKey} maxLength={4096} disabled={busy || clearKey} placeholder={settings.hasKey && !addressChanged ? "등록됨 · 교체할 때만 입력" : "서버가 키를 요구할 때 입력"} onChange={event => setApiKey(event.target.value)} /></label>
      </div>
      {settings.hasKey && addressChanged && <p className="muted">새 서버에서 키가 필요하면 API 키를 입력하세요.</p>}
      {settings.hasKey && !addressChanged && <label className="check-label"><input type="checkbox" checked={clearKey} disabled={busy} onChange={event => { setClearKey(event.target.checked); setApiKey(""); }} />저장된 키 삭제</label>}
      <div className="button-row">
        <button className="primary" disabled={!baseUrl.trim() || busy}>설정 저장</button>
        <button className="secondary" type="button" disabled={!settings.model || addressChanged || busy} onClick={() => void test()}>저장된 설정으로 연결 시험</button>
      </div>
    </form>}
  </section>;
}

export function TrackerAISummary({ runId }: { runId: string }) {
  const [summary, setSummary] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function generate() {
    setBusy(true); setError(""); setSummary("");
    try {
      const result = await request<{ summary: string }>(`/api/v1/ai/runs/${encodeURIComponent(runId)}/summary`, { method: "POST" });
      setSummary(result.summary);
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }
  return <section className="run-metadata-section" aria-label="공통 AI 분석 요약">
    <button className="secondary" type="button" disabled={busy} onClick={() => void generate()}>{busy ? "요약 생성 중…" : "사내 AI로 요약"}</button>
    <p className="muted">심각도별 건수와 최대 25개 CVE ID를 사내 모델에 보냅니다. 응답은 검토 참고용입니다.</p>
    {error && <p className="form-message" role="alert">{error}</p>}
    {summary && <p role="status" style={{ whiteSpace: "pre-wrap", overflowWrap: "anywhere" }}>{summary}</p>}
  </section>;
}

function useAIRequest<T>(path: string, body?: unknown) {
  const [result, setResult] = useState<T | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  async function run() {
    setBusy(true); setError(""); setResult(null);
    try {
      setResult(await request<T>(path, body === undefined ? { method: "POST" } : {
        method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body),
      }));
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }
  return { result, error, busy, run };
}

const preWrap = { whiteSpace: "pre-wrap", overflowWrap: "anywhere" } as const;

type Briefing = { briefing: { newRisks: string; resolvedRisks: string; approvalChecks: string[] }; truncated: string[] };

export function ComparisonAIBriefing(props: { baseRunId: string; targetRunId: string; baseAnalysisId?: string; targetAnalysisId?: string }) {
  const { result, error, busy, run } = useAIRequest<Briefing>("/api/v1/comparisons/ai-briefing", {
    baseRunId: props.baseRunId, targetRunId: props.targetRunId,
    ...(props.baseAnalysisId ? { baseAnalysisId: props.baseAnalysisId } : {}),
    ...(props.targetAnalysisId ? { targetAnalysisId: props.targetAnalysisId } : {}),
  });
  return <section className="run-metadata-section comparison-ai-briefing" aria-label="사내 AI 릴리스 브리핑">
    <button className="secondary" type="button" disabled={busy} onClick={() => void run()}>{busy ? "브리핑 생성 중…" : "사내 AI 릴리스 브리핑"}</button>
    <p className="muted">비교 결과의 건수와 변경 목록(영역별 최대 30건)을 사내 모델에 보냅니다. 해시·회차 ID·원본은 보내지 않으며 응답은 검토 참고용입니다.</p>
    {error && <p className="form-message" role="alert">{error}</p>}
    {result && <div role="status">
      <h4>새로 생긴 위험</h4><p style={preWrap}>{result.briefing.newRisks}</p>
      <h4>해소된 위험</h4><p style={preWrap}>{result.briefing.resolvedRisks}</p>
      {!!result.briefing.approvalChecks.length && <><h4>승인 전 확인</h4><ul className="paths">{result.briefing.approvalChecks.map((item, index) => <li key={index} style={preWrap}>{item}</li>)}</ul></>}
      {!!result.truncated.length && <p className="muted">일부 목록만 전달했습니다. 전체 변경은 아래 탭에서 확인하세요.</p>}
    </div>}
  </section>;
}

type Explanation = { explanation: { summary: string; candidates: { version: string; note: string }[]; checklist: string[] } };

export function UpgradeAIExplanation({ runId, batchId }: { runId: string; batchId: string }) {
  const { result, error, busy, run } = useAIRequest<Explanation>(
    `/api/v1/upgrade-batches/${encodeURIComponent(runId)}/${encodeURIComponent(batchId)}/ai-explanation`);
  return <section className="run-metadata-section" aria-label="사내 AI 후보 해설">
    <button className="secondary" type="button" disabled={busy} onClick={() => void run()}>{busy ? "해설 생성 중…" : "사내 AI로 해설"}</button>
    <p className="muted">버전 선택은 위 검토 엔진 결과가 기준입니다. AI는 근거를 설명하고 확인 항목을 정리하며, 서버 별칭은 보내지 않습니다.</p>
    {error && <p className="form-message" role="alert">{error}</p>}
    {result && <div role="status">
      <p style={preWrap}>{result.explanation.summary}</p>
      {!!result.explanation.candidates.length && <ul className="paths">{result.explanation.candidates.map(item => <li key={item.version} style={preWrap}><strong>{item.version}</strong> · {item.note}</li>)}</ul>}
      {!!result.explanation.checklist.length && <><h4>적용 전 확인</h4><ul className="paths">{result.explanation.checklist.map((item, index) => <li key={index} style={preWrap}>{item}</li>)}</ul></>}
    </div>}
  </section>;
}

type IdentityCandidate = { id: string; vendor: string; product: string; match: "exact" | "partial"; cveCount: number; cpe: string; confidence: "high" | "medium" | "low" | null; reason: string | null };
type IdentityResult = { candidates: IdentityCandidate[]; dataAsOf: string | null; reason?: string };
const confidenceLabel = { high: "높음", medium: "보통", low: "낮음" };

export function IdentityAISuggestions({ runId, identityKey }: { runId: string; identityKey: string }) {
  const { result, error, busy, run } = useAIRequest<IdentityResult>(
    `/api/v1/ai/runs/${encodeURIComponent(runId)}/identity-suggestions`, { identityKey });
  useEffect(() => { void run(); }, []); // eslint-disable-line react-hooks/exhaustive-deps -- one lookup per opened row
  return <div className="cpe-candidate-results" role="region" aria-label="CPE 식별 후보 결과">
    {busy && <p role="status">활성 NVD 자료에서 후보를 찾는 중…</p>}
    {error && <p className="form-message" role="alert">{error}</p>}
    {result && !result.candidates.length && <p className="muted">{result.reason || "식별 후보가 없습니다."}</p>}
    {result && result.candidates.length > 0 && <>
      <ul aria-label="후보 목록">
        {result.candidates.map(item => <li key={item.id}>
          <code>{item.cpe}</code>
          <small>{item.match === "exact" ? "이름 정확 일치" : "이름 부분 일치"} · 관련 CVE {item.cveCount}건{item.confidence ? ` · AI 신뢰도 ${confidenceLabel[item.confidence]}` : " · AI 순위 없음"}</small>
          {item.reason && <p>{item.reason}</p>}
        </li>)}
      </ul>
      <p className="muted">NVD 기준일 {result.dataAsOf || "미상"} · 검토용 후보</p>
      <p className="muted">확인한 CPE를 원본 SBOM에 넣고 다시 업로드하면 분석에 반영됩니다.</p>
    </>}
  </div>;
}
