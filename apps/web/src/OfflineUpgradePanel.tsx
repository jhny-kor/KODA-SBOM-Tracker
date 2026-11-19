import { useEffect, useState, type FormEvent } from "react";
import { request } from "./api";
import { formatSeoulDateTime } from "./format";
import { EvidenceFacts, SourceFiles, SourceLink, type ReferenceItem } from "./OfficialCompatibilityEvidence";
import { UpgradeAIExplanation } from "./SharedAI";

const endpoint = "/api/v1/upgrade-batches";
const labels = { maven: "Java/Maven", python: "Python", elf: "Linux C/ELF" };
type Engine = keyof typeof labels;
type RunReference = { runId: string; sha256: string; releaseVersion: string; roundNumber: number };
type Deployment = { id: string; server: string; os: string; architecture: string; javaMajor: number };
type Context = { baseline: RunReference; service: string; environment: string; candidates: RunReference[]; candidatesTruncated: boolean; javaDeployments: Deployment[] };
type Check = { status: "passed" | "failed" | "not_reported"; reference?: string; artifactSha256?: string };
type OfficialReference = ReferenceItem & { bundleId: string; collectedAt: string };
type Candidate = { officialReferences?: OfficialReference[]; version: string; sbom: { runId: string } | null; conditionStatus: "conditions_met" | "conflict" | "unknown"; reasons: string[]; evidenceSource: string | null; build: Check; runtime: Check };
type BatchSummary = { id: string; createdAt: string; ecosystem: Engine; coordinate: string; highestConditionVersion: string | null; highestVerifiedVersion: string | null };
type Batch = BatchSummary & { platform: { server: string; os: string; architecture: string }; currentVersions: string[]; candidates: Candidate[]; orderingLimited: boolean };

export default function OfflineUpgradePanel({ runId, canManage }: { runId: string; canManage: boolean }) {
  const [open, setOpen] = useState(false);
  return <details className="run-metadata-section" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary>폐쇄망 후보 버전 일괄 검토</summary>
    {open && <UpgradeForm runId={runId} canManage={canManage} />}
  </details>;
}

function UpgradeForm({ runId, canManage }: { runId: string; canManage: boolean }) {
  const path = `${endpoint}/${encodeURIComponent(runId)}`;
  const [context, setContext] = useState<Context | null>(null);
  const [history, setHistory] = useState<{ items: BatchSummary[]; hasMore: boolean }>({ items: [], hasMore: false });
  const [historyPage, setHistoryPage] = useState(1);
  const [revision, setRevision] = useState(0);
  const [engine, setEngine] = useState<Engine>("maven");
  const [deploymentId, setDeploymentId] = useState("");
  const [result, setResult] = useState<Batch | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    void request<Context>(`${path}/context`, { signal: controller.signal }).then(value => {
      if (!controller.signal.aborted) {
        setContext(value);
        setDeploymentId(previous => value.javaDeployments.some(item => item.id === previous) ? previous : value.javaDeployments[0]?.id ?? "");
      }
    }).catch(cause => { if (!controller.signal.aborted) setError(cause.message); });
    return () => controller.abort();
  }, [path, revision]);

  useEffect(() => {
    const controller = new AbortController();
    void request<{ items: BatchSummary[]; hasMore: boolean }>(`${path}?page=${historyPage}`, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setHistory(value); })
      .catch(cause => { if (!controller.signal.aborted) setError(cause.message); });
    return () => controller.abort();
  }, [path, historyPage, revision]);

  const selected = context?.javaDeployments.find(item => item.id === deploymentId);
  function downloadTemplate() {
    if (!context || (engine === "maven" && !selected)) return;
    const platform = selected && engine === "maven"
      ? { server: selected.server, os: selected.os, architecture: selected.architecture, javaMajor: selected.javaMajor, source: "" }
      : { server: "", os: "", architecture: "", source: "", ...(engine === "python" ? {
        pythonVersion: "", pythonImplementation: "cpython", pythonSysPlatform: "linux",
      } : { nativePlatform: "linux" }) };
    const template = {
      schemaVersion: 1, ecosystem: engine, coordinate: "",
      baseline: { runId: context.baseline.runId, sha256: context.baseline.sha256 }, platform,
      ...(engine === "maven" ? { deploymentId } : {}),
      candidates: [{ version: "", sbom: null, evidence: null }],
    };
    const url = URL.createObjectURL(new Blob([JSON.stringify(template, null, 2) + "\n"], { type: "application/json" }));
    const link = document.createElement("a");
    link.href = url;
    link.download = `upgrade-review-${engine}.json`;
    link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  async function importFile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const file = new FormData(event.currentTarget).get("manifest");
    if (!(file instanceof File) || !file.size || file.size > 1024 * 1024) {
      setError("1 MiB 이하의 검토 JSON 파일을 선택하세요.");
      return;
    }
    setBusy(true); setError(""); setResult(null);
    try {
      const body = await file.text();
      const value = JSON.parse(body);
      if (value?.baseline?.runId !== runId) throw new Error("이 회차를 배포 기준으로 작성한 파일을 선택하세요.");
      setResult(await request<Batch>(`${endpoint}/import`, {
        method: "POST", headers: { "Content-Type": "application/json" }, body,
      }));
      setHistoryPage(1); setRevision(previous => previous + 1);
    } catch (cause) {
      setError(cause instanceof SyntaxError ? "JSON 파일의 형식이 올바르지 않습니다." : (cause as Error).message);
    } finally { setBusy(false); }
  }

  async function loadBatch(id: string) {
    setBusy(true); setError(""); setResult(null);
    try { setResult(await request<Batch>(`${path}/${encodeURIComponent(id)}`)); }
    catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  return <div className="run-metadata-form">
    <p className="muted">이 회차를 배포 기준으로 사용합니다. 같은 서비스·환경에 반입한 후보 SBOM과 검토 근거를 대조합니다.</p>
    {error && <p className="form-message" role="alert">{error}</p>}
    {context && <>
      <p><strong>{context.service} / {context.environment}</strong> · {context.baseline.releaseVersion} · {context.baseline.roundNumber}차</p>
      {canManage && <>
        <div className="run-metadata-fields">
          <label>검토 종류<select value={engine} onChange={event => setEngine(event.target.value as Engine)}>
            {Object.entries(labels).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
          </select></label>
          {engine === "maven" && <label>등록한 Java 배포 기준<select value={deploymentId} onChange={event => setDeploymentId(event.target.value)}>
            {!context.javaDeployments.length && <option value="">배포 기준 없음</option>}
            {context.javaDeployments.map(item => <option key={item.id} value={item.id}>{item.server} · Java {item.javaMajor}</option>)}
          </select></label>}
        </div>
        {engine === "maven" && !selected && <p className="muted">위의 Java/Maven 버전 영향 검토에서 현재 회차를 배포 기준으로 등록한 뒤 새로고침하세요.</p>}
        <div className="button-row">
          <button type="button" className="secondary" disabled={busy || (engine === "maven" && !selected)} onClick={downloadTemplate}>검토 JSON 양식 받기</button>
          <button type="button" className="secondary" disabled={busy} onClick={() => setRevision(value => value + 1)}>기준·후보 새로고침</button>
        </div>
        <details><summary>같은 서비스·환경 후보 회차 ID와 해시</summary>
          <div className="table-scroll" role="region" aria-label="후보 회차 가로 스크롤" tabIndex={0}>
            <table><thead><tr><th>릴리스</th><th>회차 ID</th><th>SBOM SHA-256</th></tr></thead>
              <tbody>{context.candidates.map(run => <tr key={run.runId}><td>{run.releaseVersion} · {run.roundNumber}차</td>
                <td><code>{run.runId}</code></td><td><code>{run.sha256}</code></td></tr>)}
                {!context.candidates.length && <tr><td colSpan={3}>같은 서비스·환경에 후보 SBOM을 먼저 반입하세요.</td></tr>}</tbody></table>
          </div>
          {context.candidatesTruncated && <p className="muted">최근 완료 회차 100개를 표시합니다.</p>}
        </details>
        <form onSubmit={event => void importFile(event)}>
          <label>일괄 검토 JSON<input name="manifest" type="file" accept=".json,application/json" required /></label>
          <p className="muted">후보 최대 40개. 해석 결과와 별도로 빌드·실행 기록을 함께 반입할 수 있습니다.</p>
          <button className="primary" disabled={busy}>{busy ? "처리 중…" : "반입하고 일괄 검토"}</button>
        </form>
      </>}
    </>}
    {result && <BatchResult runId={runId} result={result} />}
    {!!history.items.length && <section aria-label="일괄 검토 이력">
      <h3>검토 이력</h3>
      <ul className="paths">{history.items.map(item => <li key={item.id}>
        <button type="button" className="secondary compact" disabled={busy} onClick={() => void loadBatch(item.id)}>결과 보기</button>
        {" "}{formatSeoulDateTime(item.createdAt)} · {labels[item.ecosystem]} · {item.coordinate}
      </li>)}</ul>
      {(historyPage > 1 || history.hasMore) && <div className="button-row">
        <button type="button" className="secondary compact" disabled={historyPage === 1} onClick={() => setHistoryPage(page => page - 1)}>이전</button>
        <button type="button" className="secondary compact" disabled={!history.hasMore} onClick={() => setHistoryPage(page => page + 1)}>다음</button>
      </div>}
    </section>}
  </div>;
}

const conditionLabel = { conditions_met: "조건 충족", conflict: "충돌", unknown: "미확인" };
const verificationLabel = { passed: "통과", failed: "실패", not_reported: "기록 없음" };

function VerificationCell({ check }: { check: Check }) {
  return <td>{verificationLabel[check.status]}{check.reference && <><br /><span className="muted wrap">{check.reference}</span></>}</td>;
}

function OfficialReferenceCell({ candidate }: { candidate: Candidate }) {
  const references = candidate.officialReferences ?? [];
  return <td className="wrap upgrade-official-cell">
    {!references.length && <span className="muted">{candidate.sbom ? "일치 자료 없음" : "후보 SBOM 미지정"}</span>}
    {references.map(item => <div key={`${item.bundleId}/${item.files[0]?.path}`}>
      <strong>{item.authority.organization}</strong><br />
      <SourceLink url={item.authority.url} label={item.authority.name} />
      <div className="muted">{item.package} · {item.version}{item.architecture ? ` · ${item.architecture}` : ""}</div>
      <EvidenceFacts item={item} />
      <SourceFiles files={item.files} />
      <small className="muted">수집 {formatSeoulDateTime(item.collectedAt)}</small>
    </div>)}
  </td>;
}

function BatchResult({ runId, result }: { runId: string; result: Batch }) {
  const showReferences = result.candidates.some(candidate => candidate.officialReferences !== undefined);
  return <section aria-label="후보 버전 검토 결과">
    <h3>{labels[result.ecosystem]} 후보 버전 검토 결과</h3>
    <p className="wrap">{result.coordinate} · {result.platform.server} · {result.platform.os} / {result.platform.architecture}</p>
    <p>배포 기준 버전 <strong>{result.currentVersions.join(", ")}</strong></p>
    <ul className="paths">
      <li>반입 후보 중 조건 충족 최고 버전 <strong>{result.highestConditionVersion ?? "확인된 버전 없음"}</strong></li>
      <li>반입 기록상 빌드·실행 모두 통과한 최고 버전 <strong>{result.highestVerifiedVersion ?? "확인된 버전 없음"}</strong></li>
    </ul>
    {result.orderingLimited && <p className="muted">일부 후보의 버전 정렬 규칙을 확인할 수 없어 최고 버전 계산이 제한됩니다.</p>}
    {showReferences && <p className="muted">공식 자료는 후보 SBOM에서 확인된 패키지·버전의 선언 근거입니다. 후보별 최근 자료를 최대 3건 표시하며 조건 판정과 빌드·실행 기록은 별도로 확인합니다.</p>}
    <div className="table-scroll" role="region" aria-label="후보 버전 검토 결과 가로 스크롤" tabIndex={0}>
      <table><thead><tr><th>후보</th><th>조건 판정</th><th>근거·충돌 이유</th>{showReferences && <th>공식 출처·근거</th>}<th>빌드 기록</th><th>실행 기록</th></tr></thead>
        <tbody>{result.candidates.map(candidate => <tr key={candidate.version}><td>{candidate.version}</td>
          <td>{conditionLabel[candidate.conditionStatus]}</td>
          <td className="wrap"><ul className="paths">{candidate.reasons.map((reason, index) => <li key={index}>{reason}</li>)}</ul>
            {candidate.evidenceSource && <span className="muted">{candidate.evidenceSource}</span>}</td>
          {showReferences && <OfficialReferenceCell candidate={candidate} />}
          <VerificationCell check={candidate.build} /><VerificationCell check={candidate.runtime} />
        </tr>)}</tbody></table>
    </div>
    <UpgradeAIExplanation key={result.id} runId={runId} batchId={result.id} />
  </section>;
}
