import { useEffect, useState, type FormEvent } from "react";
import { request } from "./api";

type Deployment = {
  id: string; runId: string | null; target: string; serviceName: string; environmentName: string; javaMajor: number; os: string; architecture: string;
};
type Candidate = { runId: string; releaseVersion: string; roundNumber: number; environment: string };
type Assessment = {
  status: "declared_conflict" | "needs_verification";
  deployment: Deployment; currentVersions: string[]; candidateVersions: string[];
  dependencyPaths: string[][]; graphCoverage: string; pathsTruncated: boolean;
  affectedDeployments: (Deployment & { observedVersions: string[] })[]; affectedTruncated: boolean;
  componentChangeCount: number | null;
  componentChanges: { identityKey: string; name: string; baseVersions: string[]; targetVersions: string[] }[] | null;
  vulnerabilityComparison: { status: "compared"; added: string[]; removed: string[]; addedCount: number; removedCount: number }
    | { status: "not_comparable"; reason: string };
};
const api = "/api/v1/java-impact";
const reasonLabel: Record<string, string> = {
  candidate_sbom_required: "후보 SBOM을 선택해야 합니다.",
  completed_revisions_required: "양쪽 SBOM에 완료된 취약점 분석이 필요합니다.",
  same_dataset_and_scanner_required: "양쪽 분석에 동일한 취약점 자료와 분석기 버전이 확인되어야 합니다.",
};

export default function JavaUpgradePanel({ runId, serviceId, canManage }: { runId: string; serviceId: string; canManage: boolean }) {
  const [opened, setOpened] = useState(false);
  return <details className="run-metadata-section" onToggle={event => setOpened(event.currentTarget.open)}>
    <summary>Java/Maven 버전 영향 검토</summary>
    {opened && <JavaUpgradeForm runId={runId} serviceId={serviceId} canManage={canManage} />}
  </details>;
}

function JavaUpgradeForm({ runId, serviceId, canManage }: { runId: string; serviceId: string; canManage: boolean }) {
  const [deployments, setDeployments] = useState<Deployment[] | null>(null);
  const [candidateRuns, setCandidateRuns] = useState<Candidate[]>([]);
  const [deploymentId, setDeploymentId] = useState("");
  const [candidateRunId, setCandidateRunId] = useState("");
  const [result, setResult] = useState<Assessment | null>(null);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [busy, setBusy] = useState(false);
  const [truncated, setTruncated] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    const query = new URLSearchParams({ serviceId });
    void Promise.all([
      request<{ items: Deployment[]; truncated: boolean }>(`${api}/deployments?${query}`, { signal: controller.signal }),
      request<{ items: Candidate[]; truncated: boolean }>(`${api}/candidates?${query}`, { signal: controller.signal }),
    ]).then(([bases, candidates]) => {
      if (controller.signal.aborted) return;
      const available = bases.items.filter(item => item.runId);
      setDeployments(available);
      setCandidateRuns(candidates.items);
      setDeploymentId((available.find(item => item.runId === runId) ?? available[0])?.id ?? "");
      setTruncated(bases.truncated || candidates.truncated);
    }).catch(cause => { if (!controller.signal.aborted) setError(cause.message); });
    return () => controller.abort();
  }, [runId, serviceId]);

  async function register(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true); setError(""); setStatus(""); setResult(null);
    try {
      const row = await request<Deployment>(`${api}/deployments`, {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ runId, target: String(data.get("target")).trim(), javaMajor: Number(data.get("java")),
          os: String(data.get("os")).trim(), architecture: String(data.get("architecture")).trim() }),
      });
      setDeployments(previous => [row, ...(previous ?? []).filter(item => item.id !== row.id)]);
      setDeploymentId(row.id); setCandidateRunId("");
      setStatus("현재 회차를 배포 기준으로 저장했습니다.");
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  async function assess(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    const minimum = data.get("minimum");
    setBusy(true); setError(""); setStatus(""); setResult(null);
    try {
      setResult(await request<Assessment>(`${api}/assessments`, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ deploymentId, coordinate: String(data.get("coordinate")).trim(),
          ...(candidateRunId ? { candidateRunId } : { candidateVersion: String(data.get("version")).trim() }),
          ...(minimum ? { minimumJavaMajor: Number(minimum), requirementEvidence: String(data.get("evidence")).trim() } : {}) }),
      }));
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  const baseline = deployments?.find(item => item.id === deploymentId);
  return <div className="run-metadata-form">
    <p className="muted">실제 배포에 사용한 SBOM과 서버·환경을 기준으로 후보 버전의 영향을 검토합니다. 배포 기준에 연결된 회차만 영향 목록에 집계합니다.</p>
    {error && <p className="form-message" role="alert">{error}</p>}
    {status && <p className="form-message" role="status">{status}</p>}
    {truncated && <p className="muted">배포 기준 또는 후보 회차가 100개를 넘어 최근 항목만 표시합니다.</p>}
    {deployments && canManage && <form onSubmit={event => void register(event)}>
      <h3>현재 회차를 배포 기준으로 등록</h3>
      <p className="muted">같은 서비스·환경·서버 별칭에 이미 등록한 기준은 이 회차로 갱신됩니다.</p>
      <div className="run-metadata-fields">
        <label>서버 별칭<input name="target" maxLength={128} placeholder="예: 운영 WAS 1" required /></label>
        <label>배포 Java 버전<input name="java" type="number" min={6} max={99} placeholder="11" required /></label>
        <label>운영체제<input name="os" maxLength={128} placeholder="Oracle Linux 8.2" required /></label>
        <label>아키텍처<input name="architecture" maxLength={64} placeholder="x86_64" required /></label>
      </div>
      <button className="secondary" disabled={busy}>배포 기준 저장</button>
    </form>}
    {deployments?.length === 0 && <p className="muted">이 서비스에 등록된 배포 기준이 없습니다.</p>}
    {baseline && <form onSubmit={event => void assess(event)}>
      <h3>업그레이드 후보 검토</h3>
      <div className="run-metadata-fields">
        <label>배포 기준<select value={deploymentId} onChange={event => { setDeploymentId(event.target.value); setCandidateRunId(""); setResult(null); }}>
          {deployments?.map(item => <option key={item.id} value={item.id}>{item.environmentName} / {item.target} · Java {item.javaMajor} · {item.os} / {item.architecture}</option>)}
        </select></label>
        <label>Maven PURL<input name="coordinate" required maxLength={512} placeholder="pkg:maven/org.example/artifact" /></label>
        <label>후보 SBOM<select value={candidateRunId} onChange={event => { setCandidateRunId(event.target.value); setResult(null); }}>
          <option value="">후보 버전 직접 입력</option>
          {candidateRuns.filter(item => item.runId !== baseline.runId).map(item => <option key={item.runId} value={item.runId}>{item.environment} · {item.releaseVersion} · {item.roundNumber}차</option>)}
        </select></label>
        {!candidateRunId && <label>후보 버전<input name="version" maxLength={255} placeholder="2.3.0" required /></label>}
        <label>후보 최소 Java 버전<input name="minimum" type="number" min={6} max={99} /></label>
        <label>최소 Java 버전 근거<input name="evidence" maxLength={300} placeholder="릴리스 노트 또는 검증 문서" /></label>
      </div>
      <button className="primary" disabled={busy}>버전 영향 검토</button>
    </form>}
    {result && <AssessmentResult result={result} />}
  </div>;
}

function AssessmentResult({ result }: { result: Assessment }) {
  const cves = result.vulnerabilityComparison;
  return <section aria-label="Java/Maven 버전 영향 결과">
    <h3>{result.status === "declared_conflict" ? "입력한 최소 Java 요구 버전과 충돌" : "호환성 확인 필요"}</h3>
    <p>현재 {result.currentVersions.join(", ") || "확인 불가"} → 후보 {result.candidateVersions.join(", ")} · {result.deployment.environmentName} / {result.deployment.target} / Java {result.deployment.javaMajor}</p>
    <p className="muted">실행 테스트 미수행. 그래프가 비어 있거나 경로가 일부만 확인되면 해당 의존성은 추가로 검증해야 합니다.</p>
    <h4>SBOM에서 확인한 의존 경로</h4>
    {result.dependencyPaths.length ? <ul className="paths">{result.dependencyPaths.map(path => <li className="wrap" key={JSON.stringify(path)}>{path.join(" → ")}</li>)}</ul> : <p>확인된 경로가 없습니다.</p>}
    {(result.graphCoverage === "partial" || result.graphCoverage === "limit_reached" || result.pathsTruncated) && <p>경로 일부만 표시합니다.</p>}
    <h4>같은 Maven 패키지를 쓰는 등록 배포 기준</h4>
    {result.affectedDeployments.length ? <ul className="paths">{result.affectedDeployments.map(item => <li key={item.id}>{item.serviceName} / {item.environmentName} / {item.target} · Java {item.javaMajor} · {item.observedVersions.join(", ")}</li>)}</ul> : <p>다른 등록 배포 기준에서 확인되지 않았습니다.</p>}
    {result.affectedTruncated && <p>배포 기준 결과 일부만 표시합니다.</p>}
    {result.componentChanges && <><h4>후보 SBOM의 구성요소 변경 {result.componentChangeCount}건</h4>
      <ul className="paths">{result.componentChanges.slice(0, 20).map(item => <li key={item.identityKey}>{item.name} · {item.baseVersions.join(", ") || "미관측"} → {item.targetVersions.join(", ") || "미관측"}</li>)}</ul>
      {result.componentChanges.length > 20 && <p>화면에는 처음 20개 변경을 표시합니다.</p>}
    </>}
    <h4>후보 SBOM의 공개 CVE 변화</h4>
    {cves.status === "compared" ? <><p>새로 관측 {cves.addedCount}건{cves.added.length > 0 && ` · ${cves.added.slice(0, 10).join(", ")}`}</p>
      <p>후보에서 미관측 {cves.removedCount}건{cves.removed.length > 0 && ` · ${cves.removed.slice(0, 10).join(", ")}`}</p></>
      : <p>{reasonLabel[cves.reason] ?? "비교 조건을 확인할 수 없습니다."}</p>}
  </section>;
}
