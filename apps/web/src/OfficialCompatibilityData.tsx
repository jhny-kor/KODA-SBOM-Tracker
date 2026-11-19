import { ResizableTable } from "./ResizableTable";
import { useEffect, useState, type FormEvent } from "react";
import { request } from "./api";
import { formatSeoulDateTime } from "./format";
import { EvidenceFacts, SourceFiles, SourceLink, type ReferenceItem } from "./OfficialCompatibilityEvidence";

const endpoint = "/api/v1/compatibility-data";
const maxArchiveMegabytes = 64;
const maxArchiveSize = maxArchiveMegabytes * 1_000_000;
const archiveUploadTimeout = 300_000;
const ecosystemNames = { maven: "Java/Maven", python: "Python", elf: "Linux C" };
type Ecosystem = keyof typeof ecosystemNames;
type Authority = { id: string; ecosystem: Ecosystem; organization: string; name: string; url: string };
type Bundle = { id: string; sha256: string; collectedAt: string; importedAt: string; items: ReferenceItem[] };
type BundleSummary = Omit<Bundle, "items"> & { itemCount: number };
type Catalog = { bundles: BundleSummary[]; authorities: Authority[] };

function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : "요청을 처리하지 못했습니다.";
}

function BundleDetails({ bundle }: { bundle: Bundle }) {
  return <section aria-label="반입한 호환성 자료">
    <h3>반입한 호환성 자료</h3>
    <p>수집 {formatSeoulDateTime(bundle.collectedAt)} · 반입 {formatSeoulDateTime(bundle.importedAt)} · {bundle.items.length}개 항목</p>
    <p className="wrap">압축파일 SHA-256 <code>{bundle.sha256}</code></p>
    <a className="secondary" href={`${endpoint}/${encodeURIComponent(bundle.id)}/archive`}>반입 원본 압축 내려받기</a>
    <div className="table-scroll" role="region" aria-label="반입 자료 가로 스크롤" tabIndex={0}>
      <ResizableTable className="official-compatibility-table"><thead><tr><th>기술</th><th>패키지·버전</th><th>지정 공식 출처</th><th>호환성 근거</th><th>원본 URL·SHA-256</th></tr></thead>
        <tbody>{bundle.items.map(item => <tr key={`${item.ecosystem}/${item.package}/${item.version}/${item.architecture ?? ""}/${item.files[0]?.path ?? ""}`}>
          <td>{ecosystemNames[item.ecosystem]}</td>
          <td><strong>{item.package}</strong><br />{item.version}{item.architecture ? ` · ${item.architecture}` : ""}</td>
          <td><strong>{item.authority.organization}</strong><br /><SourceLink url={item.authority.url} label={item.authority.name} /></td>
          <td className="wrap" style={{ maxWidth: "28rem" }}><EvidenceFacts item={item} /></td>
          <td className="wrap" style={{ maxWidth: "30rem" }}><SourceFiles files={item.files} /></td>
        </tr>)}</tbody>
      </ResizableTable>
    </div>
  </section>;
}

export default function OfficialCompatibilityData({ canManage }: { canManage: boolean }) {
  const [catalog, setCatalog] = useState<Catalog | null>(null);
  const [bundle, setBundle] = useState<Bundle | null>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(true);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    const options = { signal: controller.signal };
    async function load() {
      try {
        const value = await request<Catalog>(endpoint, options);
        if (controller.signal.aborted) return;
        setCatalog(value);
        const latest = value.bundles[0];
        if (latest) {
          const detail = await request<Bundle>(`${endpoint}/${encodeURIComponent(latest.id)}`, options);
          if (!controller.signal.aborted) setBundle(detail);
        }
      } catch (cause) {
        if (!controller.signal.aborted) setError(errorMessage(cause));
      } finally {
        if (!controller.signal.aborted) setBusy(false);
      }
    }
    void load();
    return () => controller.abort();
  }, []);

  async function showBundle(id: string) {
    if (!id || bundle?.id === id) return;
    setBusy(true);
    setError("");
    try {
      setBundle(await request<Bundle>(`${endpoint}/${encodeURIComponent(id)}`));
    } catch (cause) {
      setError(errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  async function importBundle(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!canManage || !file || busy) return;
    if (!file.name.toLowerCase().endsWith(".tar.gz") || !file.size || file.size > maxArchiveSize) {
      setError(`비어 있지 않은 ${maxArchiveMegabytes} MB 이하의 .tar.gz 파일을 선택하세요.`);
      return;
    }
    const form = event.currentTarget;
    const body = new FormData();
    body.append("file", file);
    setBusy(true);
    setMessage("");
    setError("");
    try {
      const result = await request<Bundle>(`${endpoint}/import`, {
        method: "POST", body, signal: AbortSignal.timeout(archiveUploadTimeout),
      });
      setBundle(result);
      const { id, sha256, collectedAt, importedAt, items } = result;
      setCatalog(previous => previous && ({ ...previous, bundles: [
        { id, sha256, collectedAt, importedAt, itemCount: items.length },
        ...previous.bundles.filter(existing => existing.id !== id),
      ] }));
      setMessage(`지정 출처와 파일 해시를 확인해 ${items.length}개 항목을 표시합니다.`);
      form.reset();
      setFile(null);
    } catch (cause) {
      setError(cause instanceof Error && cause.name === "TimeoutError"
        ? "업로드와 검증 대기 시간이 300초를 넘었습니다. 반입 이력을 먼저 확인하세요."
        : errorMessage(cause));
    } finally {
      setBusy(false);
    }
  }

  return <section className="workflow-panel tracker-view tracker-data-panel official-compatibility-panel" aria-label="공식 호환성 자료">
    <div className="settings-panel-heading"><div><h2>공식 호환성 자료</h2>
      <p>공개망에서 수집한 패키지 선언과 원본을 한 번에 반입하고, 자료별 기관·원본 URL·SHA-256을 확인합니다.</p>
    </div></div>
    <div className="tracker-panel-body">
      <p className="muted">지정 공식 출처와 반입 파일의 해시를 확인합니다. 배포 환경의 빌드·실행 결과는 후보 검토에서 별도로 확인합니다.</p>
      {catalog && <section aria-label="지정 공식 출처">
        <h3>지정 공식 출처</h3>
        <div className="table-scroll" role="region" aria-label="지정 출처 가로 스크롤" tabIndex={0}>
          <ResizableTable><thead><tr><th>기술</th><th>기관</th><th>공식 저장소</th></tr></thead>
            <tbody>{catalog.authorities.map(authority => <tr key={authority.id}>
              <td>{ecosystemNames[authority.ecosystem]}</td><td><strong>{authority.organization}</strong></td>
              <td><SourceLink url={authority.url} label={authority.name} /></td>
            </tr>)}</tbody>
          </ResizableTable>
        </div>
      </section>}
      {canManage && <form onSubmit={event => void importBundle(event)}>
        <div className="compatibility-upload-controls">
          <label>호환성 자료 압축파일 <input type="file" accept=".tar.gz" required disabled={busy}
            onChange={event => setFile(event.target.files?.[0] ?? null)} /></label>
          <button className="primary" disabled={busy || !file}>반입하고 검증</button>
        </div>
        <p className="muted">지원 형식 .tar.gz · 최대 {maxArchiveMegabytes} MB</p>
      </form>}
      {busy && <p role="status">자료 확인 중…</p>}
      {message && <p className="form-message" role="status">{message}</p>}
      {error && <p className="form-message" role="alert">{error}</p>}
      {catalog && catalog.bundles.length > 0 && <label>반입 이력 <select value={bundle?.id ?? ""} disabled={busy}
        onChange={event => void showBundle(event.target.value)}>
        {!bundle && <option value="">이력 선택</option>}
        {catalog.bundles.map(item => <option value={item.id} key={item.id}>
          {formatSeoulDateTime(item.importedAt)} · {item.itemCount}개 · {item.sha256.slice(0, 12)}
        </option>)}
      </select></label>}
      {bundle ? <BundleDetails bundle={bundle} /> : catalog && !catalog.bundles.length && <p>반입된 호환성 자료가 없습니다.</p>}
    </div>
  </section>;
}
