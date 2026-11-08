type Ecosystem = "maven" | "python" | "elf";
type Authority = { id: string; ecosystem: Ecosystem; organization: string; name: string; url: string };
type SourceFile = { kind: string; path: string; url: string; sha256: string; size: number };
export type ReferenceItem = { ecosystem: Ecosystem; package: string; version: string; architecture?: string | null;
  authority: Authority; files: SourceFile[]; evidence: Record<string, unknown> };

export function SourceLink({ url, label = url }: { url: string; label?: string }) {
  return url.startsWith("https://") ? <a className="wrap" href={url} target="_blank" rel="noreferrer">{label}</a> : <span>{label}</span>;
}

export function EvidenceFacts({ item }: { item: ReferenceItem }) {
  const { evidence } = item;
  let facts: string[] = [];
  if (item.ecosystem === "maven" && evidence.compiler && typeof evidence.compiler === "object") {
    facts = Object.entries(evidence.compiler).map(([name, value]) => `${name} ${String(value)}`);
  }
  if (item.ecosystem === "python" && typeof evidence.requiresPython === "string") {
    facts.push(`Python 요구 버전 ${evidence.requiresPython}`);
  }
  if (item.ecosystem === "elf" && Array.isArray(evidence.provides)) {
    const libraries = evidence.provides.map(value => typeof value === "string" ? value : value?.name)
      .filter((value): value is string => typeof value === "string" && value.includes(".so"));
    facts = libraries.slice(0, 2);
  }
  return <>
    {facts.length > 0 && <span>{facts.join(" · ")}</span>}
    <details className="data-sample-content"><summary>선언 근거 보기</summary><pre>{JSON.stringify(evidence, null, 2)}</pre></details>
  </>;
}

export function SourceFiles({ files }: { files: SourceFile[] }) {
  return <details><summary>원본과 검증 해시 {files.length}개</summary>
    <ul className="paths">{files.map(file => <li key={file.path}>
      <strong>{file.path.split("/").at(-1)}</strong><br /><SourceLink url={file.url} /><br />
      <span>SHA-256 <code>{file.sha256}</code></span>
    </li>)}</ul>
  </details>;
}
