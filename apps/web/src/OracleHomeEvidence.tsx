function validIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^oracle-home\/[a-f0-9]{64}$/.test(value);
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

function patchIds(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((id): id is string => typeof id === "string" && /^[0-9]{4,12}$/.test(id)) : [];
}

const releaseBases: Record<string, string> = {
  database_ru: "Database RU",
  grid_ru: "Grid Infrastructure RU",
  database_and_grid_ru: "Database RU 및 Grid Infrastructure RU",
};

export function OracleHomeEvidence({ value }: { value: unknown }) {
  if (!value || typeof value !== "object") return null;
  const evidence = value as Record<string, unknown>;
  if (!validIdentifier(evidence.homeId)) return null;

  const basis = text(evidence.listenerReleaseBasis);
  const release = text(evidence.release);
  const releasePatchIds = patchIds(evidence.listenerReleasePatchIds);
  const installedPatchIds = patchIds(evidence.opatchInventoryPatchIds);
  const paths = Array.isArray(evidence.evidencePaths) ? evidence.evidencePaths.filter((path): path is string =>
    typeof path === "string" && /^(?:homes\/[1-8]\/)?(?:listener|opatch)\.txt$/.test(path)) : [];
  const captureHash = (value: unknown) => typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : "";
  const inventoryHash = captureHash(evidence.opatchEvidenceSha256);
  const listenerHash = captureHash(evidence.listenerEvidenceSha256);

  return <details>
    <summary>Oracle Home 증거</summary>
    <dl>
      <dt>Home ID</dt><dd><code className="wrap">{evidence.homeId}</code></dd>
      {release && <><dt>Release Update</dt><dd>{release}{Object.hasOwn(releaseBases, basis) && ` · ${releaseBases[basis]}`}</dd></>}
      {releasePatchIds.length > 0 && <><dt>버전 확인에 사용한 RU 패치 ID</dt><dd>{releasePatchIds.join(", ")}</dd></>}
      {installedPatchIds.length > 0 && <><dt>OPatch 인벤토리 패치 ID</dt><dd>{installedPatchIds.join(", ")}</dd></>}
      {paths.length > 0 && <><dt>수집 근거 파일</dt><dd>{paths.join(", ")}</dd></>}
      {inventoryHash && <><dt>OPatch 수집 근거 SHA-256</dt><dd><code className="wrap">{inventoryHash}</code></dd></>}
      {listenerHash && <><dt>Listener 수집 근거 SHA-256</dt><dd><code className="wrap">{listenerHash}</code></dd></>}
    </dl>
    {(evidence.listenerReleasePatchIdsTruncated === true || evidence.opatchInventoryPatchIdsTruncated === true) && <p>일부 패치 ID가 생략됐습니다. 전체 목록은 수집 보고서에서 확인합니다.</p>}
    {evidence.patchApplicability === "unverified" && <p>이 CVE의 수정 패치 적용 여부는 미확인입니다.</p>}
  </details>;
}
