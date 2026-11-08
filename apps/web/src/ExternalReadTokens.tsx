import { useEffect, useState, type FormEvent } from "react";
import { request } from "./api";
import { formatSeoulDateTime } from "./format";
import type { CatalogItem } from "./types";

type ReadToken = {
  id: string; name: string; serviceId: string; environmentId: string | null; expiresAt: string; revokedAt: string | null;
};
const tokensPath = "/api/v1/integrations/external/tokens";

export default function ExternalReadTokens({ services, environments }: { services: CatalogItem[]; environments: CatalogItem[] }) {
  const [tokens, setTokens] = useState<ReadToken[] | null>(null);
  const [issued, setIssued] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    void request<ReadToken[]>(tokensPath, { signal: controller.signal })
      .then(value => { if (!controller.signal.aborted) setTokens(value); })
      .catch(cause => { if (!controller.signal.aborted) setError(cause.message); });
    return () => controller.abort();
  }, []);

  async function issue(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const data = new FormData(event.currentTarget);
    setBusy(true); setError(""); setIssued("");
    try {
      const { token, ...info } = await request<ReadToken & { token: string }>(tokensPath, {
        method: "POST", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name: String(data.get("name")).trim(), serviceId: data.get("service"),
          environmentId: data.get("environment") === "all" ? null : data.get("environment"), days: Number(data.get("days")) }),
      });
      setIssued(token);
      setTokens(previous => [info, ...(previous ?? [])]);
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  async function revoke(id: string) {
    setBusy(true); setError(""); setIssued("");
    try {
      const info = await request<ReadToken>(`${tokensPath}/${encodeURIComponent(id)}/revoke`, { method: "POST" });
      setTokens(previous => previous?.map(token => token.id === id ? info : token) ?? []);
    } catch (cause) { setError((cause as Error).message); }
    finally { setBusy(false); }
  }

  return <section className="table-frame" aria-label="외부 API 조회 토큰">
    <div className="settings-panel-heading"><div><h2 className="table-title">외부 API 조회 토큰</h2>
      <p>다른 시스템이 지정한 서비스와 환경의 Tracker 데이터를 읽을 때 사용합니다. 연동할 시스템마다 별도로 발급하세요.</p>
    </div></div>
    <div className="integration-status-body">
      {error && <p className="form-message" role="alert">{error}</p>}
      {tokens && <form className="run-metadata-form" onSubmit={event => void issue(event)}>
        <div className="run-metadata-fields">
          <label>연동 이름<input name="name" required maxLength={128} /></label>
          <label>서비스<select name="service" required defaultValue=""><option value="">선택</option>{services.filter(item => item.active !== false).map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select></label>
          <label>환경<select name="environment" required defaultValue=""><option value="" disabled>선택</option>{environments.filter(item => item.active !== false).map(item => <option key={item.id} value={item.id}>{item.name}</option>)}<option value="all">모든 활성 환경</option></select></label>
          <label>유효 기간(일)<input name="days" type="number" min={1} max={90} defaultValue={30} required /></label>
        </div>
        <button className="primary" disabled={busy}>조회 토큰 발급</button>
      </form>}
      {issued && <div className="token-reveal"><strong>발급한 조회 토큰 · 이 화면에서 한 번 확인</strong><code>{issued}</code><button type="button" className="secondary compact" onClick={() => setIssued("")}>닫기</button></div>}
    </div>
    {tokens && <div className="table-scroll" role="region" aria-label="외부 조회 토큰 목록" tabIndex={0}>
      <table><thead><tr><th>연동 이름</th><th>서비스</th><th>환경</th><th>만료</th><th>관리</th></tr></thead><tbody>
        {tokens.map(token => <tr key={token.id}><td>{token.name}</td><td>{services.find(item => item.id === token.serviceId)?.name ?? token.serviceId}</td>
          <td>{token.environmentId ? environments.find(item => item.id === token.environmentId)?.name ?? token.environmentId : "모든 활성 환경"}</td>
          <td>{formatSeoulDateTime(token.expiresAt)}</td><td>{token.revokedAt ? "폐기됨" : Date.parse(token.expiresAt) <= Date.now() ? "만료됨"
            : <button type="button" className="secondary compact" disabled={busy} onClick={() => void revoke(token.id)}>폐기</button>}</td></tr>)}
        {!tokens.length && <tr><td colSpan={5}>발급된 조회 토큰이 없습니다.</td></tr>}
      </tbody></table>
    </div>}
  </section>;
}
