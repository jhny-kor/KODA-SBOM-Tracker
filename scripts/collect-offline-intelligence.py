#!/usr/bin/env python3
"""Connected-host collector / approved-local-file normalizer. Runtime never invokes it."""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
from datetime import datetime, timezone
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit
import urllib.request

SCRIPT_DIR = Path(__file__).resolve().parent
MODULE = next((candidate for candidate in (
    SCRIPT_DIR.parent / "apps/api/koda_tracker/offline_intelligence.py",
    SCRIPT_DIR / "offline_intelligence.py",
    SCRIPT_DIR.parent / "source/apps/api/koda_tracker/offline_intelligence.py",
) if candidate.is_file()), None)
if MODULE is None:
    raise RuntimeError("validated offline intelligence parser is missing from this distribution")
specification = importlib.util.spec_from_file_location("offline_intelligence", MODULE)
parser_module = importlib.util.module_from_spec(specification)
specification.loader.exec_module(parser_module)

HOSTS = {"services.nvd.nist.gov", "nvd.nist.gov", "cwe.mitre.org", "endoflife.date", "security-metadata.canonical.com",
         "epss.empiricalsecurity.com", "epss.cyentia.com", "raw.githubusercontent.com"}


def approved_url(url, allowed_hosts):
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname not in allowed_hosts or parsed.port not in {None, 443} or parsed.username or parsed.password or parsed.fragment:
        raise ValueError("source URL is not an approved credential-free HTTPS origin")
    if parsed.hostname == "raw.githubusercontent.com" and not parsed.path.startswith(("/cisagov/vulnrichment/", "/CVEProject/cvelistV5/", "/spdx/license-list-data/")):
        raise ValueError("unapproved raw GitHub repository")
    if any(key.lower() in {"api_key", "apikey", "token", "access_token", "password", "authorization", "signature", "credential"} for key, _ in parse_qsl(parsed.query)):
        raise ValueError("collector URLs must not contain credentials")


class ApprovedRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_hosts, trace):
        self.allowed_hosts, self.trace = allowed_hosts, trace

    def redirect_request(self, request, fp, code, message, headers, new_url):
        target = urljoin(request.full_url, new_url)
        approved_url(target, self.allowed_hosts)
        if len(self.trace) >= 6:
            raise ValueError("redirect limit exceeded")
        self.trace.append(target)
        return super().redirect_request(request, fp, code, message, headers, target)


def fetch_url(url, allowed_hosts, *, trace=None):
    approved_url(url, allowed_hosts)
    trace = trace if trace is not None else []
    trace.append(url)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), ApprovedRedirect(allowed_hosts, trace))
    request = urllib.request.Request(url, headers={"User-Agent": "KODA-offline-intelligence-collector/1", "Accept": "application/json,application/xml,text/csv,*/*"})
    with opener.open(request, timeout=30) as response:
        raw = response.read(parser_module.MAX_FILE_BYTES + 1)
    if not raw or len(raw) > parser_module.MAX_FILE_BYTES:
        raise ValueError("download size limit exceeded")
    return raw


def collect(spec: dict, output: Path, *, fetch=False, inline=False, base=Path("."), allow_hosts=()):
    if not isinstance(spec, dict) or set(spec) != {"sources"} or not isinstance(spec["sources"], list) or not 0 < len(spec["sources"]) <= parser_module.MAX_SOURCES:
        raise ValueError("spec requires a bounded sources list")
    output = Path(output)
    if output.exists():
        raise ValueError("output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=".intelligence-", dir=output.parent))
    try:
        sources_dir = temporary / "intelligence-sources"
        sources_dir.mkdir()
        document = {"format": parser_module.FORMAT, "createdAt": datetime.now(timezone.utc).isoformat(), "datasets": {}}
        ids = set()
        for item in spec["sources"]:
            kind, source_id = item.get("kind"), item.get("id")
            if kind not in parser_module.KINDS or not isinstance(source_id, str) or source_id in ids:
                raise ValueError("invalid kind or duplicate source id")
            ids.add(source_id)
            path, url = item.get("path"), item.get("url")
            if bool(path) == bool(url):
                raise ValueError("each source requires exactly one path or url")
            if url and not fetch:
                raise ValueError("remote acquisition requires explicit --fetch on connected host")
            if url and item.get("sourceUrl") not in {None, url}:
                raise ValueError("remote sourceUrl must identify the fetched URL")
            if path:
                file = base / path
                if file.is_symlink() or not file.is_file() or file.stat().st_size > parser_module.MAX_FILE_BYTES:
                    raise ValueError("invalid local source file")
                if not item.get("fetchedAt"):
                    raise ValueError("approved local source requires its original fetchedAt")
                raw = file.read_bytes()
            else:
                trace = []
                raw = fetch_url(url, HOSTS | set(allow_hosts), trace=trace)
            page = 0
            max_pages = item.get("maxPages", 10)
            if type(max_pages) is not int or not 1 <= max_pages <= 100:
                raise ValueError("maxPages must be 1..100")
            while True:
                source = {"id": source_id if page == 0 else f"{source_id[:100]}-p{page}",
                          "sourceUrl": url if url else item.get("sourceUrl"), "fetchedAt": datetime.now(timezone.utc).isoformat() if url else item["fetchedAt"]}
                if url:
                    source.update(resolvedSourceUrl=trace[-1], redirectChain=trace.copy())
                if item.get("dataDate"):
                    source["dataDate"] = item["dataDate"]
                if item.get("maxAgeDays") is not None:
                    source["maxAgeDays"] = item["maxAgeDays"]
                digest = hashlib.sha256(raw).hexdigest()
                source["sourceFile"] = f"intelligence-sources/{digest}.bin"
                if inline:
                    source["rawBase64"] = base64.b64encode(raw).decode("ascii")
                target = temporary / source["sourceFile"]
                if not target.exists():
                    target.write_bytes(raw)
                normalized = parser_module.normalize_source(kind, raw, source)
                dataset = document["datasets"].setdefault(kind, {"sources": [], "records": []})
                dataset["sources"].extend(normalized["sources"])
                dataset["records"].extend(normalized["records"])
                if not url or not item.get("paginate"):
                    break
                if urlsplit(url).hostname != "services.nvd.nist.gov" or kind not in {"cpe-dictionary", "cpe-match"}:
                    raise ValueError("automatic pagination is supported only for NVD CPE APIs")
                envelope = json.loads(raw)
                start, count, total = (envelope.get(key) for key in ("startIndex", "resultsPerPage", "totalResults"))
                if any(type(value) is not int or value < 0 for value in (start, count, total)) or count == 0:
                    raise ValueError("invalid NVD pagination metadata")
                if start + count >= total:
                    break
                page += 1
                if page >= max_pages:
                    raise ValueError("NVD pagination incomplete: increase bounded maxPages or narrow product query")
                parsed = urlsplit(url)
                params = dict(parse_qsl(parsed.query)); params["startIndex"] = str(start + count)
                url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(params), ""))
                time.sleep(6.5)
                trace = []
                raw = fetch_url(url, HOSTS | set(allow_hosts), trace=trace)
        parser_module.validate_document(document, temporary)
        encoded = (json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        if len(encoded) > parser_module.MAX_FILE_BYTES:
            raise ValueError("normalized index size limit exceeded; split collection into smaller approved sources")
        (temporary / "intelligence.json").write_bytes(encoded)
        parser_module.load_intelligence(temporary)
        os.replace(temporary, output)
        return output / "intelligence.json"
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--fetch", action="store_true", help="explicit connected-host acquisition")
    parser.add_argument("--inline", action="store_true", help="include rawBase64 for authenticated JSON import")
    parser.add_argument("--allow-host", action="append", default=[], help="operator-approved vendor HTTPS host")
    args = parser.parse_args()
    print(collect(json.loads(args.spec.read_text()), args.output, fetch=args.fetch, inline=args.inline, base=args.spec.parent, allow_hosts=args.allow_host))


if __name__ == "__main__":
    main()
