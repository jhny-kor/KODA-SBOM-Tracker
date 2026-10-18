#!/usr/bin/env python3
"""Wait for KODA analysis and enforce its current policy/quality decision in CI.

Exit 0: pass, 1: blocked, 2: timeout/configuration/transport failure.
Only a successful current gate may allow the next pipeline step.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def wait_for_gate(fetch, *, timeout: float, interval: float, clock=time.monotonic, sleep=time.sleep) -> tuple[int, dict]:
    deadline = clock() + timeout
    while True:
        result = fetch()
        if result.get("status") == "pass" and result.get("allowed") is True and not result.get("reasons"):
            return 0, result
        if result.get("status") == "blocked":
            return 1, result
        if result.get("status") != "pending":
            return 2, {"status": "error", "reasons": ["invalid_gate_response"]}
        remaining = deadline - clock()
        if remaining <= 0:
            return 2, {**result, "status": "timeout"}
        sleep(min(interval, remaining))


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("run_id")
    p.add_argument("--timeout", type=float, default=600)
    p.add_argument("--interval", type=float, default=3)
    args = p.parse_args()
    base, token = os.environ.get("KODA_TRACKER_URL", "").rstrip("/"), os.environ.get("KODA_TRACKER_TOKEN", "")
    parsed = urlsplit(base)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc or parsed.username or parsed.password or parsed.query or parsed.fragment or not token or not 0 < args.timeout <= 86400 or not 0 < args.interval <= 60:
        p.error("KODA_TRACKER_URL / KODA_TRACKER_TOKEN 및 유효한 timeout/interval이 필요합니다")
    opener = build_opener(NoRedirect())

    def fetch():
        req = Request(base + "/api/v1/sbom-runs/" + quote(args.run_id, safe="") + "/gate",
                      headers={"Authorization": "Bearer " + token, "Accept": "application/json"})
        with opener.open(req, timeout=min(30, args.timeout)) as response:
            return json.loads(response.read(1024 * 1024))

    try:
        code, result = wait_for_gate(fetch, timeout=args.timeout, interval=args.interval)
    except (HTTPError, URLError, ValueError, OSError):
        # Do not print request headers, token, or a proxy's possibly sensitive body.
        code, result = 2, {"status": "error", "reasons": ["gate_request_failed"]}
    print(json.dumps(result, ensure_ascii=False))
    return code


if __name__ == "__main__":
    sys.exit(main())
