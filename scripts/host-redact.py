#!/usr/bin/env python3
"""저장소에 실제 호스트명·IP가 들어가지 않도록 하는 git clean/smudge 필터.

작업 트리에는 실제 값을 두고 커밋에는 자리표시자만 남긴다.
대응표는 추적하지 않는 `.hostmap`에서 읽으며, 파일이 없으면 내용을 그대로 통과시킨다.

  .hostmap 형식 (탭 또는 = 구분, `#`는 주석)
      koda.example.internal = koda.real.example
      10.0.0.10             = 10.20.30.40

  clean  : 실제 값 -> 자리표시자 (git add / commit 시)
  smudge : 자리표시자 -> 실제 값 (checkout 시)
"""
import sys, os, pathlib

def load_map(root):
    p = pathlib.Path(root) / ".hostmap"
    pairs = []
    if not p.exists():
        return pairs
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        sep = "=" if "=" in line else "\t"
        if sep not in line:
            continue
        holder, real = (x.strip() for x in line.split(sep, 1))
        if holder and real:
            pairs.append((holder, real))
    # 긴 문자열을 먼저 바꿔 부분 치환을 막는다
    return sorted(pairs, key=lambda kv: -len(kv[0]))

def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    if mode not in ("clean", "smudge"):
        sys.stderr.write("usage: host-redact.py {clean|smudge}\n")
        return 2
    root = os.environ.get("GIT_PREFIX_ROOT") or os.getcwd()
    data = sys.stdin.buffer.read()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        sys.stdout.buffer.write(data)   # 텍스트가 아니면 손대지 않는다
        return 0
    for holder, real in load_map(root):
        text = text.replace(real, holder) if mode == "clean" else text.replace(holder, real)
    sys.stdout.buffer.write(text.encode("utf-8"))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
