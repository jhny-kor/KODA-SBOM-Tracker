#!/bin/sh
# 실제 호스트명·IP를 작업 트리에만 두고 커밋에는 자리표시자를 남기는 필터를 설정합니다.
# 클론마다 한 번 실행합니다. git config 는 저장소에 커밋되지 않습니다.
set -e
ROOT=$(git rev-parse --show-toplevel)
cd "$ROOT"

git config filter.hostredact.clean  "python3 scripts/host-redact.py clean"
git config filter.hostredact.smudge "python3 scripts/host-redact.py smudge"
git config filter.hostredact.required true

if [ ! -f .hostmap ]; then
  cat > .hostmap <<'MAP'
# 자리표시자 = 실제 값   (이 파일은 커밋되지 않습니다)
koda.example.internal = koda.example.internal
10.0.0.10             = 10.0.0.10
MAP
  echo ".hostmap 을 만들었습니다. 실제 호스트명과 IP로 오른쪽 값을 채우세요."
fi

# 이미 받아둔 파일에 smudge 를 적용
git ls-files -z | xargs -0 -n50 -- rm -f --
git checkout -- .

echo "완료. 이제 작업 트리에는 실제 값이, 커밋에는 자리표시자가 들어갑니다."
echo "확인:  git show :docs/operations-ko.md | grep -c example.internal"
