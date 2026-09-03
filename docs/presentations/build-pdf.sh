#!/bin/sh
# HTML을 수정한 뒤 이 스크립트를 실행하면 같은 규격(1440x810, 16:9)으로 PDF가 다시 만들어집니다.
# 사용법:  ./build-pdf.sh
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
CHROME="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"

"$CHROME" --headless=new --disable-gpu --no-pdf-header-footer \
  --virtual-time-budget=25000 \
  --print-to-pdf="$DIR/koda-suite-user-briefing.pdf" \
  "file://$DIR/koda-suite-user-briefing.html"

echo "생성됨: $DIR/koda-suite-user-briefing.pdf"
