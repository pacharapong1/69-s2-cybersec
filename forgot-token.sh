#!/usr/bin/env bash
# ============================================================
# ขอ reset code จากระบบแล้วเขียนลง .env ให้อัตโนมัติ
#
# วิธีใช้ (รันใน Git Bash / WSL / terminal):
#   ./forgot-token.sh admin                 # ใช้ ADMIN_EMAIL จาก .env
#   ./forgot-token.sh user                  # ใช้ USER_EMAIL จาก .env
#
# แล้วเปิด api.http กดข้อ 1.3.1 / 2.3.1 ได้เลย (code ถูกใส่ใน .env แล้ว)
# ============================================================
set -euo pipefail

cd "$(dirname "$0")"

set -a
# shellcheck disable=SC1091
source ./.env
set +a

SERVICE="${1:-admin}"
PORT="${APP_PORT:-9092}"
BASE="http://localhost:${PORT}"

case "$SERVICE" in
  admin)
    EMAIL="${ADMIN_EMAIL:-}"
    ENV_KEY="ADMIN_RESET_CODE"
    URL="${BASE}/admin/forgot-password"
    ;;
  user)
    EMAIL="${USER_EMAIL:-}"
    ENV_KEY="USER_RESET_CODE"
    URL="${BASE}/api/auth/forgot-password"
    ;;
  *)
    echo "ใช้งาน: $0 <admin|user>"
    exit 1
    ;;
esac

if [ -z "$EMAIL" ]; then
  echo "error: ไม่พบ EMAIL ใน .env"
  exit 1
fi

echo "==> เรียก ${URL}"
RESP="$(curl -s -X POST "${URL}" -H "Content-Type: application/json" -d "{\"email\":\"${EMAIL}\"}")"
echo "resp: ${RESP}"

CODE="$(printf '%s' "${RESP}" | sed -n 's/.*"code":"\([^"]*\)".*/\1/p')"

if [ -z "$CODE" ]; then
  echo "error: ไม่ได้รับ code จากระบบ (ตรวจว่า app รันอยู่หรือ email ถูกต้อง)"
  exit 1
fi

echo "==> เขียน ${ENV_KEY} ลง .env"
if grep -q "^${ENV_KEY}=" .env; then
  sed -i "s/^${ENV_KEY}=.*/${ENV_KEY}=${CODE}/" .env
else
  echo "${ENV_KEY}=${CODE}" >> .env
fi

echo
echo "เรียบร้อย! ${ENV_KEY}=${CODE}"
echo "เปิด api.http แล้วกดข้อ 1.3.1 (admin) หรือ 2.3.1 (user) ได้เลย"