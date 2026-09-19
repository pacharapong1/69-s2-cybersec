#!/usr/bin/env bash
# ============================================================
# ตั้ง reset code/token ผ่านเทอมินอล (ไม่ต้องพึ่งอีเมล)
# แล้วกลับไปเรียกข้อ 1.3.1 (Admin) หรือ 2.3.1 (User) ใน api.http
#
# วิธีใช้ (รันใน Git Bash / WSL / terminal):
#   ./reset-token.sh admin                 # ใช้ ADMIN_EMAIL จาก .env, สุ่ม code อัตโนมัติ
#   ./reset-token.sh admin admin@x.com     # ระบุ email เอง สุ่ม code
#   ./reset-token.sh admin admin@x.com 1234  # ระบุ email + code เอง
#   ./reset-token.sh user                  # ใช้ USER_EMAIL จาก .env
#   ./reset-token.sh user user@x.com abcd
# ============================================================
set -euo pipefail

cd "$(dirname "$0")"

# อ่านค่าการเชื่อมต่อ DB จาก .env
set -a
# shellcheck disable=SC1091
source ./.env
set +a

SERVICE="${1:-admin}"
EMAIL="${2:-}"
CODE="${3:-}"

case "$SERVICE" in
  admin)
    TABLE="admin_users"
    DEFAULT_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
    ;;
  user)
    TABLE="up_users"
    DEFAULT_EMAIL="${USER_EMAIL:-user@example.com}"
    ;;
  *)
    echo "ใช้งาน: $0 <admin|user> [email] [code]"
    exit 1
    ;;
esac

# กันค่าแปลก ๆ (SQL injection defense): อนุญาตเฉพาะชื่อตารางที่รู้จัก
case "$TABLE" in
  admin_users|up_users) ;;
  *) echo "error: invalid table"; exit 1 ;;
esac

EMAIL="${EMAIL:-$DEFAULT_EMAIL}"

# ใช้ openssl เท่านั้น (หลีกเลี่ยง fallback ที่คาดเดาได้)
if [ -z "$CODE" ]; then
  if command -v openssl >/dev/null 2>&1; then
    CODE="$(openssl rand -hex 16)"
  else
    echo "error: openssl not found, cannot generate a secure code"
    exit 1
  fi
fi

# ระบบปัจจุบันต้องการ code รูปแบบ "<expires_ms>:<random>" (TTL 15 นาที)
# และเก็บใน DB เป็น SHA-256 hash เท่านั้น (ไม่เก็บตัวเต็ม)
EXPIRES_MS="$(( ($(date +%s) + 900) * 1000 ))"
FULL_CODE="${EXPIRES_MS}:${CODE}"
HASH="$(printf '%s' "$FULL_CODE" | sha256sum | cut -d' ' -f1)"

# Escape single quotes สำหรับ SQL string literal
sql_escape() {
  printf '%s' "$1" | sed "s/'/''/g"
}

TABLE_S="$(sql_escape "$TABLE")"
EMAIL_S="$(sql_escape "$EMAIL")"
HASH_S="$(sql_escape "$HASH")"

CONTAINER="69-s2-db"
DBPORT="5432"

echo "==> ตั้ง reset token ให้ $TABLE (email = $EMAIL, หมดอายุใน 15 นาที)"
docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" "$CONTAINER" psql \
  -h localhost -p "$DBPORT" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
  -c "UPDATE ${TABLE_S} SET reset_password_token = '${HASH_S}' WHERE email = '${EMAIL_S}';"

echo
echo "==> ตรวจสอบผล (reset_password_token ควรเป็น hash 64 ตัว ไม่ใช่ code ตัวเต็ม)"
docker exec -e PGPASSWORD="${POSTGRES_PASSWORD}" "$CONTAINER" psql \
  -h localhost -p "$DBPORT" -U "${POSTGRES_USER}" -d "${POSTGRES_DB}" \
  -c "SELECT id, email, reset_password_token, length(reset_password_token) AS len FROM ${TABLE_S} WHERE email = '${EMAIL_S}';"

echo
echo "เรียบร้อย! นำ code นี้ไปใส่ใน .env แล้วเรียกข้อ 1.3.1 / 2.3.1"
echo "   ADMIN_RESET_CODE=${FULL_CODE}"
echo "   USER_RESET_CODE=${FULL_CODE}"