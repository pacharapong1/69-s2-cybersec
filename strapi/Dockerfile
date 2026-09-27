# Custom Strapi image: /admin/forgot-password and /api/auth/forgot-password
# deliver the reset code out-of-band by email (Mailhog) instead of returning it
# in the HTTP response. Both sides also enforce JWT-gated, owner-only reset with
# TTL, persistent account lockout, session revocation on password change and
# durable JSONL audit logs.
FROM prawee/strapi:latest

USER root

# 1) users-permissions: override forgot-password to send the code by email (no response code)
#    + explicit rate-limit config + shared audit logger
COPY src/ /opt/app/src/
COPY config/ /opt/app/config/

# 2) admin (core): patch controller/service/routes so POST /admin/forgot-password
#    emails the token, admin lockout is persisted, sessions are revoked on password
#    change, and login/change/reset events are audited.
COPY patch/ /opt/patch/
RUN node /opt/patch/patch-admin.js && node /opt/patch/patch-users-permissions.js && rm -rf /opt/patch

USER node