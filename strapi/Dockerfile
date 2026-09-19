# Custom Strapi image: /admin/forgot-password and /api/auth/forgot-password
# return the reset token in the HTTP response instead of sending it by email.
FROM prawee/strapi:latest

USER root

# 1) users-permissions: override forgot-password so the token is returned (no email)
#    + explicit rate-limit config for users-permissions
COPY src/ /opt/app/src/
COPY config/ /opt/app/config/

# 2) admin (core): patch controller/service so POST /admin/forgot-password returns the token
COPY patch/ /opt/patch/
RUN node /opt/patch/patch-admin.js && rm -rf /opt/patch

USER node