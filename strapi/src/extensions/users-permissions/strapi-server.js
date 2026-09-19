'use strict';

const crypto = require('crypto');

const RESET_CODE_TTL_MS = 15 * 60 * 1000;

function audit(action, ctx, extra = {}) {
  const ip = (ctx && ctx.request && ctx.request.ip) || 'unknown';
  console.log(`[audit][${action}] ip=${ip} at=${new Date().toISOString()} ${JSON.stringify(extra)}`);
}

module.exports = (plugin) => {
  const originalResetPassword = plugin.controllers.auth.resetPassword;

  plugin.controllers.auth.forgotPassword = async (ctx) => {
    const { email } = ctx.request.body || {};

    if (!email) {
      return ctx.badRequest('Please provide your email.');
    }

    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { email: email.toLowerCase() } });

    if (!user || user.blocked) {
      audit('user/forgot', ctx, { email: email.toLowerCase(), result: 'no-op' });
      return ctx.send({ ok: true });
    }

    const expiresAt = Date.now() + RESET_CODE_TTL_MS;
    const code = `${expiresAt}:${crypto.randomBytes(64).toString('hex')}`;

    await strapi
      .query('plugin::users-permissions.user')
      .update({ where: { id: user.id }, data: { resetPasswordToken: code } });

    audit('user/forgot', ctx, { email: user.email, result: 'token-issued' });

    ctx.send({ ok: true, code });
  };

  plugin.controllers.auth.resetPassword = async (ctx) => {
    const { code } = ctx.request.body || {};

    const sep = code ? code.indexOf(':') : -1;
    const expires = sep > 0 ? parseInt(code.slice(0, sep), 10) : NaN;

    if (!(expires && expires > Date.now())) {
      audit('user/reset', ctx, { result: 'invalid-or-expired' });
      return ctx.badRequest('Reset code is invalid or has expired.');
    }

    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { resetPasswordToken: code } });

    audit('user/reset', ctx, {
      result: user ? 'ok' : 'no-user',
      email: user ? user.email : undefined,
    });

    return originalResetPassword(ctx);
  };

  return plugin;
};