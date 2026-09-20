'use strict';

const crypto = require('crypto');

const RESET_CODE_TTL_MS = 15 * 60 * 1000;

function audit(action, ctx, extra = {}) {
  const ip = (ctx && ctx.request && ctx.request.ip) || 'unknown';
  console.log(`[audit][${action}] ip=${ip} at=${new Date().toISOString()} ${JSON.stringify(extra)}`);
}

function sha256(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

async function authenticate(ctx) {
  try {
    const token = await strapi.plugin('users-permissions').service('jwt').getToken(ctx);
    if (!token || token.id === undefined) {
      return null;
    }
    const user = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { id: token.id } });
    if (!user || user.blocked) {
      return null;
    }
    return user;
  } catch (err) {
    return null;
  }
}

module.exports = (plugin) => {
  const originalResetPassword = plugin.controllers.auth.resetPassword;

  // Strapi auto-injects `config.auth = { scope }` on content-api routes, and the
  // injected scope (plugin::users-permissions.auth.*) is not granted to the
  // "Authenticated" role -> would 403. We set auth:false and do the JWT + owner
  // check ourselves in the controllers below (course flow: token from login).
  for (const route of plugin.routes['content-api'].routes) {
    if (route.handler === 'auth.forgotPassword' || route.handler === 'auth.resetPassword') {
      route.config = { ...route.config, auth: false };
    }
  }

  plugin.controllers.auth.forgotPassword = async (ctx) => {
    const user = await authenticate(ctx);

    if (!user) {
      audit('user/forgot', ctx, { result: 'auth-required' });
      return ctx.throw(401, 'You must be logged in to request a password reset.');
    }

    const { email } = ctx.request.body || {};
    const requestedEmail = (email || '').toLowerCase();
    const ownEmail = (user.email || '').toLowerCase();

    if (!requestedEmail || requestedEmail !== ownEmail) {
      audit('user/forgot', ctx, { result: 'denied', email: requestedEmail });
      return ctx.throw(403, 'You can only request a password reset for your own account.');
    }

    const expiresAt = Date.now() + RESET_CODE_TTL_MS;
    const code = `${expiresAt}:${crypto.randomBytes(64).toString('hex')}`;

    await strapi
      .query('plugin::users-permissions.user')
      .update({
        where: { id: user.id },
        data: { resetPasswordToken: sha256(code) },
      });

    audit('user/forgot', ctx, { email: user.email, result: 'token-issued' });

    ctx.send({ ok: true, code });
  };

  plugin.controllers.auth.resetPassword = async (ctx) => {
    const body = ctx.request.body || {};
    const { code } = body;

    const user = await authenticate(ctx);

    if (!user) {
      audit('user/reset', ctx, { result: 'auth-required' });
      return ctx.throw(401, 'You must be logged in to reset your password.');
    }

    const sep = code ? code.indexOf(':') : -1;
    const expires = sep > 0 ? parseInt(code.slice(0, sep), 10) : NaN;

    if (!(expires && expires > Date.now())) {
      audit('user/reset', ctx, { result: 'invalid-or-expired' });
      return ctx.badRequest('Reset code is invalid or has expired.');
    }

    const hashed = sha256(code);
    const target = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { resetPasswordToken: hashed } });

    audit('user/reset', ctx, {
      result: target ? 'ok' : 'no-user',
      email: target ? target.email : undefined,
    });

    if (!target) {
      return ctx.badRequest('Reset code is invalid or has expired.');
    }

    if (target.id !== user.id) {
      audit('user/reset', ctx, { result: 'not-owner', email: target.email });
      return ctx.throw(403, 'You can only reset your own password.');
    }

    body.code = hashed;

    return originalResetPassword(ctx);
  };

  return plugin;
};