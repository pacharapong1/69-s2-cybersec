'use strict';

const crypto = require('crypto');
const audit = require('/opt/app/src/audit');

const RESET_CODE_TTL_MS = 15 * 60 * 1000;

// Account lockout: after MAX_LOGIN_FAILS consecutive failed logins for the same
// identifier the account is locked for LOCKOUT_MS. Persisted in the plugin store
// (DB) so the state is shared regardless of how the module is loaded.
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const LOCKOUT_STORE_KEY = 'login_lockouts_store';
const PASSWORD_CHANGED_STORE_KEY = 'password_changed_store';

function sha256(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex');
}

// Mirrors the admin-side password policy (@strapi/admin common-validators):
// min 8 chars + at least one lowercase, uppercase and digit.
function isStrongPassword(password) {
  return (
    typeof password === 'string' &&
    password.length >= 8 &&
    /[a-z]/.test(password) &&
    /[A-Z]/.test(password) &&
    /\d/.test(password)
  );
}

function clientInfo(ctx) {
  const req = (ctx && ctx.request) || {};
  return {
    ip: req.ip || 'unknown',
    ua: (req && req.header && req.header['user-agent']) || 'unknown',
  };
}

// ---------------------------------------------------------------------------
// Login failure / lockout helpers (persisted in the plugin store)
// ---------------------------------------------------------------------------
async function getLoginFailures() {
  const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
  const all = (await store.get({ key: LOCKOUT_STORE_KEY })) || {};
  return { store, all };
}

async function isAccountLocked(identifier) {
  const { all } = await getLoginFailures();
  const rec = all[identifier];
  if (!rec) return false;
  if (rec.until > Date.now()) return true;
  if (rec.until <= Date.now()) delete all[identifier];
  return false;
}

async function recordLoginFailure(identifier) {
  const { store, all } = await getLoginFailures();
  const rec = all[identifier] || { count: 0, until: 0 };
  rec.count += 1;
  if (rec.count >= LOGIN_MAX_FAILS) {
    rec.until = Date.now() + LOGIN_LOCKOUT_MS;
    rec.count = 0;
    all[identifier] = rec;
    await store.set({ key: LOCKOUT_STORE_KEY, value: all });
    return rec.until;
  }
  all[identifier] = rec;
  await store.set({ key: LOCKOUT_STORE_KEY, value: all });
  return 0;
}

async function clearLoginFailures(identifier) {
  const { store, all } = await getLoginFailures();
  delete all[identifier];
  await store.set({ key: LOCKOUT_STORE_KEY, value: all });
}

// ---------------------------------------------------------------------------
// Session revocation: every password change invalidates all tokens that were
// issued before the change (compared on the JWT "iat" claim).
// ---------------------------------------------------------------------------
async function setPasswordChangedAt(userId, value) {
  const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
  const all = (await store.get({ key: PASSWORD_CHANGED_STORE_KEY })) || {};
  if (value == null) {
    delete all[userId];
  } else {
    all[userId] = value;
  }
  await store.set({ key: PASSWORD_CHANGED_STORE_KEY, value: all });
}

async function getPasswordChangedAt(userId) {
  const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
  const all = (await store.get({ key: PASSWORD_CHANGED_STORE_KEY })) || {};
  return all[userId] || 0;
}

async function recordPasswordChange(userId) {
  await setPasswordChangedAt(userId, Date.now());
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
    const changedAt = await getPasswordChangedAt(user.id);
    if (changedAt && token.iat && Number(token.iat) < Math.floor(changedAt / 1000)) {
      return null;
    }
    return user;
  } catch (err) {
    return null;
  }
}

module.exports = (plugin) => {
  const originalResetPassword = plugin.controllers.auth.resetPassword;
  const originalChangePassword = plugin.controllers.auth.changePassword;
  const originalCallback = plugin.controllers.auth.callback;
  const originalRegister = plugin.controllers.auth.register;
  const originalSendEmailConfirmation = plugin.controllers.auth.sendEmailConfirmation;

  // Strapi auto-injects `config.auth = { scope }` on content-api routes, and the
  // injected scope (plugin::users-permissions.auth.*) is not granted to the
  // "Authenticated" role -> would 403. We set auth:false and do the JWT + owner
  // check ourselves in the controllers below (course flow: token from login).
  for (const route of plugin.routes['content-api'].routes) {
    if (route.handler === 'auth.forgotPassword' || route.handler === 'auth.resetPassword') {
      route.config = { ...route.config, auth: false };
    }
    // anti-enumeration endpoint: also protect with the plugin rate limiter
    if (route.handler === 'auth.sendEmailConfirmation') {
      route.config = {
        ...route.config,
        middlewares: ['plugin::users-permissions.rateLimit'],
      };
    }
  }

  plugin.controllers.auth.callback = async (ctx) => {
    const provider = (ctx.params && ctx.params.provider) || 'local';
    const identifier = String(
      (ctx.request.body && ctx.request.body.identifier) || ''
    ).toLowerCase();

    if (provider === 'local') {
      if (await isAccountLocked(identifier)) {
        audit('user/login', clientInfo(ctx), { identifier, result: 'locked' });
        return ctx.throw(423, 'Too many login attempts. Please try again later.');
      }
    }

    try {
      const result = await originalCallback(ctx);
      if (provider === 'local') {
        await clearLoginFailures(identifier);
      }
      audit('user/login', clientInfo(ctx), { identifier, result: 'ok' });
      return result;
    } catch (err) {
      if (provider === 'local') {
        const lockedUntil = await recordLoginFailure(identifier);
        if (lockedUntil) {
          audit('user/login', clientInfo(ctx), { identifier, result: 'lockout' });
        }
        audit('user/login', clientInfo(ctx), { identifier, result: 'failed' });
      } else {
        audit('user/login', clientInfo(ctx), { identifier, result: 'failed' });
      }
      throw err;
    }
  };

  plugin.controllers.auth.sendEmailConfirmation = async (ctx) => {
    const { email } = ctx.request.body || {};
    try {
      await originalSendEmailConfirmation(ctx);
    } catch (err) {
      // uniform response regardless of account state (no enumeration of
      // confirmed/blocked status); input validation errors still surface
      if (err.name === 'ValidationError') {
        throw err;
      }
      audit('user/send-email-confirmation', clientInfo(ctx), { email, result: 'uniform-response' });
      return ctx.send({ email: (email || '').toLowerCase(), sent: true });
    }
    return undefined;
  };

  plugin.controllers.auth.register = async (ctx) => {
    const password = (ctx.request.body || {}).password;

    if (password !== undefined && !isStrongPassword(password)) {
      audit('user/register', clientInfo(ctx), { result: 'weak-password' });
      return ctx.badRequest(
        'Password must be at least 8 characters and include lowercase, uppercase and a number.'
      );
    }

    return originalRegister(ctx);
  };

  plugin.controllers.auth.changePassword = async (ctx) => {
    const body = ctx.request.body || {};
    const password = body.password;

    if (password !== undefined && !isStrongPassword(password)) {
      audit('user/change-password', clientInfo(ctx), { result: 'weak-password' });
      return ctx.badRequest(
        'Password must be at least 8 characters and include lowercase, uppercase and a number.'
      );
    }

    let previousChangedAt = 0;
    if (ctx.state.user) {
      previousChangedAt = await getPasswordChangedAt(ctx.state.user.id);
    }

    try {
      // Record the change BEFORE issuing the replacement token so the new JWT
      // (iat = now) stays valid while every older token is revoked. On failure
      // the recorded change is rolled back so no session is revoked.
      if (ctx.state.user) {
        await recordPasswordChange(ctx.state.user.id);
      }
      const result = await originalChangePassword(ctx);
      audit('user/change-password', clientInfo(ctx), { result: 'ok' });
      return result;
    } catch (err) {
      if (ctx.state.user) {
        await setPasswordChangedAt(ctx.state.user.id, previousChangedAt || null);
      }
      audit('user/change-password', clientInfo(ctx), { result: 'failed' });
      throw err;
    }
  };

  plugin.controllers.auth.forgotPassword = async (ctx) => {
    const user = await authenticate(ctx);

    if (!user) {
      audit('user/forgot', clientInfo(ctx), { result: 'auth-required' });
      return ctx.throw(401, 'You must be logged in to request a password reset.');
    }

    const { email } = ctx.request.body || {};
    const requestedEmail = (email || '').toLowerCase();
    const ownEmail = (user.email || '').toLowerCase();

    if (!requestedEmail || requestedEmail !== ownEmail) {
      audit('user/forgot', clientInfo(ctx), { email: requestedEmail, result: 'denied' });
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

    // The reset code is delivered out-of-band (email) — it must never appear in
    // the HTTP response.
    try {
      const from =
        strapi.config.get('plugin.email.settings.defaultFrom') || 'no-reply@localhost';
      const text = [
        'Password reset request',
        '',
        `Your verification code is:`,
        '',
        code,
        '',
        'It will expire in 15 minutes. Use it with POST /api/auth/reset-password.',
      ].join('\n');

      await strapi.plugin('email').service('email').send({
        from,
        to: user.email,
        replyTo: from,
        subject: 'Password reset request',
        text,
        html: text.replace(/\n/g, '<br/>'),
      });

      audit('user/forgot', clientInfo(ctx), { email: user.email, result: 'token-emailed' });
    } catch (err) {
      audit('user/forgot', clientInfo(ctx), { email: user.email, result: 'email-failed' });
      return ctx.throw(500, 'Could not send the reset email. Please try again later.');
    }

    ctx.send({ ok: true });
  };

  plugin.controllers.auth.resetPassword = async (ctx) => {
    const body = ctx.request.body || {};
    // tolerate URL-encoded codes copied from the reset email (link: %3A = ":")
    let code = typeof body.code === 'string' ? body.code.replace(/%3A/gi, ':').trim() : body.code;

    const user = await authenticate(ctx);

    if (!user) {
      audit('user/reset', clientInfo(ctx), { result: 'auth-required' });
      return ctx.throw(401, 'You must be logged in to reset your password.');
    }

    if (!isStrongPassword(body.password)) {
      audit('user/reset', clientInfo(ctx), { result: 'weak-password' });
      return ctx.badRequest(
        'Password must be at least 8 characters and include lowercase, uppercase and a number.'
      );
    }

    const sep = code ? code.indexOf(':') : -1;
    const expires = sep > 0 ? parseInt(code.slice(0, sep), 10) : NaN;

    if (!(expires && expires > Date.now())) {
      audit('user/reset', clientInfo(ctx), { result: 'invalid-or-expired' });
      return ctx.badRequest('Reset code is invalid or has expired.');
    }

    const hashed = sha256(code);
    const target = await strapi
      .query('plugin::users-permissions.user')
      .findOne({ where: { resetPasswordToken: hashed } });

    audit('user/reset', clientInfo(ctx), {
      result: target ? 'ok' : 'no-user',
      email: target ? target.email : undefined,
    });

    if (!target) {
      return ctx.badRequest('Reset code is invalid or has expired.');
    }

    if (target.id !== user.id) {
      audit('user/reset', clientInfo(ctx), { result: 'not-owner', email: target.email });
      return ctx.throw(403, 'You can only reset your own password.');
    }

    body.code = hashed;

    // Record the change BEFORE the original controller replaces the password and
    // issues the new JWT, so the freshly issued token (iat = now) stays valid
    // while every previously issued token is revoked. On failure the recorded
    // change is rolled back so no session is revoked.
    const previousChangedAt = await getPasswordChangedAt(user.id);
    await recordPasswordChange(user.id);

    try {
      const result = await originalResetPassword(ctx);
      return result;
    } catch (err) {
      await setPasswordChangedAt(user.id, previousChangedAt || null);
      audit('user/reset', clientInfo(ctx), { result: 'failed' });
      throw err;
    }
  };

  return plugin;
};