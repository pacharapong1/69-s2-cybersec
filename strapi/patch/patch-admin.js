'use strict';

const fs = require('fs');
const path = require('path');

const ADM = '/opt/node_modules/@strapi/admin/server';

function patch(file, pairs) {
  const abs = path.join(ADM, file);
  let src = fs.readFileSync(abs, 'utf8');
  for (const { from, to } of pairs) {
    if (typeof from === 'string') {
      if (!src.includes(from)) {
        throw new Error(`[patch] string not found in ${file}: ${from.slice(0, 120)}`);
      }
      src = src.split(from).join(to);
    } else {
      if (!from.test(src)) {
        throw new Error(`[patch] regex not matched in ${file}: ${from}`);
      }
      src = src.replace(from, to);
    }
  }
  fs.writeFileSync(abs, src);
  console.log(`[patch] ok: ${file}`);
}

// ------------------------------------------------------------------
// 0) Shared: inject constant "audit" (durable JSONL logger) into the
//    files that will be patched below.
// ------------------------------------------------------------------
patch('services/auth.js', [
  {
    from: `const { getService } = require('../utils');`,
    to: `const { getService } = require('../utils');
const audit = require('/opt/app/src/audit');`,
  },
]);
patch('controllers/authentication.js', [
  {
    from: `const { getService } = require('../utils');`,
    to: `const { getService } = require('../utils');
const audit = require('/opt/app/src/audit');`,
  },
]);
patch('controllers/authenticated-user.js', [
  {
    from: `const { getService } = require('../utils');`,
    to: `const { getService } = require('../utils');
const audit = require('/opt/app/src/audit');`,
  },
]);
patch('strategies/admin.js', [
  {
    from: `const { getService } = require('../utils');`,
    to: `const { getService } = require('../utils');
const audit = require('/opt/app/src/audit');`,
  },
]);
patch('services/user.js', [
  {
    from: `const { getService } = require('../utils');`,
    to: `const { getService } = require('../utils');
const audit = require('/opt/app/src/audit');`,
  },
]);

// ------------------------------------------------------------------
// 1) services/auth.js - forgotPassword: TTL + store hash only + deliver
//    the code out-of-band by email (never in the HTTP response).
// ------------------------------------------------------------------
patch('services/auth.js', [
  {
    from: `  const resetPasswordToken = getService('token').createToken();
  await getService('user').updateById(user.id, { resetPasswordToken });

  // Send an email to the admin.
  const url = \`\${getAbsoluteAdminUrl(
    strapi.config
  )}/auth/reset-password?code=\${resetPasswordToken}\`;
  return strapi
    .plugin('email')
    .service('email')
    .sendTemplatedEmail(
      {
        to: user.email,
        from: strapi.config.get('admin.forgotPassword.from'),
        replyTo: strapi.config.get('admin.forgotPassword.replyTo'),
      },
      strapi.config.get('admin.forgotPassword.emailTemplate'),
      {
        url,
        user: _.pick(user, ['email', 'firstname', 'lastname', 'username']),
      }
    )
    .catch((err) => {
      // log error server side but do not disclose it to the user to avoid leaking informations
      strapi.log.error(err);
    });
};`,
    to: `  const resetPasswordToken = getService('token').createToken();
  const expiresAt = Date.now() + 15 * 60 * 1000;
  const crypto = require('crypto');
  const code = \`\${expiresAt}:\${resetPasswordToken}\`;

  // (custom) store only the hash of the code, never the plaintext value
  await getService('user').updateById(user.id, {
    resetPasswordToken: crypto.createHash('sha256').update(code).digest('hex'),
  });

  // (custom) TTL + deliver the reset code out-of-band by email (no code in the response)
  const url = \`\${getAbsoluteAdminUrl(
    strapi.config
  )}/auth/reset-password?code=\${encodeURIComponent(code)}\`;
  await strapi
    .plugin('email')
    .service('email')
    .sendTemplatedEmail(
      {
        to: user.email,
        from: strapi.config.get('admin.forgotPassword.from'),
        replyTo: strapi.config.get('admin.forgotPassword.replyTo'),
      },
      strapi.config.get('admin.forgotPassword.emailTemplate'),
      {
        url,
        user: _.pick(user, ['email', 'firstname', 'lastname', 'username']),
      }
    )
    .catch((err) => {
      // log error server side but do not disclose it to the user to avoid leaking informations
      strapi.log.error(err);
    });

  audit('admin/forgot', { email: user.email, result: 'token-issued' });
};`,
  },
]);

// ------------------------------------------------------------------
// 2) services/auth.js - resetPassword: validate TTL + lookup by hash + audit then reset
// ------------------------------------------------------------------
patch('services/auth.js', [
  {
    from: `const resetPassword = async ({ resetPasswordToken, password } = {}) => {
  const matchingUser = await strapi
    .query('admin::user')
    .findOne({ where: { resetPasswordToken, isActive: true } });

  if (!matchingUser) {
    throw new ApplicationError();
  }

  return getService('user').updateById(matchingUser.id, {
    password,
    resetPasswordToken: null,
  });
};`,
    to: `const resetPassword = async ({ resetPasswordToken, password } = {}) => {
  // (custom) tolerate URL-encoded codes copied from the reset email (link: %3A = ":")
  if (resetPasswordToken && typeof resetPasswordToken === 'string') {
    resetPasswordToken = resetPasswordToken.replace(/%3A/gi, ':').trim();
  }
  // (custom) TTL check
  const sepIdx = resetPasswordToken && resetPasswordToken.indexOf(':');
  const expires = sepIdx > 0 ? parseInt(resetPasswordToken.slice(0, sepIdx), 10) : NaN;
  if (!(expires && expires > Date.now())) {
    audit('admin/reset', { result: 'invalid-or-expired' });
    throw new ApplicationError();
  }

  // (custom) lookup by the hash stored in the database
  const crypto = require('crypto');
  const hashedToken = crypto.createHash('sha256').update(resetPasswordToken).digest('hex');
  const matchingUser = await strapi
    .query('admin::user')
    .findOne({ where: { resetPasswordToken: hashedToken, isActive: true } });

  if (!matchingUser) {
    audit('admin/reset', { result: 'no-user' });
    throw new ApplicationError();
  }

  const updated = await getService('user').updateById(matchingUser.id, {
    password,
    resetPasswordToken: null,
  });

  audit('admin/reset', { result: 'ok', email: matchingUser.email });
  return updated;
};`,
  },
]);

// ------------------------------------------------------------------
// 3) controllers/authentication.js - forgotPassword: JWT gate + own-email
//    check, then out-of-band email (no code in the response).
// ------------------------------------------------------------------
patch('controllers/authentication.js', [
  {
    from: `    getService('auth').forgotPassword(input);

    ctx.status = 204;`,
    to: `    // (custom) JWT gate: only the logged-in admin (Bearer from /admin/login)
    // can request a reset, and only for their own account.
    const operator = ctx.state.user;
    const requestedEmail = ((input && input.email) || '').toLowerCase();
    const ownEmail = operator && operator.email ? operator.email.toLowerCase() : '';

    if (!operator || !ownEmail || requestedEmail !== ownEmail) {
      audit('admin/forgot', { email: requestedEmail, ip: ctx.request.ip || 'unknown', result: 'denied' });
      ctx.throw(403, 'You can only request a password reset for your own account.');
    }

    await getService('auth').forgotPassword(input);

    audit('admin/forgot', { email: requestedEmail, ip: ctx.request.ip || 'unknown', result: 'ok' });
    ctx.status = 204;`,
  },
]);

// ------------------------------------------------------------------
// 4) routes/authentication.js - apply admin::rateLimit to forgot/reset password
// ------------------------------------------------------------------
patch('routes/authentication.js', [
  {
    from: `    path: '/forgot-password',
    handler: 'authentication.forgotPassword',
    config: { auth: false },`,
    to: `    path: '/forgot-password',
    handler: 'authentication.forgotPassword',
    config: {
      auth: { scope: ['admin'] },
      middlewares: ['admin::rateLimit'],
    },`,
  },
  {
    from: `    path: '/reset-password',
    handler: 'authentication.resetPassword',
    config: { auth: false },`,
    to: `    path: '/reset-password',
    handler: 'authentication.resetPassword',
    config: {
      auth: false,
      middlewares: ['admin::rateLimit'],
    },`,
  },
]);

// ------------------------------------------------------------------
// 5) controllers/authentication.js - audit admin login success/failure (with IP)
// ------------------------------------------------------------------
patch('controllers/authentication.js', [
  {
    from: `        const sanitizedUser = getService('user').sanitizeUser(user);
        strapi.eventHub.emit('admin.auth.success', { user: sanitizedUser, provider: 'local' });

        return next();`,
    to: `        const sanitizedUser = getService('user').sanitizeUser(user);
        strapi.eventHub.emit('admin.auth.success', { user: sanitizedUser, provider: 'local' });
        audit('admin/login', { email: (user.email || '').toLowerCase(), ip: ctx.request.ip || 'unknown', result: 'ok' });

        return next();`,
  },
  {
    from: `          strapi.eventHub.emit('admin.auth.error', {
            error: new Error(info.message),
            provider: 'local',
          });
          throw new ApplicationError(info.message);`,
    to: `          strapi.eventHub.emit('admin.auth.error', {
            error: new Error(info.message),
            provider: 'local',
          });
          audit('admin/login', {
            email: ((ctx.request.body || {}).email || '').toLowerCase(),
            ip: ctx.request.ip || 'unknown',
            result: 'failed',
          });
          throw new ApplicationError(info.message);`,
  },
]);

// ------------------------------------------------------------------
// 6) controllers/authenticated-user.js - audit admin change own password + same-password check
// ------------------------------------------------------------------
patch('controllers/authenticated-user.js', [
  {
    from: `    const updatedUser = await userService.updateById(ctx.state.user.id, userInfo);`,
    to: `    const updatedUser = await userService.updateById(ctx.state.user.id, userInfo);

    if (userInfo.password) {
      audit('admin/change-own-password', {
        email: ctx.state.user.email,
        ip: ctx.request.ip || 'unknown',
        result: 'ok',
      });
    }`,
  },
  {
    from: `    const { currentPassword, ...userInfo } = input;`,
    to: `    const { currentPassword, ...userInfo } = input;

    if (userInfo.password && currentPassword === userInfo.password) {
      return ctx.badRequest('ValidationError', {
        password: ['Your new password must be different than your current password'],
      });
    }`,
  },
]);

// ------------------------------------------------------------------
// 7) services/auth.js - account lockout on repeated failed logins (persisted in the DB)
// ------------------------------------------------------------------
patch('services/auth.js', [
  {
    from: `const checkCredentials = async ({ email, password }) => {
  const user = await strapi.query('admin::user').findOne({ where: { email } });

  if (!user || !user.password) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  const isValid = await validatePassword(password, user.password);

  if (!isValid) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  if (!(user.isActive === true)) {
    return [null, false, { message: 'User not active' }];
  }

  return [null, user];
};`,
    to: `const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;
const LOCKOUT_STORE_KEY = 'admin_login_lockouts';

const getAdminLockout = async (lockKey) => {
  const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
  const all = (await store.get({ key: LOCKOUT_STORE_KEY })) || {};
  return { store, all, rec: all[lockKey] || null };
};

const checkCredentials = async ({ email, password }) => {
  const lockKey = String(email || '').toLowerCase();

  const { store, all, rec } = await getAdminLockout(lockKey);

  if (rec && rec.until > Date.now()) {
    audit('admin/login', { email, result: 'locked' });
    return [null, false, { message: 'Too many login attempts. Please try again later.' }];
  }
  if (rec && rec.until <= Date.now()) {
    delete all[lockKey];
  }

  const user = await strapi.query('admin::user').findOne({ where: { email } });

  if (!user || !user.password) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  const isValid = await validatePassword(password, user.password);

  if (!isValid) {
    const count = (rec ? rec.count : 0) + 1;
    if (count >= LOGIN_MAX_FAILS) {
      all[lockKey] = { count: 0, until: Date.now() + LOGIN_LOCKOUT_MS };
      await store.set({ key: LOCKOUT_STORE_KEY, value: all });
      audit('admin/login', { email, result: 'lockout' });
    } else {
      all[lockKey] = { count, until: 0 };
      await store.set({ key: LOCKOUT_STORE_KEY, value: all });
    }
    return [null, false, { message: 'Invalid credentials' }];
  }

  if (!(user.isActive === true)) {
    return [null, false, { message: 'User not active' }];
  }

  delete all[lockKey];
  await store.set({ key: LOCKOUT_STORE_KEY, value: all });

  return [null, user];
};`,
  },
]);

// ------------------------------------------------------------------
// 8) services/user.js - record a password-changed timestamp whenever a new
//    password is stored so previously issued admin JWTs are revoked.
// ------------------------------------------------------------------
patch('services/user.js', [
  {
    from: `  // hash password if a new one is sent
  if (_.has(attributes, 'password')) {
    const hashedPassword = await getService('auth').hashPassword(attributes.password);

    const updatedUser = await strapi.query('admin::user').update({
      where: { id },
      data: {
        ...attributes,
        password: hashedPassword,
      },
      populate: ['roles'],
    });

    strapi.eventHub.emit('user.update', { user: sanitizeUser(updatedUser) });

    return updatedUser;
  }`,
    to: `  // hash password if a new one is sent
  if (_.has(attributes, 'password')) {
    const hashedPassword = await getService('auth').hashPassword(attributes.password);

    const updatedUser = await strapi.query('admin::user').update({
      where: { id },
      data: {
        ...attributes,
        password: hashedPassword,
      },
      populate: ['roles'],
    });

    strapi.eventHub.emit('user.update', { user: sanitizeUser(updatedUser) });

    // (custom) invalidate every previously issued JWT for this user
    const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
    const pwdAll = (await store.get({ key: 'admin_password_changed' })) || {};
    pwdAll[id] = Date.now();
    await store.set({ key: 'admin_password_changed', value: pwdAll });

    audit('admin/password-changed', { userId: id, result: 'ok' });

    return updatedUser;
  }`,
  },
]);

// ------------------------------------------------------------------
// 9) strategies/admin.js - reject admin JWTs issued before the last password change
// ------------------------------------------------------------------
patch('strategies/admin.js', [
  {
    from: `  if (!user || !(user.isActive === true)) {
    return { authenticated: false };
  }

  const userAbility = await getService('permission').engine.generateUserAbility(user);`,
    to: `  if (!user || !(user.isActive === true)) {
    return { authenticated: false };
  }

  // (custom) session revocation: tokens issued before the last password change
  // are no longer accepted
  const store = strapi.store({ type: 'plugin', name: 'users-permissions' });
  const pwdAll = (await store.get({ key: 'admin_password_changed' })) || {};
  const changedAt = pwdAll[payload.id] || 0;
  if (payload.iat && Number(payload.iat) < Math.floor(changedAt / 1000)) {
    return { authenticated: false };
  }

  const userAbility = await getService('permission').engine.generateUserAbility(user);`,
  },
]);

// ------------------------------------------------------------------
// 10) routes/authentication.js - rate limit admin /renew-token
// ------------------------------------------------------------------
patch('routes/authentication.js', [
  {
    from: `    path: '/renew-token',
    handler: 'authentication.renewToken',
    config: { auth: false },`,
    to: `    path: '/renew-token',
    handler: 'authentication.renewToken',
    config: {
      auth: false,
      middlewares: ['admin::rateLimit'],
    },`,
  },
]);

console.log('[patch] admin: email-based reset, durable lockout, session revocation, audit added.');