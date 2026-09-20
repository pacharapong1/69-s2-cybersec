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

// 1) services/auth.js - forgotPassword: TTL + store hash only + audit, still return the code (course flow)
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

  // (custom) TTL + audit: return the reset token to the client (course test flow), no email
  console.log(\`[audit][admin/forgot] email=\${email} at=\${new Date().toISOString()} ok\`);
  return code;
};`,
  },
]);

// 2) services/auth.js - resetPassword: validate TTL + lookup by hash + audit then reset
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
  // (custom) TTL check
  const sepIdx = resetPasswordToken && resetPasswordToken.indexOf(':');
  const expires = sepIdx > 0 ? parseInt(resetPasswordToken.slice(0, sepIdx), 10) : NaN;
  if (!(expires && expires > Date.now())) {
    console.log('[audit][admin/reset] invalid or expired token at=' + new Date().toISOString());
    throw new ApplicationError();
  }

  // (custom) lookup by the hash stored in the database
  const crypto = require('crypto');
  const hashedToken = crypto.createHash('sha256').update(resetPasswordToken).digest('hex');
  const matchingUser = await strapi
    .query('admin::user')
    .findOne({ where: { resetPasswordToken: hashedToken, isActive: true } });

  if (!matchingUser) {
    console.log('[audit][admin/reset] no user for token at=' + new Date().toISOString());
    throw new ApplicationError();
  }

  const updated = await getService('user').updateById(matchingUser.id, {
    password,
    resetPasswordToken: null,
  });

  console.log('[audit][admin/reset] ok email=' + matchingUser.email + ' at=' + new Date().toISOString());
  return updated;
};`,
  },
]);

// 3) controllers/authentication.js - forgotPassword: JWT gate + return the token in the response
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
      console.log('[audit][admin/forgot] denied email=' + requestedEmail + ' at=' + new Date().toISOString());
      ctx.throw(403, 'You can only request a password reset for your own account.');
    }

    const code = await getService('auth').forgotPassword(input);

    ctx.body = { ok: true, code };`,
  },
]);

// 4) routes/authentication.js - apply admin::rateLimit to forgot/reset password
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
      auth: { scope: ['admin'] },
      middlewares: ['admin::rateLimit'],
    },`,
  },
]);

// 5) controllers/authentication.js - audit admin login success/failure
patch('controllers/authentication.js', [
  {
    from: `        const sanitizedUser = getService('user').sanitizeUser(user);
        strapi.eventHub.emit('admin.auth.success', { user: sanitizedUser, provider: 'local' });

        return next();`,
    to: `        const sanitizedUser = getService('user').sanitizeUser(user);
        strapi.eventHub.emit('admin.auth.success', { user: sanitizedUser, provider: 'local' });
        console.log('[audit][admin/login] email=' + (user.email || '') + ' at=' + new Date().toISOString() + ' ok');

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
          console.log('[audit][admin/login] failed email=' + (((ctx.request.body || {}).email || '')).toLowerCase() + ' at=' + new Date().toISOString());
          throw new ApplicationError(info.message);`,
  },
]);

// 6) controllers/authenticated-user.js - audit admin change own password
patch('controllers/authenticated-user.js', [
  {
    from: `    const updatedUser = await userService.updateById(ctx.state.user.id, userInfo);`,
    to: `    const updatedUser = await userService.updateById(ctx.state.user.id, userInfo);

    if (userInfo.password) {
      console.log('[audit][admin/change-own-password] email=' + ctx.state.user.email + ' at=' + new Date().toISOString() + ' ok');
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

// 7) services/auth.js - account lockout on repeated failed logins
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
    to: `const loginFailures = new Map();
const LOGIN_MAX_FAILS = 5;
const LOGIN_LOCKOUT_MS = 15 * 60 * 1000;

const checkCredentials = async ({ email, password }) => {
  const lockKey = String(email || '').toLowerCase();

  const rec = loginFailures.get(lockKey);
  if (rec && rec.until > Date.now()) {
    console.log('[audit][admin/login] locked email=' + email + ' at=' + new Date().toISOString());
    return [null, false, { message: 'Too many login attempts. Please try again later.' }];
  }
  if (rec && rec.until <= Date.now()) {
    loginFailures.delete(lockKey);
  }

  const user = await strapi.query('admin::user').findOne({ where: { email } });

  if (!user || !user.password) {
    return [null, false, { message: 'Invalid credentials' }];
  }

  const isValid = await validatePassword(password, user.password);

  if (!isValid) {
    const count = (rec ? rec.count : 0) + 1;
    if (count >= LOGIN_MAX_FAILS) {
      loginFailures.set(lockKey, { count: 0, until: Date.now() + LOGIN_LOCKOUT_MS });
      console.log('[audit][admin/login] lockout email=' + email + ' at=' + new Date().toISOString());
    } else {
      loginFailures.set(lockKey, { count, until: 0 });
    }
    return [null, false, { message: 'Invalid credentials' }];
  }

  if (!(user.isActive === true)) {
    return [null, false, { message: 'User not active' }];
  }

  loginFailures.delete(lockKey);

  return [null, user];
};`,
  },
]);

// 8) routes/authentication.js - rate limit admin /renew-token
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

console.log('[patch] admin lockout + renew-token rate limit + same-password check added.');