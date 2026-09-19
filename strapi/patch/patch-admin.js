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

// 1) services/auth.js - forgotPassword: add TTL + audit, keep returning the token (course flow)
patch('services/auth.js', [
  {
    from: `  const resetPasswordToken = getService('token').createToken();`,
    to: `  const resetPasswordToken = getService('token').createToken();
  const expiresAt = Date.now() + 15 * 60 * 1000;`,
  },
  {
    from: `  await getService('user').updateById(user.id, { resetPasswordToken });

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
    to: `  await getService('user').updateById(user.id, {
    resetPasswordToken: \`\${expiresAt}:\${resetPasswordToken}\`,
  });

  // (custom) TTL + audit: return the reset token to the client (course test flow), no email
  console.log(\`[audit][admin/forgot] email=\${email} at=\${new Date().toISOString()} ok\`);
  return \`\${expiresAt}:\${resetPasswordToken}\`;
};`,
  },
]);

// 2) services/auth.js - resetPassword: validate TTL + audit then reset
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

  const matchingUser = await strapi
    .query('admin::user')
    .findOne({ where: { resetPasswordToken, isActive: true } });

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

// 3) controllers/authentication.js - forgotPassword: return the token in the response
patch('controllers/authentication.js', [
  {
    from: `    getService('auth').forgotPassword(input);

    ctx.status = 204;`,
    to: `    const code = await getService('auth').forgotPassword(input);

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
      auth: false,
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

console.log('[patch] admin forgot/reset now enforces TTL + audit + rate limit and returns the reset token.');