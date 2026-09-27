'use strict';

// Build-time patch for @strapi/plugin-users-permissions content-api strategy:
// reject JWTs that were issued before the user's last password change
// (session revocation). The plugin registers this strategy directly from its
// own module in server/register.js, so it can't be replaced from a Strapi 4
// extension - we patch the file at build time instead.

const fs = require('fs');

const STRATEGY = '/opt/node_modules/@strapi/plugin-users-permissions/server/strategies/users-permissions.js';

let src = fs.readFileSync(STRATEGY, 'utf8');

const from = `      // Generate an ability (content API engine) based on the given permissions`;
const to = `      // (custom) session revocation: token issued before the last password change
      // is rejected so the old session is invalidated immediately.
      const pwc =
        (await strapi
          .store({ type: 'plugin', name: 'users-permissions' })
          .get({ key: 'password_changed_store' })) || {};
      const changedAt = pwc[user.id] || 0;
      if (changedAt && token.iat && Number(token.iat) < Math.floor(changedAt / 1000)) {
        return { authenticated: false };
      }

      // Generate an ability (content API engine) based on the given permissions`;

if (!src.includes(from)) {
  throw new Error(`[patch] strategy anchor not found in users-permissions.js`);
}

src = src.split(from).join(to);
fs.writeFileSync(STRATEGY, src);
console.log('[patch] ok: users-permissions strategy (session revocation)');