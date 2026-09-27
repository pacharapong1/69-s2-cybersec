module.exports = ({ env }) => ({
  email: {
    config: {
      provider: 'sendmail',
      providerOptions: {
        devHost: env('EMAIL_PROVIDER_DEV_HOST', 'mail'),
        devPort: env.int('EMAIL_PROVIDER_DEV_PORT', 1025),
        silent: true,
      },
      settings: {
        defaultFrom: env('EMAIL_DEFAULT_FROM', 'no-reply@localhost'),
        defaultReplyTo: env('EMAIL_DEFAULT_FROM', 'no-reply@localhost'),
      },
    },
  },
  'users-permissions': {
    config: {
      jwt: {
        expiresIn: '1d',
      },
      ratelimit: {
        enabled: true,
        interval: 60000,
        max: 10,
      },
    },
  },
});