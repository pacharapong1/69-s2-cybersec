module.exports = {
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
};