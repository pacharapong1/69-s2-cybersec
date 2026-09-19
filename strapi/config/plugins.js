module.exports = {
  'users-permissions': {
    config: {
      ratelimit: {
        enabled: true,
        interval: 60000,
        max: 10,
      },
    },
  },
};