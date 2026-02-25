'use strict';

const { authPing, createAuthHandlers } = require('../../modules/auth/auth.routes');
const { createAuthRouteHandlers } = require('../../modules/auth/auth.handlers');

module.exports = {
  authPing,
  createAuthHandlers,
  createAuthRouteHandlers
};
