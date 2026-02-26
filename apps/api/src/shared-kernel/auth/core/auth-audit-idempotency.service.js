'use strict';

const createAuthAuditIdempotencyService = ({ authService } = {}) => {
  if (!authService || typeof authService !== 'object') {
    throw new Error('createAuthAuditIdempotencyService requires authService');
  }

  if (typeof authService.listAuditEvents !== 'function') {
    throw new Error('authService.listAuditEvents is required');
  }
  if (typeof authService.recordIdempotencyEvent !== 'function') {
    throw new Error('authService.recordIdempotencyEvent is required');
  }

  return {
    listAuditEvents: (...args) => authService.listAuditEvents(...args),
    recordIdempotencyEvent: (...args) => authService.recordIdempotencyEvent(...args)
  };
};

module.exports = {
  createAuthAuditIdempotencyService
};
