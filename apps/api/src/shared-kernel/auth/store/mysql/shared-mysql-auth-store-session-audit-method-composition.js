'use strict';

const createSharedMysqlAuthStoreSessionAuditMethodComposition = ({
  listAuditEvents,
  recordAuditEvent,
  repositoryMethods
} = {}) => ({
  findUserByPhone: repositoryMethods.findUserByPhone,
  findUserById: repositoryMethods.findUserById,
  updateUserPhone: repositoryMethods.updateUserPhone,

  recordAuditEvent: async (payload = {}) => recordAuditEvent(payload),
  listAuditEvents: async (query = {}) => listAuditEvents(query),

  createSession: repositoryMethods.createSession,
  findSessionById: repositoryMethods.findSessionById,
  updateSessionContext: repositoryMethods.updateSessionContext,
  findDomainAccessByUserId: repositoryMethods.findDomainAccessByUserId,
  ensureDefaultDomainAccessForUser: repositoryMethods.ensureDefaultDomainAccessForUser,
  revokeSession: repositoryMethods.revokeSession,
  revokeAllUserSessions: repositoryMethods.revokeAllUserSessions,
  createRefreshToken: repositoryMethods.createRefreshToken,
  findRefreshTokenByHash: repositoryMethods.findRefreshTokenByHash,
  markRefreshTokenStatus: repositoryMethods.markRefreshTokenStatus,
  linkRefreshRotation: repositoryMethods.linkRefreshRotation,
  rotateRefreshToken: repositoryMethods.rotateRefreshToken,
  updateUserPasswordAndBumpSessionVersion:
    repositoryMethods.updateUserPasswordAndBumpSessionVersion,
  updateUserPasswordAndRevokeSessions:
    repositoryMethods.updateUserPasswordAndRevokeSessions
});

module.exports = {
  createSharedMysqlAuthStoreSessionAuditMethodComposition
};
