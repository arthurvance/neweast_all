'use strict';

const createSharedMemoryAuthStoreRepositoryUserIdentityGovernance = ({
  clone,
  usersByPhone,
  usersById,
  MAINLAND_PHONE_PATTERN,
  CONTROL_CHAR_PATTERN
} = {}) => ({
  findUserByPhone: async (phone) => clone(usersByPhone.get(phone) || null),

  findUserById: async (userId) => clone(usersById.get(String(userId)) || null),

  updateUserPhone: async ({
    userId,
    phone
  } = {}) => {
    const normalizedUserId = String(userId || '').trim();
    const normalizedPhone = String(phone || '').trim();
    if (
      !normalizedUserId
      || !normalizedPhone
      || !MAINLAND_PHONE_PATTERN.test(normalizedPhone)
      || CONTROL_CHAR_PATTERN.test(normalizedPhone)
    ) {
      throw new Error('updateUserPhone requires valid userId and mainland phone');
    }

    const existingUser = usersById.get(normalizedUserId);
    if (!existingUser) {
      return {
        reason: 'invalid-user-id'
      };
    }
    if (String(existingUser.phone || '').trim() === normalizedPhone) {
      return {
        reason: 'no-op',
        user_id: normalizedUserId,
        phone: normalizedPhone
      };
    }

    const phoneOwner = usersByPhone.get(normalizedPhone);
    if (
      phoneOwner
      && String(phoneOwner.id || '').trim() !== normalizedUserId
    ) {
      return {
        reason: 'phone-conflict'
      };
    }

    usersByPhone.delete(String(existingUser.phone || '').trim());
    const updatedUser = {
      ...existingUser,
      phone: normalizedPhone
    };
    usersById.set(normalizedUserId, updatedUser);
    usersByPhone.set(normalizedPhone, updatedUser);
    return {
      reason: 'ok',
      user_id: normalizedUserId,
      phone: normalizedPhone
    };
  },
});

module.exports = {
  createSharedMemoryAuthStoreRepositoryUserIdentityGovernance
};
