'use strict';

const createSharedMemoryAuthStoreEntityRecordCloneRuntimeSupport = () => {
  const clone = (value) => (value ? { ...value } : null);

  return {
    clone
  };
};

module.exports = {
  createSharedMemoryAuthStoreEntityRecordCloneRuntimeSupport
};
