'use strict';

const createSharedMemoryAuthStoreTestFaultInjectionRuntimeSupport = ({
  faultInjector = null
} = {}) => {
  const invokeFaultInjector = (hookName, payload = {}) => {
    if (!faultInjector || typeof faultInjector !== 'object') {
      return;
    }
    const hook = faultInjector[hookName];
    if (typeof hook === 'function') {
      hook(payload);
    }
  };

  return {
    invokeFaultInjector
  };
};

module.exports = {
  createSharedMemoryAuthStoreTestFaultInjectionRuntimeSupport
};
