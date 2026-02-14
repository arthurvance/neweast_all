export const createLatestRequestExecutor = () => {
  let latestRequestId = 0;

  return {
    async run(requestFactory, applyResult, options = {}) {
      latestRequestId += 1;
      const requestId = latestRequestId;
      const isResultCurrent =
        typeof options.isResultCurrent === 'function'
          ? options.isResultCurrent
          : null;

      try {
        const result = await requestFactory();
        if (requestId !== latestRequestId) {
          return undefined;
        }
        if (isResultCurrent && !isResultCurrent(result)) {
          return undefined;
        }
        if (typeof applyResult === 'function') {
          applyResult(result);
        }
        return result;
      } catch (error) {
        if (requestId !== latestRequestId) {
          return undefined;
        }
        throw error;
      }
    }
  };
};
