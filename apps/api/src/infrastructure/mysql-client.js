const mysql = require('mysql2/promise');

const connectMySql = async ({ host, port, user, password, database, connectTimeoutMs = 1500 }) => {
  const connection = await mysql.createConnection({
    host,
    port,
    user,
    password,
    database,
    connectTimeout: connectTimeoutMs
  });

  const query = async (sql, params = []) => {
    // Use text protocol with parameter escaping to support LIMIT/OFFSET placeholders
    // across MySQL variants where server-side prepared statements reject them.
    const [results] = await connection.query(sql, params);
    return results;
  };

  const ping = async () => {
    await connection.ping();
  };

  const close = async () => {
    let timer = null;
    try {
      await Promise.race([
        connection.end(),
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(new Error('mysql close timeout')), 3000);
        })
      ]);
    } catch (_error) {
      if (typeof connection.destroy === 'function') {
        connection.destroy();
      }
    } finally {
      if (timer) {
        clearTimeout(timer);
      }
    }
  };

  const inTransaction = async (work) => {
    if (typeof work !== 'function') {
      throw new Error('inTransaction requires a callback');
    }

    await connection.beginTransaction();
    const tx = {
      query: async (sql, params = []) => {
        // Keep transaction behavior aligned with top-level query() for LIMIT/OFFSET support.
        const [results] = await connection.query(sql, params);
        return results;
      }
    };

    try {
      const result = await work(tx);
      await connection.commit();
      return result;
    } catch (error) {
      try {
        await connection.rollback();
      } catch (_rollbackError) {
      }
      throw error;
    }
  };

  return {
    query,
    ping,
    inTransaction,
    close
  };
};

module.exports = { connectMySql };
