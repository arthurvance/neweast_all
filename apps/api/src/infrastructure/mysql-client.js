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

  const query = async (sql) => {
    const [results] = await connection.execute(sql);
    return results;
  };

  const ping = async () => {
    await connection.ping();
  };

  const close = () => {
    connection.end();
  };

  return {
    query,
    ping,
    close
  };
};

module.exports = { connectMySql };
