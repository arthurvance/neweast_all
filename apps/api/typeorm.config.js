module.exports = {
  type: 'mysql',
  host: process.env.DB_HOST || 'mysql',
  port: Number(process.env.DB_PORT || '3306'),
  username: process.env.DB_USER || 'neweast',
  password: process.env.DB_PASSWORD || 'neweast',
  database: process.env.DB_NAME || 'neweast',
  migrations: ['apps/api/migrations/*.sql'],
  synchronize: false,
  logging: false
};
