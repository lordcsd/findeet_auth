export const configConstants = {
  database: {
    type: 'DATABASE_TYPE',
    host: 'DATABASE_HOST',
    port: 'DATABASE_PORT',
    username: 'DATABASE_USERNAME',
    name: 'DATABASE_NAME',
    password: 'DATABASE_PASSWORD',
  },
  jwt: { secret: 'JWT_SECRET' },
  bcrypt: { salt: 'BCRYPT_SALT' },
  googleAuth: {
    clientId: 'GOOGLE_AUTH_CLIENT_ID',
    clientSecret: 'GOOGLE_AUTH_CLIENT_SECRET',
  },
  mailjet: {
    apiKey: 'MAIL_JET_API_KEY',
    apiSecret: 'MAIL_JET_API_SECRET',
  },
  email: { source: 'EMAIL_SOURCE' },
  rabbitMQ: {
    url: 'RABBITMQ_URL',
  },
  service: { root: 'ROOT' },
};
