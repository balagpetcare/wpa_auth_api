// PM2 production process manager config for WPA Central Auth API.
//
// This file intentionally contains NO secrets. Environment variables
// (DATABASE_URL, JWT_ACCESS_SECRET, JWT_REFRESH_SECRET, CREDENTIAL_ENCRYPTION_KEY,
// REDIS_URL, SMTP_*, etc.) must be provided by the deployment process — e.g. a
// real `.env` file loaded via `dotenv`/`node --env-file`, a systemd
// EnvironmentFile, a secrets manager injecting process env vars, or PM2's own
// `env_file` support (see commented-out example below). Do NOT hardcode
// secrets in this file or commit a populated .env to source control.
//
// Usage:
//   pm2 start ecosystem.production.config.cjs --env production
//   pm2 status
//   pm2 logs wpa-auth-api
//   pm2 reload wpa-auth-api   (zero-downtime reload)
//   pm2 logs wpa-auth-communication-worker
//   pm2 reload wpa-auth-communication-worker
//
// Before starting, make sure the app has been built:
//   npm run build

module.exports = {
  apps: [
    {
      name: 'wpa-auth-api',
      script: 'dist/server.js',
      // `npm run start` runs `node dist/server.js` — invoking the built file
      // directly (as above) avoids an extra npm wrapper process under PM2.
      // If you prefer to go through npm instead, use:
      //   script: 'npm',
      //   args: 'run start',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      // Uncomment to load environment variables from a file PM2 manages itself.
      // Requires PM2 >= 5 with the `env_file` plugin/feature or a wrapper script;
      // otherwise ensure the environment is already populated in the shell/
      // process manager that launches PM2 (e.g. systemd EnvironmentFile=).
      // env_file: '.env',
      env: {
        NODE_ENV: 'production',
        // Communication abuse protection (src/lib/antiAbuse.ts). Non-secret
        // tuning values — safe to keep here; real secrets stay in the
        // deployment-managed .env. See .env.production.example for details.
        COMMUNICATION_RATE_LIMIT_ENABLED: 'true',
        COMMUNICATION_MAX_SMS_PER_PHONE_PER_HOUR: '5',
        COMMUNICATION_MAX_SMS_PER_PHONE_PER_DAY: '10',
        COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_HOUR: '5',
        COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_DAY: '10',
        COMMUNICATION_MAX_PROVIDER_TEST_PER_ADMIN_HOUR: '10',
        COMMUNICATION_MAX_BULK_RETRY_COUNT: '50',
        COMMUNICATION_SYSTEM_SMS_HOURLY_CAP: '200',
        COMMUNICATION_SYSTEM_SMS_DAILY_CAP: '2000',
        COMMUNICATION_SYSTEM_EMAIL_HOURLY_CAP: '1000',
        COMMUNICATION_SYSTEM_EMAIL_DAILY_CAP: '10000',
      },
      out_file: './logs/wpa-auth-api.out.log',
      error_file: './logs/wpa-auth-api.error.log',
      merge_logs: true,
      time: true,
    },
    {
      name: 'wpa-auth-communication-worker',
      script: 'npm',
      args: 'run worker:communication',
      cwd: __dirname,
      instances: 1,
      exec_mode: 'fork',
      autorestart: true,
      watch: false,
      max_memory_restart: '512M',
      env: {
        NODE_ENV: 'production',
        COMMUNICATION_RETRY_WORKER_ENABLED: 'true',
        // Same abuse-protection tuning as wpa-auth-api above — the retry
        // worker calls the same gate (via executeRetry) before every retry
        // attempt, so both processes must agree on these values. Keep in
        // sync with the wpa-auth-api app block above.
        COMMUNICATION_RATE_LIMIT_ENABLED: 'true',
        COMMUNICATION_MAX_SMS_PER_PHONE_PER_HOUR: '5',
        COMMUNICATION_MAX_SMS_PER_PHONE_PER_DAY: '10',
        COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_HOUR: '5',
        COMMUNICATION_MAX_EMAIL_PER_ADDRESS_PER_DAY: '10',
        COMMUNICATION_MAX_PROVIDER_TEST_PER_ADMIN_HOUR: '10',
        COMMUNICATION_MAX_BULK_RETRY_COUNT: '50',
        COMMUNICATION_SYSTEM_SMS_HOURLY_CAP: '200',
        COMMUNICATION_SYSTEM_SMS_DAILY_CAP: '2000',
        COMMUNICATION_SYSTEM_EMAIL_HOURLY_CAP: '1000',
        COMMUNICATION_SYSTEM_EMAIL_DAILY_CAP: '10000',
      },
      out_file: './logs/wpa-auth-communication-worker.out.log',
      error_file: './logs/wpa-auth-communication-worker.error.log',
      merge_logs: true,
      time: true,
    },
  ],
};
