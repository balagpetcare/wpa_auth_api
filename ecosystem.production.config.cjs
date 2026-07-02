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
      },
      out_file: './logs/wpa-auth-api.out.log',
      error_file: './logs/wpa-auth-api.error.log',
      merge_logs: true,
      time: true,
    },
  ],
};
