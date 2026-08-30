import pino from 'pino';
import { config } from '../config/index.js';

export const logger = pino({
  level: config.NODE_ENV === 'development' ? 'debug' : 'info',
  base: config.NODE_ENV === 'production' ? { service: 'wpa-auth-api' } : undefined,
  transport: config.NODE_ENV === 'development'
    ? {
        target: 'pino-pretty',
        options: {
          colorize: true,
          translateTime: 'SYS:HH:MM:ss.l',
          levelFirst: true,
          singleLine: false,
          ignore: 'pid,hostname,service',
          messageFormat: '[wpa-auth-api] {msg}'
        },
      }
    : undefined,
});
