type CounterKey =
  | 'requests_total'
  | 'errors_total'
  | 'login_success_total'
  | 'login_failure_total'
  | 'refresh_token_reuse_total'
  | 'rate_limit_block_total'
  | 'otp_send_total'
  | 'otp_failure_total'
  | 'email_send_total'
  | 'email_failure_total'
  | 'sms_send_total'
  | 'sms_failure_total'
  | 'provider_health_check_total';

type HistogramBucket = 'lt_50ms' | 'lt_100ms' | 'lt_250ms' | 'lt_500ms' | 'lt_1000ms' | 'gte_1000ms';

type MetricsSnapshot = {
  counters: Record<CounterKey, number>;
  latency: Record<HistogramBucket, number>;
  lastHealth: {
    redis: 'UP' | 'DOWN' | 'UNKNOWN';
    postgres: 'UP' | 'DOWN' | 'UNKNOWN';
    updatedAt: string | null;
  };
};

const counters: MetricsSnapshot['counters'] = {
  requests_total: 0,
  errors_total: 0,
  login_success_total: 0,
  login_failure_total: 0,
  refresh_token_reuse_total: 0,
  rate_limit_block_total: 0,
  otp_send_total: 0,
  otp_failure_total: 0,
  email_send_total: 0,
  email_failure_total: 0,
  sms_send_total: 0,
  sms_failure_total: 0,
  provider_health_check_total: 0,
};

const latency: MetricsSnapshot['latency'] = {
  lt_50ms: 0,
  lt_100ms: 0,
  lt_250ms: 0,
  lt_500ms: 0,
  lt_1000ms: 0,
  gte_1000ms: 0,
};

const lastHealth: MetricsSnapshot['lastHealth'] = {
  redis: 'UNKNOWN',
  postgres: 'UNKNOWN',
  updatedAt: null,
};

export function recordRequestLatency(durationMs: number) {
  if (durationMs < 50) latency.lt_50ms += 1;
  else if (durationMs < 100) latency.lt_100ms += 1;
  else if (durationMs < 250) latency.lt_250ms += 1;
  else if (durationMs < 500) latency.lt_500ms += 1;
  else if (durationMs < 1000) latency.lt_1000ms += 1;
  else latency.gte_1000ms += 1;
}

export function incrementMetric(key: CounterKey, amount = 1) {
  counters[key] += amount;
}

export function updateHealthStatus(next: Partial<MetricsSnapshot['lastHealth']>) {
  if (next.redis) lastHealth.redis = next.redis;
  if (next.postgres) lastHealth.postgres = next.postgres;
  lastHealth.updatedAt = new Date().toISOString();
}

export function getMetricsSnapshot(): MetricsSnapshot {
  return {
    counters: { ...counters },
    latency: { ...latency },
    lastHealth: { ...lastHealth },
  };
}

export function renderPrometheusMetrics(): string {
  const snapshot = getMetricsSnapshot();
  return [
    '# HELP wpa_requests_total Total HTTP requests observed',
    '# TYPE wpa_requests_total counter',
    `wpa_requests_total ${snapshot.counters.requests_total}`,
    '# HELP wpa_errors_total Total API errors observed',
    '# TYPE wpa_errors_total counter',
    `wpa_errors_total ${snapshot.counters.errors_total}`,
    '# HELP wpa_login_success_total Successful logins',
    '# TYPE wpa_login_success_total counter',
    `wpa_login_success_total ${snapshot.counters.login_success_total}`,
    '# HELP wpa_login_failure_total Failed logins',
    '# TYPE wpa_login_failure_total counter',
    `wpa_login_failure_total ${snapshot.counters.login_failure_total}`,
    '# HELP wpa_refresh_token_reuse_total Refresh token reuse detections',
    '# TYPE wpa_refresh_token_reuse_total counter',
    `wpa_refresh_token_reuse_total ${snapshot.counters.refresh_token_reuse_total}`,
    '# HELP wpa_rate_limit_block_total Rate-limit blocks',
    '# TYPE wpa_rate_limit_block_total counter',
    `wpa_rate_limit_block_total ${snapshot.counters.rate_limit_block_total}`,
    '# HELP wpa_request_latency_bucket Request latency buckets',
    '# TYPE wpa_request_latency_bucket counter',
    `wpa_request_latency_bucket{le="50"} ${snapshot.latency.lt_50ms}`,
    `wpa_request_latency_bucket{le="100"} ${snapshot.latency.lt_100ms}`,
    `wpa_request_latency_bucket{le="250"} ${snapshot.latency.lt_250ms}`,
    `wpa_request_latency_bucket{le="500"} ${snapshot.latency.lt_500ms}`,
    `wpa_request_latency_bucket{le="1000"} ${snapshot.latency.lt_1000ms}`,
    `wpa_request_latency_bucket{le="+Inf"} ${snapshot.latency.gte_1000ms}`,
  ].join('\n');
}
