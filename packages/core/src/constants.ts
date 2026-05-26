// Cross-cutting timeouts and retry settings.
// Detector-specific thresholds (similarity, heuristic weights, age cutoffs)
// stay inside their detector — those encode that detector's policy and
// shouldn't be touched globally.

// Per-request HTTP timeout for short calls (e.g. block-explorer ABI lookup).
// Kept tight so a slow API never blocks transaction analysis.
export const HTTP_TIMEOUT_MS = 3000

// History-fetch timeout — longer because we paginate large lists.
export const HISTORY_FETCH_TIMEOUT_MS = 8000

// Default retry/backoff for HTTP calls.
export const HTTP_RETRIES = 2
export const HTTP_RETRY_DELAY_MS = 1000
