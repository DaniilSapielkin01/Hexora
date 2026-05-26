// Opt-in observability. Hexora silently swallows recoverable errors
// (rate limits, unverified contracts, network blips) so a single bad
// network call doesn't break the user's app. The downside: when something
// is actually wrong (invalid API key, persistent 5xx) users get empty
// results with no signal.
//
// Pattern: inject a logger via setLogger() and we'll emit structured events
// at every catch site. Default is a no-op so library usage stays zero-cost.

export type LogLevel = "debug" | "info" | "warn" | "error"

export interface LogEvent {
  level:   LogLevel
  source:  string                  // e.g. "abiDecoder", "historyFetcher"
  message: string
  context?: Record<string, unknown>
}

export interface Logger {
  log(event: LogEvent): void
}

const NOOP: Logger = { log: () => {} }
let active: Logger = NOOP

export function setLogger(logger: Logger | null): void {
  active = logger ?? NOOP
}

export function getLogger(): Logger {
  return active
}

// Convenience helper — keeps call sites short.
export function logEvent(
  level:   LogLevel,
  source:  string,
  message: string,
  context?: Record<string, unknown>,
): void {
  const event: LogEvent = { level, source, message }
  if (context) event.context = context
  active.log(event)
}
