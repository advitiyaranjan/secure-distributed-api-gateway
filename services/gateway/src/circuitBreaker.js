// Per-upstream circuit breaker. After `failureThreshold` consecutive failures the
// circuit opens and requests fail fast with 503 instead of piling up on a dead
// backend. After `resetTimeoutMs` a single trial request is let through
// (half-open); success closes the circuit, failure re-opens it.

export class CircuitBreaker {
  constructor({ name, failureThreshold = 5, resetTimeoutMs = 10_000, logger } = {}) {
    Object.assign(this, { name, failureThreshold, resetTimeoutMs, logger });
    this.state = 'closed';
    this.failures = 0;
    this.openedAt = 0;
    this.trialInFlight = false;
  }

  canRequest(now = Date.now()) {
    if (this.state === 'closed') return true;
    if (this.state === 'open' && now - this.openedAt >= this.resetTimeoutMs) {
      this.state = 'half-open';
      this.trialInFlight = false;
    }
    if (this.state === 'half-open' && !this.trialInFlight) {
      this.trialInFlight = true;
      return true;
    }
    return false;
  }

  onSuccess() {
    if (this.state !== 'closed') this.logger?.info('circuit closed', { upstream: this.name });
    this.state = 'closed';
    this.failures = 0;
    this.trialInFlight = false;
  }

  onFailure(now = Date.now()) {
    this.failures += 1;
    this.trialInFlight = false;
    if (this.state === 'half-open' || this.failures >= this.failureThreshold) {
      if (this.state !== 'open') this.logger?.warn('circuit opened', { upstream: this.name, failures: this.failures });
      this.state = 'open';
      this.openedAt = now;
    }
  }
}
