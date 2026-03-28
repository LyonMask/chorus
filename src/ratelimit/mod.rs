//! Rate Limiter — Walkie Talkie v4 Platform Layer
//!
//! Token-bucket rate limiter keyed by (tenant_id, agent_id).

use std::collections::HashMap;
use std::sync::RwLock;
use std::time::Instant;

// ─── Token Bucket ───────────────────────────────────────────────

#[derive(Debug)]
struct Bucket {
    tokens: f64,
    max_tokens: f64,
    rate: f64,
    last_refill: Instant,
}

impl Bucket {
    fn new(rate: u32, burst: u32) -> Self {
        Self { tokens: burst as f64, max_tokens: burst as f64, rate: rate as f64, last_refill: Instant::now() }
    }

    fn try_acquire(&mut self, cost: u32) -> bool {
        self.refill();
        let cost = cost as f64;
        if self.tokens >= cost { self.tokens -= cost; true } else { false }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.max_tokens);
        self.last_refill = Instant::now();
    }

    fn available(&self) -> f64 {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        (self.tokens + elapsed * self.rate).min(self.max_tokens)
    }
}

// ─── Rate Limiter ───────────────────────────────────────────────

#[derive(Debug)]
pub struct RateLimiter {
    buckets: RwLock<HashMap<String, Bucket>>,
    default_rate: u32,
    default_burst: u32,
}

impl RateLimiter {
    pub fn new(rate: u32, burst: u32) -> Self {
        Self { buckets: RwLock::new(HashMap::new()), default_rate: rate, default_burst: burst }
    }

    pub fn make_key(tenant_id: &str, agent_id: &str) -> String {
        format!("{}:{}", tenant_id, agent_id)
    }

    pub fn try_acquire(&self, tenant_id: &str, agent_id: &str, cost: u32) -> bool {
        let key = Self::make_key(tenant_id, agent_id);
        let mut buckets = self.buckets.write().unwrap();
        let bucket = buckets.entry(key).or_insert_with(|| Bucket::new(self.default_rate, self.default_burst));
        bucket.try_acquire(cost)
    }

    pub fn set_rate(&self, tenant_id: &str, agent_id: &str, rate: u32, burst: u32) {
        let key = Self::make_key(tenant_id, agent_id);
        self.buckets.write().unwrap().insert(key, Bucket::new(rate, burst));
    }

    pub fn set_tenant_rate(&self, tenant_id: &str, rate: u32, burst: u32) {
        let prefix = format!("{}:", tenant_id);
        let mut buckets = self.buckets.write().unwrap();
        for (key, bucket) in buckets.iter_mut() {
            if key.starts_with(&prefix) {
                bucket.rate = rate as f64;
                bucket.max_tokens = burst as f64;
            }
        }
    }

    pub fn available_tokens(&self, tenant_id: &str, agent_id: &str) -> f64 {
        let key = Self::make_key(tenant_id, agent_id);
        let buckets = self.buckets.read().unwrap();
        match buckets.get(&key) {
            Some(b) => b.available(),
            None => self.default_burst as f64,
        }
    }

    pub fn reset(&self, tenant_id: &str, agent_id: &str) {
        let key = Self::make_key(tenant_id, agent_id);
        self.buckets.write().unwrap().remove(&key);
    }

    pub fn bucket_count(&self) -> usize {
        self.buckets.read().unwrap().len()
    }
}

// ─── Tests ──────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_acquire() {
        let limiter = RateLimiter::new(5, 10);
        for _ in 0..10 { assert!(limiter.try_acquire("t1", "a1", 1)); }
        assert!(!limiter.try_acquire("t1", "a1", 1));
    }

    #[test]
    fn test_separate_keys() {
        let limiter = RateLimiter::new(5, 10);
        for _ in 0..10 { limiter.try_acquire("t1", "a1", 1); }
        assert!(!limiter.try_acquire("t1", "a1", 1));
        assert!(limiter.try_acquire("t1", "a2", 1)); // different key
    }

    #[test]
    fn test_cost() {
        let limiter = RateLimiter::new(5, 10);
        assert!(limiter.try_acquire("t1", "a1", 10));
        assert!(!limiter.try_acquire("t1", "a1", 1));
    }

    #[test]
    fn test_available_tokens() {
        let limiter = RateLimiter::new(5, 10);
        let avail = limiter.available_tokens("t1", "a1");
        assert!((avail - 10.0).abs() < 0.01);
        limiter.try_acquire("t1", "a1", 1);
        let avail = limiter.available_tokens("t1", "a1");
        assert!((avail - 9.0).abs() < 0.1);
    }

    #[test]
    fn test_available_tokens_default() {
        let limiter = RateLimiter::new(5, 10);
        assert!((limiter.available_tokens("nope", "nope") - 10.0).abs() < 0.01);
    }

    #[test]
    fn test_set_rate() {
        let limiter = RateLimiter::new(100, 100);
        limiter.set_rate("t1", "a1", 0, 0);
        assert!(!limiter.try_acquire("t1", "a1", 1));
    }

    #[test]
    fn test_tenant_rate_override() {
        let limiter = RateLimiter::new(100, 100);
        limiter.try_acquire("t1", "a1", 1);
        limiter.try_acquire("t1", "a2", 1);
        limiter.set_tenant_rate("t1", 0, 0);
        assert!(!limiter.try_acquire("t1", "a1", 1));
        assert!(!limiter.try_acquire("t1", "a2", 1));
    }

    #[test]
    fn test_reset() {
        let limiter = RateLimiter::new(5, 10);
        for _ in 0..10 { limiter.try_acquire("t1", "a1", 1); }
        assert!(!limiter.try_acquire("t1", "a1", 1));
        limiter.reset("t1", "a1");
        assert!(limiter.try_acquire("t1", "a1", 1));
    }

    #[test]
    fn test_bucket_count() {
        let limiter = RateLimiter::new(5, 10);
        assert_eq!(limiter.bucket_count(), 0);
        limiter.try_acquire("t1", "a1", 1);
        limiter.try_acquire("t1", "a2", 1);
        limiter.try_acquire("t2", "a1", 1);
        assert_eq!(limiter.bucket_count(), 3);
        limiter.reset("t1", "a1");
        assert_eq!(limiter.bucket_count(), 2);
    }

    #[test]
    fn test_make_key() {
        assert_eq!(RateLimiter::make_key("org", "agent"), "org:agent");
    }
}
