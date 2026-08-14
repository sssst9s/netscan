use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, Semaphore, SemaphorePermit};
use tokio::time::Instant;

const MIN_TIMEOUT: Duration = Duration::from_millis(50);

const MAX_TIMEOUT: Duration = Duration::from_secs(20);

const LOSS_BACKOFF_THRESHOLD: f64 = 0.15;

const LOSS_RAMP_THRESHOLD: f64 = 0.02;

const LOSS_WINDOW: u32 = 128;

#[derive(Debug)]
pub struct DynamicSemaphore {
    inner: Arc<Semaphore>,
    capacity: AtomicUsize,
    max: usize,
}

impl DynamicSemaphore {
    pub fn new(initial: usize, max: usize) -> Arc<Self> {
        let initial = initial.clamp(1, max.max(1));
        Arc::new(Self {
            inner: Arc::new(Semaphore::new(initial)),
            capacity: AtomicUsize::new(initial),
            max: max.max(1),
        })
    }

    pub fn capacity(&self) -> usize {
        self.capacity.load(Ordering::Relaxed)
    }

    pub fn max(&self) -> usize {
        self.max
    }

    pub async fn acquire(&self) -> Option<SemaphorePermit<'_>> {
        self.inner.acquire().await.ok()
    }

    pub fn grow_to(&self, target: usize) {
        let target = target.clamp(1, self.max);
        let current = self.capacity.load(Ordering::Relaxed);
        if target > current {
            self.inner.add_permits(target - current);
            self.capacity.store(target, Ordering::Relaxed);
        }
    }

    pub fn shrink_to(&self, target: usize) {
        let target = target.clamp(1, self.max);
        let current = self.capacity.load(Ordering::Relaxed);
        if target >= current {
            return;
        }
        let mut withdrawn = 0;
        for _ in 0..(current - target) {
            match self.inner.try_acquire() {
                Ok(permit) => {
                    permit.forget();
                    withdrawn += 1;
                }
                Err(_) => break,
            }
        }
        if withdrawn > 0 {
            self.capacity.fetch_sub(withdrawn, Ordering::Relaxed);
        }
    }

    pub fn resize(&self, target: usize) {
        let current = self.capacity();
        if target > current {
            self.grow_to(target);
        } else if target < current {
            self.shrink_to(target);
        }
    }

    pub fn close(&self) {
        self.inner.close();
    }
}

#[derive(Debug)]
pub struct RateLimiter {
    state: Mutex<BucketState>,
    rate_per_sec: f64,
    burst: f64,
}

#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new(rate: u32) -> Self {
        let rate_per_sec = f64::from(rate.max(1));
        let burst = (rate_per_sec / 10.0).max(1.0);
        Self {
            state: Mutex::new(BucketState {
                tokens: burst,
                last_refill: Instant::now(),
            }),
            rate_per_sec,
            burst,
        }
    }

    pub fn rate(&self) -> f64 {
        self.rate_per_sec
    }

    pub async fn acquire(&self) {
        loop {
            let wait = {
                let mut state = self.state.lock().await;
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                state.tokens = (state.tokens + elapsed * self.rate_per_sec).min(self.burst);
                state.last_refill = now;

                if state.tokens >= 1.0 {
                    state.tokens -= 1.0;
                    return;
                }
                let deficit = 1.0 - state.tokens;
                Duration::from_secs_f64(deficit / self.rate_per_sec)
            };
            tokio::time::sleep(wait).await;
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct RttEstimator {
    srtt: Option<Duration>,
    rttvar: Duration,
    samples: u64,
}

impl Default for RttEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl RttEstimator {
    pub fn new() -> Self {
        Self {
            srtt: None,
            rttvar: Duration::ZERO,
            samples: 0,
        }
    }

    pub fn record(&mut self, rtt: Duration) {
        self.samples += 1;
        match self.srtt {
            None => {
                self.srtt = Some(rtt);
                self.rttvar = rtt / 2;
            }
            Some(srtt) => {
                let diff = srtt.abs_diff(rtt);
                self.rttvar = (self.rttvar * 3 + diff) / 4;

                self.srtt = Some((srtt * 7 + rtt) / 8);
            }
        }
    }

    pub fn samples(&self) -> u64 {
        self.samples
    }

    pub fn mean(&self) -> Option<Duration> {
        self.srtt
    }

    pub fn timeout(&self) -> Option<Duration> {
        let srtt = self.srtt?;
        if self.samples < 4 {
            return None;
        }
        let timeout = srtt + self.rttvar * 4;
        Some(timeout.clamp(MIN_TIMEOUT, MAX_TIMEOUT))
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct LossEstimator {
    responded: u32,
    lost: u32,
}

impl LossEstimator {
    pub fn record_response(&mut self) {
        self.responded = self.responded.saturating_add(1);
        self.decay();
    }

    pub fn record_loss(&mut self) {
        self.lost = self.lost.saturating_add(1);
        self.decay();
    }

    fn decay(&mut self) {
        if self.responded + self.lost > LOSS_WINDOW {
            self.responded /= 2;
            self.lost /= 2;
        }
    }

    pub fn observations(&self) -> u32 {
        self.responded + self.lost
    }

    pub fn rate(&self) -> f64 {
        let total = self.observations();
        if total == 0 {
            return 0.0;
        }
        f64::from(self.lost) / f64::from(total)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Adjustment {
    pub timeout: Duration,
    pub concurrency: usize,
    pub changed: bool,
}

#[derive(Debug)]
pub struct AdaptiveController {
    enabled: bool,
    rtt: std::sync::Mutex<RttEstimator>,
    loss: std::sync::Mutex<LossEstimator>,
    timeout_us: AtomicU64,
    concurrency: AtomicUsize,
    max_concurrency: usize,
    base_timeout: Duration,
    since_adjust: AtomicU64,
}

impl AdaptiveController {
    pub fn new(enabled: bool, base_timeout: Duration, concurrency: usize) -> Self {
        Self {
            enabled,
            rtt: std::sync::Mutex::new(RttEstimator::new()),
            loss: std::sync::Mutex::new(LossEstimator::default()),
            timeout_us: AtomicU64::new(base_timeout.as_micros() as u64),
            concurrency: AtomicUsize::new(concurrency.max(1)),
            max_concurrency: concurrency.max(1),
            base_timeout,
            since_adjust: AtomicU64::new(0),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_micros(self.timeout_us.load(Ordering::Relaxed))
    }

    pub fn concurrency(&self) -> usize {
        self.concurrency.load(Ordering::Relaxed)
    }

    pub fn mean_rtt(&self) -> Option<Duration> {
        self.rtt.lock().expect("rtt mutex poisoned").mean()
    }

    pub fn loss_rate(&self) -> f64 {
        self.loss.lock().expect("loss mutex poisoned").rate()
    }

    pub fn record_response(&self, rtt: Duration) {
        self.rtt.lock().expect("rtt mutex poisoned").record(rtt);
        self.loss
            .lock()
            .expect("loss mutex poisoned")
            .record_response();
        self.maybe_adjust();
    }

    pub fn record_timeout(&self) {
        self.loss.lock().expect("loss mutex poisoned").record_loss();
        self.maybe_adjust();
    }

    fn maybe_adjust(&self) -> Option<Adjustment> {
        if !self.enabled {
            return None;
        }

        if self.since_adjust.fetch_add(1, Ordering::Relaxed) % 32 != 31 {
            return None;
        }
        Some(self.adjust())
    }

    pub fn adjust(&self) -> Adjustment {
        let previous_timeout = self.timeout();
        let previous_concurrency = self.concurrency();

        let timeout = self
            .rtt
            .lock()
            .expect("rtt mutex poisoned")
            .timeout()
            .unwrap_or(self.base_timeout)
            .clamp(MIN_TIMEOUT, MAX_TIMEOUT);

        let loss = *self.loss.lock().expect("loss mutex poisoned");
        let concurrency = if loss.observations() < 16 {
            previous_concurrency
        } else if loss.rate() > LOSS_BACKOFF_THRESHOLD {
            (previous_concurrency / 2).max(1)
        } else if loss.rate() < LOSS_RAMP_THRESHOLD {
            let step = (self.max_concurrency / 16).max(1);
            (previous_concurrency + step).min(self.max_concurrency)
        } else {
            previous_concurrency
        };

        if self.enabled {
            self.timeout_us
                .store(timeout.as_micros() as u64, Ordering::Relaxed);
            self.concurrency.store(concurrency, Ordering::Relaxed);
        }

        Adjustment {
            timeout,
            concurrency,
            changed: timeout != previous_timeout || concurrency != previous_concurrency,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_estimator_needs_samples_before_it_speaks() {
        let mut estimator = RttEstimator::new();
        assert_eq!(estimator.timeout(), None);
        estimator.record(Duration::from_millis(10));
        assert_eq!(estimator.timeout(), None, "one sample is not enough");
        for _ in 0..4 {
            estimator.record(Duration::from_millis(10));
        }
        assert!(estimator.timeout().is_some());
    }

    #[test]
    fn rtt_estimator_converges_on_a_stable_latency() {
        let mut estimator = RttEstimator::new();
        for _ in 0..50 {
            estimator.record(Duration::from_millis(20));
        }
        let mean = estimator.mean().unwrap();
        assert!(
            mean >= Duration::from_millis(19) && mean <= Duration::from_millis(21),
            "mean drifted to {mean:?}"
        );

        let timeout = estimator.timeout().unwrap();
        assert!(timeout >= mean, "timeout {timeout:?} below mean {mean:?}");
        assert!(
            timeout < Duration::from_millis(60),
            "timeout {timeout:?} too generous"
        );
    }

    #[test]
    fn rtt_estimator_widens_the_timeout_when_latency_is_erratic() {
        let mut steady = RttEstimator::new();
        let mut jittery = RttEstimator::new();
        for i in 0..50 {
            steady.record(Duration::from_millis(20));
            jittery.record(Duration::from_millis(if i % 2 == 0 { 5 } else { 60 }));
        }
        assert!(
            jittery.timeout().unwrap() > steady.timeout().unwrap(),
            "a jittery path should get a wider timeout"
        );
    }

    #[test]
    fn rtt_timeout_is_clamped() {
        let mut fast = RttEstimator::new();
        for _ in 0..10 {
            fast.record(Duration::from_micros(1));
        }
        assert_eq!(fast.timeout().unwrap(), MIN_TIMEOUT);

        let mut slow = RttEstimator::new();
        for _ in 0..10 {
            slow.record(Duration::from_secs(60));
        }
        assert_eq!(slow.timeout().unwrap(), MAX_TIMEOUT);
    }

    #[test]
    fn loss_estimator_tracks_rate_and_bounds_its_window() {
        let mut loss = LossEstimator::default();
        assert_eq!(loss.rate(), 0.0);
        for _ in 0..10 {
            loss.record_response();
        }
        for _ in 0..10 {
            loss.record_loss();
        }
        assert!((loss.rate() - 0.5).abs() < 0.01);

        for _ in 0..10_000 {
            loss.record_response();
        }
        assert!(
            loss.observations() <= LOSS_WINDOW + 1,
            "window grew to {}",
            loss.observations()
        );
        assert!(loss.rate() < 0.01, "recent successes should dominate");
    }

    #[test]
    fn controller_leaves_values_alone_when_disabled() {
        let controller = AdaptiveController::new(false, Duration::from_millis(500), 100);
        for _ in 0..1000 {
            controller.record_timeout();
        }
        assert_eq!(controller.timeout(), Duration::from_millis(500));
        assert_eq!(controller.concurrency(), 100);

        assert!(controller.loss_rate() > 0.9);
    }

    #[test]
    fn controller_backs_off_under_loss() {
        let controller = AdaptiveController::new(true, Duration::from_millis(500), 100);
        for _ in 0..200 {
            controller.record_timeout();
        }
        assert!(
            controller.concurrency() < 100,
            "concurrency stayed at {}",
            controller.concurrency()
        );
    }

    #[test]
    fn controller_ramps_up_on_a_clean_fast_path() {
        let controller = AdaptiveController::new(true, Duration::from_millis(1000), 512);
        controller.concurrency.store(8, Ordering::Relaxed);
        for _ in 0..500 {
            controller.record_response(Duration::from_millis(2));
        }
        assert!(controller.concurrency() > 8, "concurrency did not grow");
        assert!(
            controller.timeout() < Duration::from_millis(1000),
            "timeout should tighten on a fast path, was {:?}",
            controller.timeout()
        );
    }

    #[test]
    fn controller_never_exceeds_the_configured_ceiling() {
        let controller = AdaptiveController::new(true, Duration::from_millis(100), 64);
        for _ in 0..10_000 {
            controller.record_response(Duration::from_millis(1));
        }
        assert!(controller.concurrency() <= 64);
    }

    #[test]
    fn controller_never_drops_below_one() {
        let controller = AdaptiveController::new(true, Duration::from_millis(100), 4);
        for _ in 0..10_000 {
            controller.record_timeout();
        }
        assert!(controller.concurrency() >= 1);
    }

    #[tokio::test]
    async fn dynamic_semaphore_bounds_concurrency() {
        let semaphore = DynamicSemaphore::new(2, 10);
        let _a = semaphore.acquire().await.unwrap();
        let _b = semaphore.acquire().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), semaphore.acquire())
                .await
                .is_err(),
            "third acquire should have blocked"
        );
    }

    #[tokio::test]
    async fn dynamic_semaphore_grows_and_shrinks() {
        let semaphore = DynamicSemaphore::new(1, 8);
        assert_eq!(semaphore.capacity(), 1);

        semaphore.grow_to(4);
        assert_eq!(semaphore.capacity(), 4);
        let permits: Vec<_> = vec![
            semaphore.acquire().await.unwrap(),
            semaphore.acquire().await.unwrap(),
            semaphore.acquire().await.unwrap(),
            semaphore.acquire().await.unwrap(),
        ];
        assert_eq!(permits.len(), 4);
        drop(permits);

        semaphore.shrink_to(2);
        assert_eq!(semaphore.capacity(), 2);
        let _a = semaphore.acquire().await.unwrap();
        let _b = semaphore.acquire().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), semaphore.acquire())
                .await
                .is_err(),
            "capacity was not actually reduced"
        );
    }

    #[tokio::test]
    async fn dynamic_semaphore_respects_the_ceiling() {
        let semaphore = DynamicSemaphore::new(1, 3);
        semaphore.grow_to(1000);
        assert_eq!(semaphore.capacity(), 3);
    }

    #[tokio::test]
    async fn shrinking_does_not_interrupt_in_flight_work() {
        let semaphore = DynamicSemaphore::new(4, 8);
        let held: Vec<_> = vec![
            semaphore.acquire().await.unwrap(),
            semaphore.acquire().await.unwrap(),
            semaphore.acquire().await.unwrap(),
            semaphore.acquire().await.unwrap(),
        ];

        semaphore.shrink_to(1);
        assert_eq!(
            semaphore.capacity(),
            4,
            "in-flight permits must not be revoked"
        );
        drop(held);
        semaphore.shrink_to(1);
        assert_eq!(semaphore.capacity(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_enforces_the_average_rate() {
        let limiter = RateLimiter::new(100);
        let start = Instant::now();
        for _ in 0..50 {
            limiter.acquire().await;
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed >= Duration::from_millis(350),
            "50 operations at 100/s finished in {elapsed:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn rate_limiter_allows_a_small_burst() {
        let limiter = RateLimiter::new(1000);
        let start = Instant::now();
        for _ in 0..100 {
            limiter.acquire().await;
        }
        assert!(
            start.elapsed() < Duration::from_millis(50),
            "burst allowance did not apply: {:?}",
            start.elapsed()
        );
    }
}
