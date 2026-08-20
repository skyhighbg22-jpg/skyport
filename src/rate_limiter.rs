//! In-memory sliding-window rate limiter for global and scoped traffic guardrails.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Status when a request is permitted under rate limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitStatus {
    pub limit_rpm: Option<u32>,
    pub remaining_rpm: Option<u32>,
    pub reset_secs: u64,
}

/// Error details when a request is blocked due to exceeding rate limits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateLimitExceeded {
    pub limit_rpm: Option<u32>,
    pub limit_rps: Option<u32>,
    pub retry_after_secs: u64,
    pub is_burst: bool,
}

#[derive(Debug)]
struct SlidingWindow {
    requests: VecDeque<Instant>,
}

impl SlidingWindow {
    fn new() -> Self {
        Self {
            requests: VecDeque::new(),
        }
    }

    /// Prune entries older than 60 seconds and evaluate limits.
    fn check_and_record(
        &mut self,
        now: Instant,
        max_rpm: Option<u32>,
        max_rps: Option<u32>,
    ) -> Result<RateLimitStatus, RateLimitExceeded> {
        let sixty_secs_ago = now.checked_sub(Duration::from_secs(60)).unwrap_or(now);
        let one_sec_ago = now.checked_sub(Duration::from_secs(1)).unwrap_or(now);

        // Discard entries older than 60 seconds
        while let Some(&first) = self.requests.front() {
            if first < sixty_secs_ago {
                self.requests.pop_front();
            } else {
                break;
            }
        }

        // Check RPS (burst limit in the last 1 second)
        if let Some(rps_limit) = max_rps {
            let rps_count = self
                .requests
                .iter()
                .rev()
                .take_while(|&&t| t >= one_sec_ago)
                .count() as u32;
            if rps_count >= rps_limit {
                let oldest_in_sec = self
                    .requests
                    .iter()
                    .rev()
                    .take_while(|&&t| t >= one_sec_ago)
                    .last()
                    .copied()
                    .unwrap_or(now);
                let elapsed = now.duration_since(oldest_in_sec);
                let retry_after = 1u64.saturating_sub(elapsed.as_secs()).max(1);
                return Err(RateLimitExceeded {
                    limit_rpm: max_rpm,
                    limit_rps: Some(rps_limit),
                    retry_after_secs: retry_after,
                    is_burst: true,
                });
            }
        }

        // Check RPM (requests in the last 60 seconds)
        let count = self.requests.len() as u32;
        if let Some(rpm_limit) = max_rpm {
            if count >= rpm_limit {
                let oldest = self.requests.front().copied().unwrap_or(now);
                let elapsed = now.duration_since(oldest);
                let retry_after = 60u64.saturating_sub(elapsed.as_secs()).max(1);
                return Err(RateLimitExceeded {
                    limit_rpm: Some(rpm_limit),
                    limit_rps: max_rps,
                    retry_after_secs: retry_after,
                    is_burst: false,
                });
            }
        }

        // Record request
        self.requests.push_back(now);
        let current_count = self.requests.len() as u32;

        let reset_secs = if let Some(&oldest) = self.requests.front() {
            60u64
                .saturating_sub(now.duration_since(oldest).as_secs())
                .max(1)
        } else {
            60
        };

        Ok(RateLimitStatus {
            limit_rpm: max_rpm,
            remaining_rpm: max_rpm.map(|limit| limit.saturating_sub(current_count)),
            reset_secs,
        })
    }
}

/// Global and scoped rate limiter engine.
#[derive(Debug)]
pub struct RateLimiter {
    global: Mutex<SlidingWindow>,
    scoped: Mutex<HashMap<String, SlidingWindow>>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            global: Mutex::new(SlidingWindow::new()),
            scoped: Mutex::new(HashMap::new()),
        }
    }

    /// Check and record a global request.
    pub fn check_global(
        &self,
        max_rpm: Option<u32>,
        max_rps: Option<u32>,
    ) -> Result<RateLimitStatus, RateLimitExceeded> {
        if max_rpm.is_none() && max_rps.is_none() {
            return Ok(RateLimitStatus {
                limit_rpm: None,
                remaining_rpm: None,
                reset_secs: 0,
            });
        }
        let now = Instant::now();
        let mut global = self.global.lock().unwrap_or_else(|p| p.into_inner());
        global.check_and_record(now, max_rpm, max_rps)
    }

    /// Check and record a scoped request (e.g. "openai" or "openai:primary").
    pub fn check_scoped(
        &self,
        scope: &str,
        max_rpm: Option<u32>,
    ) -> Result<RateLimitStatus, RateLimitExceeded> {
        let Some(rpm_limit) = max_rpm else {
            return Ok(RateLimitStatus {
                limit_rpm: None,
                remaining_rpm: None,
                reset_secs: 0,
            });
        };
        let now = Instant::now();
        let mut scoped = self.scoped.lock().unwrap_or_else(|p| p.into_inner());
        let window = scoped
            .entry(scope.to_string())
            .or_insert_with(SlidingWindow::new);
        window.check_and_record(now, Some(rpm_limit), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sliding_window_allows_within_limit_and_blocks_overflow() {
        let mut window = SlidingWindow::new();
        let now = Instant::now();

        // 3 requests allowed with max_rpm = 3
        assert!(window.check_and_record(now, Some(3), None).is_ok());
        assert!(window.check_and_record(now, Some(3), None).is_ok());
        let third = window.check_and_record(now, Some(3), None);
        assert!(third.is_ok());
        assert_eq!(third.unwrap().remaining_rpm, Some(0));

        // 4th request exceeds limit
        let fourth = window.check_and_record(now, Some(3), None);
        assert!(fourth.is_err());
        let err = fourth.unwrap_err();
        assert_eq!(err.limit_rpm, Some(3));
        assert!(!err.is_burst);
        assert!(err.retry_after_secs > 0);
    }

    #[test]
    fn sliding_window_enforces_burst_rps() {
        let mut window = SlidingWindow::new();
        let now = Instant::now();

        // 2 requests allowed with max_rps = 2
        assert!(window.check_and_record(now, None, Some(2)).is_ok());
        assert!(window.check_and_record(now, None, Some(2)).is_ok());

        // 3rd in the same second fails burst limit
        let third = window.check_and_record(now, None, Some(2));
        assert!(third.is_err());
        let err = third.unwrap_err();
        assert!(err.is_burst);
        assert_eq!(err.limit_rps, Some(2));
    }

    #[test]
    fn sliding_window_prunes_expired_timestamps() {
        let mut window = SlidingWindow::new();
        let start = Instant::now();

        assert!(window.check_and_record(start, Some(1), None).is_ok());
        assert!(window.check_and_record(start, Some(1), None).is_err());

        // 61 seconds later, the old request has expired
        let later = start + Duration::from_secs(61);
        let result = window.check_and_record(later, Some(1), None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().remaining_rpm, Some(0));
    }
}
