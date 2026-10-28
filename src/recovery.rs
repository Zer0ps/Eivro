//! Finite backoff driven by actual network/sleep events, never a health polling loop.
use std::time::{Duration, Instant};
#[derive(Default)]
pub struct Recovery {
    pub due: Option<Instant>,
    attempts: usize,
    pub recovering: bool,
    pub sleeping: bool,
    pub offline: bool,
    pub exhausted: bool,
}
impl Recovery {
    pub fn cancel(&mut self) {
        self.due = None;
        self.attempts = 0;
        self.recovering = false;
        self.exhausted = false;
    }
    pub fn schedule(&mut self, now: Instant) {
        self.recovering = true;
        self.exhausted = false;
        self.attempts = 0;
        self.due = if self.sleeping || self.offline {
            None
        } else {
            Some(now + Duration::from_secs(2))
        };
    }
    pub fn failed(&mut self, now: Instant) -> bool {
        const DELAYS: [u64; 6] = [2, 5, 15, 30, 60, 120];
        self.due = None;
        if self.sleeping || self.offline {
            return true;
        }
        if let Some(delay) = DELAYS.get(self.attempts) {
            self.attempts += 1;
            self.due = Some(now + Duration::from_secs(*delay));
            true
        } else {
            self.exhausted = true;
            false
        }
    }
    pub fn ready(&mut self, now: Instant) -> bool {
        if !self.sleeping && !self.offline && self.due.is_some_and(|d| d <= now) {
            self.due = None;
            true
        } else {
            false
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_offline_sleep_and_cancel_never_poll() {
        let now = Instant::now();
        let mut r = Recovery::default();
        assert!(!r.ready(now));
        assert!(r.due.is_none());
        r.offline = true;
        r.schedule(now);
        assert!(r.due.is_none());
        r.offline = false;
        r.sleeping = true;
        r.schedule(now);
        assert!(r.due.is_none());
        r.sleeping = false;
        r.schedule(now);
        assert!(!r.ready(now));
        assert!(r.ready(now + Duration::from_secs(2)));
        for _ in 0..6 {
            assert!(r.failed(now));
        }
        assert!(!r.failed(now));
        assert!(r.due.is_none());
        r.schedule(now);
        r.cancel();
        assert!(!r.ready(now + Duration::from_secs(9999)));
    }
}
