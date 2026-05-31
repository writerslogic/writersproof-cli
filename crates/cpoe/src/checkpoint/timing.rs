// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Behavioral checkpoint timing for WAR/1.1 evidence.
//!
//! Triggers checkpoints based on typing behavior and entropy accumulation
//! rather than fixed time intervals, creating checkpoints naturally
//! entangled with the authorship process.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};

pub const ENTROPY_THRESHOLD_BASIC: f64 = 2.0;
pub const ENTROPY_THRESHOLD_STANDARD: f64 = 3.0;
pub const ENTROPY_THRESHOLD_ENHANCED: f64 = 3.0;

/// Number of recent jitter samples used for windowed entropy estimation.
const JITTER_WINDOW_SIZE: usize = 16;
/// Bitmask for fast power-of-two ring buffer indexing (16 - 1)
const WINDOW_MASK: usize = JITTER_WINDOW_SIZE - 1;

/// Reason a checkpoint was triggered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TriggerReason {
    MaxKeystrokes,
    TypingPause,
    EntropyThreshold,
    SizeDelta,
    MaxTimeInterval,
    Manual,
    SessionEnd,
}

/// Configuration for behavioral checkpoint timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub min_keystroke_interval: u64,
    pub max_keystroke_interval: u64,
    pub pause_threshold_secs: f64,
    pub entropy_threshold_bits: f64,
    pub size_delta_threshold: i64,
    pub max_time_interval_secs: f64,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            min_keystroke_interval: 50,
            max_keystroke_interval: 500,
            pause_threshold_secs: 5.0,
            entropy_threshold_bits: ENTROPY_THRESHOLD_STANDARD,
            size_delta_threshold: 256,
            max_time_interval_secs: 300.0,
        }
    }
}

mod duration_serde {
    use super::*;
    pub fn serialize<S>(d: &Duration, s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_f64(d.as_secs_f64())
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Duration, D::Error>
    where
        D: Deserializer<'de>,
    {
        let f = f64::deserialize(d)?;
        Ok(Duration::from_secs_f64(f))
    }
}

/// A checkpoint trigger event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TriggerEvent {
    pub timestamp: DateTime<Utc>,
    pub reason: TriggerReason,
    pub keystroke_count: u64,
    pub entropy_bits: f64,
    pub document_size: i64,
    #[serde(with = "duration_serde")]
    pub elapsed_since_last: Duration,
}

/// Tracks typing behavior and determines when to create checkpoints.
///
/// Features pre-baked Durations to remove runtime float calculations
/// from the hot loop, along with branchless bitwise ring buffer masking.
#[derive(Debug, Clone)]
pub struct CheckpointTrigger {
    config: Config,
    // Pre-baked time structures to completely stop runtime float parsing
    pause_threshold: Duration,
    max_time_interval: Duration,
    keystrokes_since_checkpoint: u64,
    total_keystrokes: u64,
    accumulated_entropy: f64,
    last_keystroke: Option<Instant>,
    last_checkpoint: Instant,
    last_checkpoint_size: i64,
    entropy_hash: [u8; 32],
    window_buf: [u32; JITTER_WINDOW_SIZE],
    window_idx: usize,
    window_len: usize,
    sum_x: u64,
    sum_x2: u128,
}

impl CheckpointTrigger {
    pub fn new() -> Self {
        Self::with_config(Config::default())
    }

    pub fn with_config(config: Config) -> Self {
        let pause_threshold = Duration::from_secs_f64(config.pause_threshold_secs);
        let max_time_interval = Duration::from_secs_f64(config.max_time_interval_secs);
        Self {
            config,
            pause_threshold,
            max_time_interval,
            keystrokes_since_checkpoint: 0,
            total_keystrokes: 0,
            accumulated_entropy: 0.0,
            last_keystroke: None,
            last_checkpoint: Instant::now(),
            last_checkpoint_size: 0,
            entropy_hash: [0u8; 32],
            window_buf: [0u32; JITTER_WINDOW_SIZE],
            window_idx: 0,
            window_len: 0,
            sum_x: 0,
            sum_x2: 0,
        }
    }

    pub fn record_keystroke(
        &mut self,
        jitter_micros: u32,
        current_doc_size: i64,
    ) -> Option<TriggerEvent> {
        let now = Instant::now();
        self.total_keystrokes += 1;
        self.keystrokes_since_checkpoint += 1;

        self.accumulate_entropy(jitter_micros);

        let prev_keystroke = self.last_keystroke;
        self.last_keystroke = Some(now);

        let reason = self.evaluate_rules(now, prev_keystroke, current_doc_size)?;
        Some(self.create_trigger(reason, current_doc_size, now))
    }

    pub fn check_time_trigger(&mut self, current_doc_size: i64) -> Option<TriggerEvent> {
        let now = Instant::now();
        if now.duration_since(self.last_checkpoint) >= self.max_time_interval
            && self.keystrokes_since_checkpoint > 0
        {
            return Some(self.create_trigger(
                TriggerReason::MaxTimeInterval,
                current_doc_size,
                now,
            ));
        }
        None
    }

    pub fn manual_trigger(&mut self, current_doc_size: i64) -> TriggerEvent {
        self.create_trigger(TriggerReason::Manual, current_doc_size, Instant::now())
    }

    pub fn session_end_trigger(&mut self, current_doc_size: i64) -> TriggerEvent {
        self.create_trigger(TriggerReason::SessionEnd, current_doc_size, Instant::now())
    }

    pub fn entropy_hash(&self) -> [u8; 32] {
        self.entropy_hash
    }

    pub fn finalize_entropy_hash(self) -> [u8; 32] {
        self.entropy_hash
    }

    pub fn keystrokes_since_checkpoint(&self) -> u64 {
        self.keystrokes_since_checkpoint
    }

    pub fn total_keystrokes(&self) -> u64 {
        self.total_keystrokes
    }

    pub fn accumulated_entropy(&self) -> f64 {
        self.accumulated_entropy
    }

    pub fn reset_for_checkpoint(&mut self, doc_size: i64) {
        self.reset_for_checkpoint_internal(doc_size, Instant::now());
    }

    #[inline(always)]
    fn reset_for_checkpoint_internal(&mut self, doc_size: i64, now: Instant) {
        self.keystrokes_since_checkpoint = 0;
        self.accumulated_entropy = 0.0;
        self.last_checkpoint = now;
        self.last_checkpoint_size = doc_size;
    }

    #[inline(always)]
    fn evaluate_rules(
        &self,
        now: Instant,
        prev_keystroke: Option<Instant>,
        current_doc_size: i64,
    ) -> Option<TriggerReason> {
        // Pure integer/Duration comparison, zero runtime floats
        if now.duration_since(self.last_checkpoint) >= self.max_time_interval {
            return Some(TriggerReason::MaxTimeInterval);
        }

        if self.keystrokes_since_checkpoint >= self.config.max_keystroke_interval {
            return Some(TriggerReason::MaxKeystrokes);
        }

        if self.keystrokes_since_checkpoint >= self.config.min_keystroke_interval {
            if let Some(last) = prev_keystroke {
                if now.duration_since(last) >= self.pause_threshold {
                    return Some(TriggerReason::TypingPause);
                }
            }

            if self.accumulated_entropy >= self.config.entropy_threshold_bits {
                return Some(TriggerReason::EntropyThreshold);
            }

            if (current_doc_size - self.last_checkpoint_size).abs()
                >= self.config.size_delta_threshold
            {
                return Some(TriggerReason::SizeDelta);
            }
        }

        None
    }

    fn create_trigger(
        &mut self,
        reason: TriggerReason,
        doc_size: i64,
        now: Instant,
    ) -> TriggerEvent {
        let elapsed = now.duration_since(self.last_checkpoint);
        let event = TriggerEvent {
            timestamp: Utc::now(),
            reason,
            keystroke_count: self.keystrokes_since_checkpoint,
            entropy_bits: self.accumulated_entropy,
            document_size: doc_size,
            elapsed_since_last: elapsed,
        };
        self.reset_for_checkpoint_internal(doc_size, now);
        event
    }

    fn accumulate_entropy(&mut self, jitter_micros: u32) {
        let mut hasher = Sha256::new();
        hasher.update(self.entropy_hash);
        hasher.update(jitter_micros.to_be_bytes());
        hasher.update(self.total_keystrokes.to_be_bytes());
        self.entropy_hash = hasher.finalize().into();

        self.update_window_stats(jitter_micros);
        self.accumulated_entropy += self.windowed_entropy_estimate();
    }

    #[inline(always)]
    fn update_window_stats(&mut self, val: u32) {
        if self.window_len == JITTER_WINDOW_SIZE {
            let old = self.window_buf[self.window_idx];
            self.sum_x -= old as u64;
            self.sum_x2 -= (old as u128) * (old as u128);
        } else {
            self.window_len += 1;
        }

        self.window_buf[self.window_idx] = val;
        self.sum_x += val as u64;
        self.sum_x2 += (val as u128) * (val as u128);

        // Fast power-of-two bitwise masking instead of modulo division arithmetic
        self.window_idx = (self.window_idx + 1) & WINDOW_MASK;
    }

    fn windowed_entropy_estimate(&self) -> f64 {
        let n = self.window_len as f64;
        if n < 4.0 {
            return 0.0;
        }

        let mean = self.sum_x as f64 / n;
        if mean < 1.0 {
            return 0.0;
        }

        let var = (self.sum_x2 as f64 / n) - (mean * mean);
        let cv = var.max(0.0).sqrt() / mean;
        crate::utils::Probability::clamp((1.0 + cv).log2()).get()
    }
}

impl Default for CheckpointTrigger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.min_keystroke_interval, 50);
        assert_eq!(config.max_keystroke_interval, 500);
        assert_eq!(config.pause_threshold_secs, 5.0);
    }

    #[test]
    fn test_trigger_on_max_keystrokes() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 10,
            entropy_threshold_bits: 10000.0,
            size_delta_threshold: 10000,
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        for i in 0..9 {
            let result = trigger.record_keystroke(10, 100);
            assert!(
                result.is_none(),
                "Unexpected trigger at keystroke {}",
                i + 1
            );
        }

        let result = trigger.record_keystroke(10, 100);
        assert!(result.is_some());
        let event = result.unwrap();
        assert_eq!(event.reason, TriggerReason::MaxKeystrokes);
        assert_eq!(event.keystroke_count, 10);
    }

    #[test]
    fn test_trigger_on_entropy_threshold() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 1000,
            entropy_threshold_bits: 3.0,
            size_delta_threshold: 100_000,
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        let jitters = [
            500, 5000, 800, 4000, 600, 5500, 700, 4200, 550, 5100, 900, 3800, 650, 4500, 750, 4800,
            500, 5200, 850, 3900,
        ];
        for (i, &j) in jitters.iter().enumerate() {
            let result = trigger.record_keystroke(j, 100);
            if let Some(event) = result {
                assert_eq!(event.reason, TriggerReason::EntropyThreshold);
                assert!(i >= 5, "Should need at least a few keystrokes");
                return;
            }
        }

        panic!(
            "Expected EntropyThreshold trigger within 20 keystrokes, got entropy={}",
            trigger.accumulated_entropy()
        );
    }

    #[test]
    fn test_trigger_on_size_delta() {
        let config = Config {
            min_keystroke_interval: 5,
            max_keystroke_interval: 1000,
            size_delta_threshold: 100,
            entropy_threshold_bits: 10000.0,
            ..Default::default()
        };
        let mut trigger = CheckpointTrigger::with_config(config);

        for i in 0..10 {
            let result = trigger.record_keystroke(10, i * 5);
            assert!(
                result.is_none(),
                "Unexpected trigger at keystroke {}",
                i + 1
            );
        }

        let result = trigger.record_keystroke(10, 500);
        assert!(result.is_some());
        assert_eq!(result.unwrap().reason, TriggerReason::SizeDelta);
    }

    #[test]
    fn test_manual_trigger() {
        let mut trigger = CheckpointTrigger::new();
        trigger.record_keystroke(1000, 100);

        let event = trigger.manual_trigger(150);
        assert_eq!(event.reason, TriggerReason::Manual);
        assert_eq!(event.document_size, 150);
    }

    #[test]
    fn test_session_end_trigger() {
        let mut trigger = CheckpointTrigger::new();
        trigger.record_keystroke(1000, 100);

        let event = trigger.session_end_trigger(200);
        assert_eq!(event.reason, TriggerReason::SessionEnd);
    }

    #[test]
    fn test_entropy_accumulation() {
        let mut trigger = CheckpointTrigger::new();

        assert_eq!(trigger.accumulated_entropy(), 0.0);

        trigger.record_keystroke(1000, 100);
        trigger.record_keystroke(2000, 100);
        trigger.record_keystroke(500, 100);
        assert_eq!(trigger.accumulated_entropy(), 0.0);

        trigger.record_keystroke(3000, 100);
        assert!(trigger.accumulated_entropy() > 0.0);

        let e1 = trigger.accumulated_entropy();
        trigger.record_keystroke(800, 100);
        assert!(trigger.accumulated_entropy() > e1);
    }

    #[test]
    fn test_reset_for_checkpoint() {
        let mut trigger = CheckpointTrigger::new();

        for i in 0..10 {
            let j = if i % 2 == 0 { 500 } else { 5000 };
            trigger.record_keystroke(j, 100);
        }

        assert!(trigger.keystrokes_since_checkpoint() > 0);
        assert!(trigger.accumulated_entropy() > 0.0);

        trigger.reset_for_checkpoint(200);

        assert_eq!(trigger.keystrokes_since_checkpoint(), 0);
        assert_eq!(trigger.accumulated_entropy(), 0.0);
        assert_eq!(trigger.total_keystrokes(), 10);
    }

    #[test]
    fn test_entropy_hash_changes() {
        let mut trigger = CheckpointTrigger::new();
        let initial_hash = trigger.entropy_hash();

        trigger.record_keystroke(1000, 100);
        let hash1 = trigger.entropy_hash();
        assert_ne!(initial_hash, hash1);

        trigger.record_keystroke(2000, 100);
        let hash2 = trigger.entropy_hash();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_uniform_jitter_yields_zero_entropy() {
        let mut trigger = CheckpointTrigger::new();
        for _ in 0..20 {
            trigger.record_keystroke(1000, 100);
        }
        assert_eq!(trigger.accumulated_entropy(), 0.0);
    }

    #[test]
    fn test_variable_jitter_yields_more_entropy() {
        let mut uniform = CheckpointTrigger::new();
        let mut variable = CheckpointTrigger::new();
        for i in 0..20 {
            uniform.record_keystroke(1000, 100);
            let j = if i % 2 == 0 { 500 } else { 5000 };
            variable.record_keystroke(j, 100);
        }
        assert!(
            variable.accumulated_entropy() > uniform.accumulated_entropy(),
            "Variable jitter ({}) should yield more entropy than uniform ({})",
            variable.accumulated_entropy(),
            uniform.accumulated_entropy()
        );
    }

    #[test]
    fn test_trigger_event_fields() {
        let mut trigger = CheckpointTrigger::new();
        for j in [500, 3000, 800, 4000, 600] {
            trigger.record_keystroke(j, 100);
        }

        let event = trigger.manual_trigger(150);

        assert!(event.timestamp <= Utc::now());
        assert_eq!(event.keystroke_count, 5);
        assert!(event.entropy_bits > 0.0);
        assert_eq!(event.document_size, 150);
    }

    #[test]
    fn test_trigger_event_serde_roundtrip() {
        let mut trigger = CheckpointTrigger::new();
        for j in [500, 3000, 800, 4000, 600] {
            trigger.record_keystroke(j, 100);
        }
        let event = trigger.manual_trigger(150);

        let json = serde_json::to_string(&event).unwrap();
        let restored: TriggerEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(event.reason, restored.reason);
        assert_eq!(event.keystroke_count, restored.keystroke_count);
    }
}
