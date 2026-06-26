// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Lock contention and entropy trigger benchmark.
//!
//! Simulates a 120 WPM burst (500 keystrokes at 150ms intervals) with the
//! entropy trigger active. Measures:
//!   1. RwLock write acquisition latency under checkpoint contention
//!   2. In-lock work duration (SHA-256 hash chain + trigger check)
//!   3. Number of entropy-triggered checkpoints during the burst
//!
//! The session's internal fields are `pub(crate)`, so this test replicates the
//! exact hash chain and trigger logic inline rather than touching DocumentSession.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cpoe_engine::sentinel::types::{
    ENTROPY_CHECKPOINT_DST, ENTROPY_CHECKPOINT_MIN_NS, ENTROPY_TRIGGER_THRESHOLD,
};

const BURST_KEYSTROKES: usize = 500;
const INTERVAL_MS: u64 = 150; // ~6.67 KPS ≈ 80 WPM (chars) ≈ 120 WPM (words at 5 cpc)

/// Opaque payload in the shared map, standing in for DocumentSession.
/// Contains only the fields the hash chain + trigger check touches.
struct SessionState {
    jitter_hash_state: [u8; 32],
    last_checkpoint_ns: i64,
    keystroke_count: u64,
    last_checkpoint_keystrokes: u64,
}

#[test]
fn entropy_trigger_lock_contention_bench() {
    // Shared map behind an RwLock — same shape as the sentinel's sessions map.
    let sessions: Arc<std::sync::RwLock<HashMap<String, SessionState>>> =
        Arc::new(std::sync::RwLock::new(HashMap::new()));

    let path = "/tmp/bench_doc.txt".to_string();

    // Initialize session with the same hash chain seed as the sentinel.
    {
        use sha2::{Digest, Sha256};
        let session_id = "bench-session-001";
        let jitter_hash_state: [u8; 32] = {
            let mut h = Sha256::new();
            h.update(ENTROPY_CHECKPOINT_DST);
            h.update(session_id.as_bytes());
            h.finalize().into()
        };
        let mut map = sessions.write().unwrap();
        map.insert(
            path.clone(),
            SessionState {
                jitter_hash_state,
                last_checkpoint_ns: 0,
                keystroke_count: 0,
                last_checkpoint_keystrokes: 0,
            },
        );
    }

    // Background thread: simulates checkpoint contention.
    // Takes a brief write lock every ~50ms, holds it for ~500µs (mirroring
    // the post-checkpoint session update in handle_checkpoint_tick).
    let contention_sessions = Arc::clone(&sessions);
    let contention_running = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let contention_flag = Arc::clone(&contention_running);
    let contention_thread = std::thread::Builder::new()
        .name("checkpoint-contention".into())
        .spawn(move || {
            let mut checkpoint_durations = Vec::new();
            while contention_flag.load(std::sync::atomic::Ordering::Relaxed) {
                let start = Instant::now();
                {
                    let mut map = contention_sessions.write().unwrap();
                    if let Some(session) = map.get_mut("/tmp/bench_doc.txt") {
                        session.last_checkpoint_keystrokes = session.keystroke_count;
                        // Simulate ~500µs of in-lock work (the sentinel reads
                        // semantic counts and updates checkpoint counter).
                        std::thread::sleep(Duration::from_micros(500));
                    }
                }
                checkpoint_durations.push(start.elapsed());
                std::thread::sleep(Duration::from_millis(50));
            }
            checkpoint_durations
        })
        .expect("spawn contention thread");

    // Main thread: simulate 500 keystrokes with instrumented lock timing.
    let mut lock_acquire_us = Vec::with_capacity(BURST_KEYSTROKES);
    let mut in_lock_work_us = Vec::with_capacity(BURST_KEYSTROKES);
    let mut total_per_keystroke_us = Vec::with_capacity(BURST_KEYSTROKES);
    let mut trigger_count = 0usize;
    let mut trigger_timestamps: Vec<i64> = Vec::new();

    let base_ns: i64 = 1_000_000_000_000;
    let interval_ns: i64 = INTERVAL_MS as i64 * 1_000_000;

    for i in 0..BURST_KEYSTROKES {
        let timestamp_ns = base_ns + (i as i64) * interval_ns;
        let duration_since_last_ns: u64 = if i == 0 { 0 } else { interval_ns as u64 };
        let zone: u8 = (i % 5) as u8;

        let t_total = Instant::now();

        // --- Lock acquisition (the contention measurement) ---
        let t_lock = Instant::now();
        let mut map = sessions.write().unwrap();
        let lock_elapsed = t_lock.elapsed();

        let session = map.get_mut(&path).unwrap();

        // --- In-lock work: hash chain update + trigger check ---
        let t_work = Instant::now();

        session.keystroke_count += 1;

        // Hash chain update (mirrors sentinel/event_handlers.rs:307-314).
        {
            use sha2::{Digest, Sha256};
            let mut h = Sha256::new();
            h.update(session.jitter_hash_state);
            h.update(timestamp_ns.to_be_bytes());
            h.update(duration_since_last_ns.to_be_bytes());
            h.update([zone]);
            session.jitter_hash_state = h.finalize().into();
        }

        // Entropy trigger check (mirrors sentinel/event_handlers.rs:318-332).
        let elapsed_since_cp = timestamp_ns.saturating_sub(session.last_checkpoint_ns);
        if elapsed_since_cp >= ENTROPY_CHECKPOINT_MIN_NS {
            let trigger = u32::from_be_bytes(session.jitter_hash_state[..4].try_into().unwrap());
            if trigger < ENTROPY_TRIGGER_THRESHOLD {
                trigger_count += 1;
                trigger_timestamps.push(timestamp_ns);
                session.last_checkpoint_ns = timestamp_ns;
            }
        }

        let work_elapsed = t_work.elapsed();
        drop(map);
        let total_elapsed = t_total.elapsed();

        lock_acquire_us.push(lock_elapsed.as_micros() as f64);
        in_lock_work_us.push(work_elapsed.as_micros() as f64);
        total_per_keystroke_us.push(total_elapsed.as_micros() as f64);

        // Yield occasionally so the contention thread gets CPU time.
        if i % 10 == 0 {
            std::thread::yield_now();
        }
    }

    // Stop contention thread.
    contention_running.store(false, std::sync::atomic::Ordering::Relaxed);
    let checkpoint_durations = contention_thread.join().expect("join contention thread");

    // --- Statistics ---
    let percentile = |vals: &[f64], p: usize| -> f64 {
        let mut sorted = vals.to_vec();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let idx = (p as f64 / 100.0 * (sorted.len() - 1) as f64).round() as usize;
        sorted[idx.min(sorted.len() - 1)]
    };
    let mean = |vals: &[f64]| -> f64 { vals.iter().sum::<f64>() / vals.len().max(1) as f64 };
    let max_val = |vals: &[f64]| -> f64 { vals.iter().cloned().fold(0.0f64, f64::max) };

    let sim_duration_s = BURST_KEYSTROKES as f64 * INTERVAL_MS as f64 / 1000.0;

    println!("\n=== Entropy Checkpoint Lock Contention Benchmark ===");
    println!(
        "Burst: {} keystrokes at {}ms intervals ({:.0} WPM)",
        BURST_KEYSTROKES,
        INTERVAL_MS,
        60_000.0 / INTERVAL_MS as f64 / 5.0,
    );
    println!("Simulated duration: {:.1}s", sim_duration_s);

    println!("\n--- Lock Acquisition Latency (µs) ---");
    println!("  mean:  {:.1}", mean(&lock_acquire_us));
    println!("  p50:   {:.1}", percentile(&lock_acquire_us, 50));
    println!("  p95:   {:.1}", percentile(&lock_acquire_us, 95));
    println!("  p99:   {:.1}", percentile(&lock_acquire_us, 99));
    println!("  max:   {:.1}", max_val(&lock_acquire_us));

    println!("\n--- In-Lock Work: SHA-256 + trigger check (µs) ---");
    println!("  mean:  {:.1}", mean(&in_lock_work_us));
    println!("  p50:   {:.1}", percentile(&in_lock_work_us, 50));
    println!("  p95:   {:.1}", percentile(&in_lock_work_us, 95));
    println!("  p99:   {:.1}", percentile(&in_lock_work_us, 99));
    println!("  max:   {:.1}", max_val(&in_lock_work_us));

    println!("\n--- Total Per-Keystroke: acquire + work + drop (µs) ---");
    println!("  mean:  {:.1}", mean(&total_per_keystroke_us));
    println!("  p50:   {:.1}", percentile(&total_per_keystroke_us, 50));
    println!("  p95:   {:.1}", percentile(&total_per_keystroke_us, 95));
    println!("  p99:   {:.1}", percentile(&total_per_keystroke_us, 99));
    println!("  max:   {:.1}", max_val(&total_per_keystroke_us));

    println!("\n--- Entropy Triggers ---");
    println!("  triggers fired:     {}", trigger_count);
    println!("  simulated time:     {:.1}s", sim_duration_s);
    if trigger_count > 0 {
        println!(
            "  effective rate:     1 per {:.1}s",
            sim_duration_s / trigger_count as f64
        );
        let intervals: Vec<f64> = trigger_timestamps
            .windows(2)
            .map(|w| (w[1] - w[0]) as f64 / 1_000_000_000.0)
            .collect();
        if !intervals.is_empty() {
            println!("  mean interval:      {:.1}s", mean(&intervals));
            println!(
                "  min interval:       {:.1}s",
                intervals.iter().cloned().fold(f64::MAX, f64::min)
            );
            println!("  max interval:       {:.1}s", max_val(&intervals));
        }
    }

    println!("\n--- Background Checkpoint Contention ---");
    let cp_us: Vec<f64> = checkpoint_durations
        .iter()
        .map(|d| d.as_micros() as f64)
        .collect();
    if !cp_us.is_empty() {
        println!("  checkpoint sims:    {}", cp_us.len());
        println!("  mean lock hold:     {:.1}µs", mean(&cp_us));
        println!("  max lock hold:      {:.1}µs", max_val(&cp_us));
    }

    // --- Assertions ---

    // Lock acquisition p99 must stay well under 1ms.
    assert!(
        percentile(&lock_acquire_us, 99) < 1000.0,
        "p99 lock acquisition must be <1ms, got {:.1}µs",
        percentile(&lock_acquire_us, 99),
    );

    // In-lock work (SHA-256 + u32 comparison) must be <50µs mean.
    assert!(
        mean(&in_lock_work_us) < 50.0,
        "Mean in-lock work must be <50µs, got {:.1}µs",
        mean(&in_lock_work_us),
    );

    // At 150ms intervals over 75s with a 10s floor, at most ~7 trigger
    // windows. Probabilistically expect 1-4 triggers.
    assert!(
        trigger_count <= 10,
        "Too many triggers ({}) — floor not enforced?",
        trigger_count,
    );

    // Every trigger interval must respect the 10s floor.
    for w in trigger_timestamps.windows(2) {
        let gap_ns = w[1] - w[0];
        assert!(
            gap_ns >= ENTROPY_CHECKPOINT_MIN_NS,
            "Trigger gap {}ns violates MIN_NS {}",
            gap_ns,
            ENTROPY_CHECKPOINT_MIN_NS,
        );
    }
}
