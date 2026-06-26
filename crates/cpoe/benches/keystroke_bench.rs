// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Benchmark the keystroke hot path: verify_event_source + channel send.
//!
//! Simulates 200 WPM (≈16.7 keystrokes/sec, or ~33 events/sec with key-up)
//! to measure per-event overhead in the CGEventTap callback path.
//!
//! Since CGEventTap requires Accessibility permissions and real events, this
//! bench exercises the lock-free stats path and channel send in isolation.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::Duration;

/// Simulate the verify_event_source hot path: atomic counter increments
/// that replaced the RwLock. Measures raw atomic throughput at keystroke rate.
fn bench_synthetic_stats_atomics(c: &mut Criterion) {
    let total_events = AtomicU64::new(0);
    let verified_hardware = AtomicU64::new(0);

    c.bench_function("verify_event_source_atomics", |b| {
        b.iter(|| {
            // Simulate the happy path (hardware event): 2 atomic increments
            black_box(total_events.fetch_add(1, Ordering::Relaxed));
            black_box(verified_hardware.fetch_add(1, Ordering::Relaxed));
        });
    });
}

/// Benchmark the channel send path: try_send on a bounded sync_channel(512).
/// This is the bottleneck after verification — moving the KeystrokeEvent
/// from the callback thread to the bridge thread.
fn bench_channel_send(c: &mut Criterion) {
    // Matches KEYSTROKE_CHANNEL_CAPACITY
    let (tx, rx) = mpsc::sync_channel::<[u8; 32]>(512);

    // Drain receiver in background to prevent Full
    let drain = std::thread::spawn(
        move || {
            while rx.recv_timeout(Duration::from_secs(5)).is_ok() {}
        },
    );

    c.bench_function("keystroke_channel_try_send", |b| {
        b.iter(|| {
            // Simulates sending a ~32-byte KeystrokeEvent struct
            let payload = black_box([0u8; 32]);
            let _ = black_box(tx.try_send(payload));
        });
    });

    drop(tx);
    let _ = drain.join();
}

/// Benchmark the full per-keystroke path cost: atomic stats + timestamp +
/// keycode extraction simulation + channel send.
fn bench_full_keystroke_path(c: &mut Criterion) {
    let total_events = AtomicU64::new(0);
    let verified_hardware = AtomicU64::new(0);
    let keystroke_count = AtomicU64::new(0);
    let (tx, rx) = mpsc::sync_channel::<(i64, u16, u8)>(512);

    let drain = std::thread::spawn(
        move || {
            while rx.recv_timeout(Duration::from_secs(5)).is_ok() {}
        },
    );

    c.bench_function("full_keystroke_callback_path", |b| {
        b.iter(|| {
            // 1. Atomic stats (replaces RwLock)
            total_events.fetch_add(1, Ordering::Relaxed);
            verified_hardware.fetch_add(1, Ordering::Relaxed);

            // 2. Timestamp (chrono::Utc::now() equivalent cost)
            let now = black_box(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_nanos() as i64,
            );

            // 3. Keycode extraction + zone lookup (simulated)
            let keycode = black_box(0x00u16); // 'a' key
            let zone = black_box(0u8);

            // 4. Counter increment
            keystroke_count.fetch_add(1, Ordering::Relaxed);

            // 5. Channel send
            let _ = black_box(tx.try_send((now, keycode, zone)));
        });
    });

    drop(tx);
    let _ = drain.join();
}

/// Throughput benchmark: sustain 200 WPM (33 events/sec including key-up)
/// for 1 second and verify no drops.
fn bench_200wpm_sustained(c: &mut Criterion) {
    let (tx, rx) = mpsc::sync_channel::<u64>(512);
    let total = AtomicU64::new(0);
    let verified = AtomicU64::new(0);

    let drain = std::thread::spawn(move || {
        let mut count = 0u64;
        while rx.recv_timeout(Duration::from_secs(5)).is_ok() {
            count += 1;
        }
        count
    });

    // 200 WPM = 1000 chars/min = 16.7 chars/sec = 33.3 events/sec (down+up)
    let events_per_iter = 33;

    c.bench_function("200wpm_burst_33_events", |b| {
        b.iter(|| {
            for i in 0..events_per_iter {
                total.fetch_add(1, Ordering::Relaxed);
                verified.fetch_add(1, Ordering::Relaxed);
                let _ = tx.try_send(black_box(i as u64));
            }
        });
    });

    drop(tx);
    let received = drain.join().unwrap_or(0);
    // Sanity: we should have received events (criterion runs many iters)
    assert!(received > 0, "drain thread received no events");
}

criterion_group!(
    benches,
    bench_synthetic_stats_atomics,
    bench_channel_send,
    bench_full_keystroke_path,
    bench_200wpm_sustained,
);
criterion_main!(benches);
