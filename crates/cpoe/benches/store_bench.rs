// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! Store query benchmarks: measures the five query patterns that benefit from
//! the v2 covering indexes added in the integrity.rs migration.
//!
//! Each benchmark runs in two groups:
//!   "with_indexes"    — normal SecureStore (all indexes present)
//!   "without_indexes" — same store with the five new indexes explicitly dropped
//!
//! Run with:
//!   cargo bench --bench store_bench --features test-utils

use cpoe_engine::store::SecureStore;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rusqlite::Connection;
use std::time::Duration;
use tempfile::TempDir;
use zeroize::Zeroizing;

const ROW_COUNT: usize = 100_000;
const FILE_COUNT: usize = 100;
const DEVICE_COUNT: usize = 5;

fn hmac_key() -> Zeroizing<Vec<u8>> {
    Zeroizing::new(vec![0x42u8; 32])
}

fn device_id(i: usize) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[0] = (i & 0xFF) as u8;
    b[1] = ((i >> 8) & 0xFF) as u8;
    b
}

fn make_populated_store() -> (TempDir, SecureStore) {
    let dir = TempDir::new().expect("tmpdir");
    let db_path = dir.path().join("bench.db");
    let mut store = SecureStore::open(&db_path, hmac_key()).expect("open store");

    // Bulk insert via raw connection — bypasses HMAC chain to keep setup fast.
    // Bench goal is query performance, not write performance (see crypto_bench).
    {
        let conn = store.raw_conn_mut();
        let tx = conn.transaction().expect("tx");
        let mut stmt = tx
            .prepare(
                "INSERT INTO secure_events (
                    device_id, machine_id, timestamp_ns, file_path,
                    content_hash, file_size, size_delta,
                    previous_hash, event_hash, hmac,
                    context_type, context_note,
                    vdf_iterations, forensic_score, is_paste
                 ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            )
            .expect("prepare events");

        let base_ts: i64 = 1_700_000_000_000_000_000;
        let content_hash = [0xABu8; 32];
        let prev_hash = [0u8; 32];
        let fake_hmac = [0xFFu8; 32];

        for i in 0..ROW_COUNT {
            let file_path = format!("/home/user/docs/document_{:04}.md", i % FILE_COUNT);
            let dev = device_id(i % DEVICE_COUNT);
            let ts = base_ts + (i as i64) * 1_000_000;
            // 80% of rows have context_note; 20% are NULL (simulates already-pruned rows).
            let note: Option<&str> = if i % 5 == 0 { None } else { Some("draft notes") };
            let mut event_hash = [0u8; 32];
            event_hash[0] = (i & 0xFF) as u8;
            event_hash[1] = ((i >> 8) & 0xFF) as u8;
            event_hash[2] = ((i >> 16) & 0xFF) as u8;
            event_hash[3] = ((i >> 24) & 0xFF) as u8;

            stmt.execute(rusqlite::params![
                &dev[..],
                "bench-machine",
                ts,
                file_path,
                &content_hash[..],
                1024i64,
                (i as i32 % 200) - 100,
                &prev_hash[..],
                &event_hash[..],
                &fake_hmac[..],
                "checkpoint",
                note,
                0i64,
                0.95f64,
                0i32,
            ])
            .expect("insert event");
        }
        drop(stmt);
        tx.commit().expect("commit events");
    }

    // Insert 10K text_fragments: 90% synced, 10% NULL (unsynced).
    {
        let conn = store.raw_conn_mut();
        let tx = conn.transaction().expect("tx");
        let mut stmt = tx
            .prepare(
                "INSERT INTO text_fragments
                    (fragment_hash, session_id, source_signature, nonce, timestamp, sync_state)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .expect("prepare frags");

        let sig = [0x01u8; 64];
        let base_ts: i64 = 1_700_000_000_000;
        for i in 0..10_000usize {
            let mut hash = [0u8; 32];
            hash[0] = (i & 0xFF) as u8;
            hash[1] = ((i >> 8) & 0xFF) as u8;
            hash[2] = ((i >> 16) & 0xFF) as u8;
            let mut nonce = [0u8; 16];
            nonce[0] = (i & 0xFF) as u8;
            nonce[1] = ((i >> 8) & 0xFF) as u8;
            let sync: Option<&str> = if i % 10 == 0 { None } else { Some("synced") };
            stmt.execute(rusqlite::params![
                &hash[..],
                format!("session-{:04}", i % 200),
                &sig[..],
                &nonce[..],
                base_ts + i as i64 * 1000,
                sync,
            ])
            .expect("insert frag");
        }
        drop(stmt);
        tx.commit().expect("commit frags");
    }

    // Insert 5K clipboard events across 10 apps.
    {
        let conn = store.raw_conn_mut();
        let tx = conn.transaction().expect("tx");
        let mut stmt = tx
            .prepare(
                "INSERT INTO clipboard_events
                    (fragment_hash, app_bundle_id, text_hash, pasteboard_change_count,
                     timestamp, captured_at)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .expect("prepare clips");

        let apps = [
            "com.apple.Notes",
            "com.microsoft.Word",
            "com.apple.Pages",
            "com.sublimetext.4",
            "com.jetbrains.goland",
            "com.github.atom",
            "com.sublimetext.3",
            "com.apple.TextEdit",
            "com.writerslogic.witnessd",
            "com.google.Chrome",
        ];
        let base_ts: i64 = 1_700_000_000_000;
        let text_hash = [0xCCu8; 32];
        for i in 0..5_000usize {
            let mut fhash = [0u8; 32];
            fhash[0] = (i & 0xFF) as u8;
            fhash[1] = ((i >> 8) & 0xFF) as u8;
            stmt.execute(rusqlite::params![
                &fhash[..],
                apps[i % apps.len()],
                &text_hash[..],
                i as i32,
                base_ts + i as i64 * 2000,
                base_ts + i as i64 * 2000 + 100,
            ])
            .expect("insert clip");
        }
        drop(stmt);
        tx.commit().expect("commit clips");
    }

    (dir, store)
}

fn drop_v2_indexes(conn: &Connection) {
    conn.execute_batch(
        "DROP INDEX IF EXISTS idx_secure_events_device_id;
         DROP INDEX IF EXISTS idx_secure_events_ts_delta;
         DROP INDEX IF EXISTS idx_secure_events_unpruned;
         DROP INDEX IF EXISTS idx_text_fragments_sync;
         DROP INDEX IF EXISTS idx_clipboard_events_app_ts;",
    )
    .expect("drop v2 indexes");
}

// Q1: DSAR export — WHERE device_id = ? ORDER BY id ASC
// Index: idx_secure_events_device_id (device_id, id)
// Without: full table scan over 100K rows; with: range scan over ~20K rows.
fn bench_device_export(c: &mut Criterion) {
    let mut group = c.benchmark_group("Q1_device_export");
    group.measurement_time(Duration::from_secs(10));

    let (_dir, store) = make_populated_store();
    let dev = device_id(0);

    group.bench_function(BenchmarkId::new("with_indexes", "device_0"), |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT id, timestamp_ns FROM secure_events \
                     WHERE device_id = ? ORDER BY id ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map([dev.as_slice()], |_row| Ok(()))
                .expect("query")
                .count();
            black_box(count)
        })
    });

    drop_v2_indexes(store.raw_conn());

    group.bench_function(BenchmarkId::new("without_indexes", "device_0"), |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT id, timestamp_ns FROM secure_events \
                     WHERE device_id = ? ORDER BY id ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map([dev.as_slice()], |_row| Ok(()))
                .expect("query")
                .count();
            black_box(count)
        })
    });

    group.finish();
}

// Q2: get_all_events_summary — SELECT timestamp_ns, size_delta ORDER BY timestamp_ns
// Index: idx_secure_events_ts_delta (timestamp_ns, size_delta) — covering
// Without: idx_secure_events_timestamp covers timestamp_ns but heap-fetches size_delta.
fn bench_events_summary(c: &mut Criterion) {
    let mut group = c.benchmark_group("Q2_events_summary");
    group.measurement_time(Duration::from_secs(10));

    let (_dir, store) = make_populated_store();

    group.bench_function("with_indexes", |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT timestamp_ns, size_delta FROM secure_events \
                     ORDER BY timestamp_ns ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map([], |row| {
                    let _ts: i64 = row.get::<_, i64>(0)?;
                    let _sd: i32 = row.get::<_, i32>(1)?;
                    Ok(())
                })
                .expect("query")
                .count();
            black_box(count)
        })
    });

    drop_v2_indexes(store.raw_conn());

    group.bench_function("without_indexes", |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT timestamp_ns, size_delta FROM secure_events \
                     ORDER BY timestamp_ns ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map([], |row| {
                    let _ts: i64 = row.get::<_, i64>(0)?;
                    let _sd: i32 = row.get::<_, i32>(1)?;
                    Ok(())
                })
                .expect("query")
                .count();
            black_box(count)
        })
    });

    group.finish();
}

// Q3: prune_payloads re-run — UPDATE … WHERE timestamp_ns < ? AND context_note IS NOT NULL
// Index: idx_secure_events_unpruned (timestamp_ns) WHERE context_note IS NOT NULL
// Scenario: first prune ran; 20% of rows already have context_note = NULL.
// SELECT COUNT proxies the planner work; actual UPDATE benchmarked destructively.
fn bench_prune_rerun(c: &mut Criterion) {
    let mut group = c.benchmark_group("Q3_prune_rerun");
    group.measurement_time(Duration::from_secs(10));

    let (_dir, store) = make_populated_store();
    let base_ts: i64 = 1_700_000_000_000_000_000;
    let quarter_ts = base_ts + (ROW_COUNT as i64 / 4) * 1_000_000;
    let half_ts = base_ts + (ROW_COUNT as i64 / 2) * 1_000_000;

    // Simulate a completed first-pass prune: null out the first quarter.
    store
        .raw_conn()
        .execute(
            "UPDATE secure_events SET context_note = NULL WHERE timestamp_ns < ?",
            [quarter_ts],
        )
        .expect("first prune");

    group.bench_function("with_indexes", |b| {
        b.iter(|| {
            let count: i64 = store
                .raw_conn()
                .query_row(
                    "SELECT COUNT(*) FROM secure_events \
                     WHERE timestamp_ns < ? AND context_note IS NOT NULL",
                    [half_ts],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count");
            black_box(count)
        })
    });

    drop_v2_indexes(store.raw_conn());

    group.bench_function("without_indexes", |b| {
        b.iter(|| {
            let count: i64 = store
                .raw_conn()
                .query_row(
                    "SELECT COUNT(*) FROM secure_events \
                     WHERE timestamp_ns < ? AND context_note IS NOT NULL",
                    [half_ts],
                    |row| row.get::<_, i64>(0),
                )
                .expect("count");
            black_box(count)
        })
    });

    group.finish();
}

// Q4: get_unsynced_fragments — WHERE sync_state IS NULL OR sync_state != 'synced'
// Index: idx_text_fragments_sync (sync_state, timestamp)
// Without: full scan over 10K rows; with: index range scan over ~1K unsynced rows.
fn bench_unsynced_fragments(c: &mut Criterion) {
    let mut group = c.benchmark_group("Q4_unsynced_fragments");
    group.measurement_time(Duration::from_secs(10));

    let (_dir, store) = make_populated_store();

    group.bench_function("with_indexes", |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT id, session_id, timestamp FROM text_fragments \
                     WHERE sync_state IS NULL OR sync_state != 'synced' \
                     ORDER BY timestamp ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map([], |_row| Ok(()))
                .expect("query")
                .count();
            black_box(count)
        })
    });

    drop_v2_indexes(store.raw_conn());

    group.bench_function("without_indexes", |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT id, session_id, timestamp FROM text_fragments \
                     WHERE sync_state IS NULL OR sync_state != 'synced' \
                     ORDER BY timestamp ASC",
                )
                .expect("query");
            let count: usize = stmt
                .query_map([], |_row| Ok(()))
                .expect("query")
                .count();
            black_box(count)
        })
    });

    group.finish();
}

// Q5: clipboard app + time-range — WHERE app_bundle_id = ? AND timestamp BETWEEN ? AND ?
// Index: idx_clipboard_events_app_ts (app_bundle_id, timestamp)
// Without: idx_clipboard_events_timestamp helps time-only filter; app filter adds heap work.
fn bench_clipboard_app_range(c: &mut Criterion) {
    let mut group = c.benchmark_group("Q5_clipboard_app_range");
    group.measurement_time(Duration::from_secs(10));

    let (_dir, store) = make_populated_store();
    let base_ts: i64 = 1_700_000_000_000;
    let end_ts = base_ts + 5_000i64 * 2000;

    group.bench_function("with_indexes", |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT id, timestamp FROM clipboard_events \
                     WHERE app_bundle_id = ? AND timestamp >= ? AND timestamp <= ? \
                     ORDER BY timestamp ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map(
                    rusqlite::params!["com.apple.Notes", base_ts, end_ts],
                    |_row| Ok(()),
                )
                .expect("query")
                .count();
            black_box(count)
        })
    });

    drop_v2_indexes(store.raw_conn());

    group.bench_function("without_indexes", |b| {
        b.iter(|| {
            let mut stmt = store
                .raw_conn()
                .prepare_cached(
                    "SELECT id, timestamp FROM clipboard_events \
                     WHERE app_bundle_id = ? AND timestamp >= ? AND timestamp <= ? \
                     ORDER BY timestamp ASC",
                )
                .expect("prepare");
            let count: usize = stmt
                .query_map(
                    rusqlite::params!["com.apple.Notes", base_ts, end_ts],
                    |_row| Ok(()),
                )
                .expect("query")
                .count();
            black_box(count)
        })
    });

    group.finish();
}

criterion_group!(
    store_benches,
    bench_device_export,
    bench_events_summary,
    bench_prune_rerun,
    bench_unsynced_fragments,
    bench_clipboard_app_range,
);
criterion_main!(store_benches);
