// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

//! File relationship detection: identifies co-edited document pairs based on
//! focus switch patterns across active sessions.

use super::types::DocumentSession;
#[cfg(test)]
use super::types::FocusSwitchRecord;
use std::collections::HashMap;
use std::time::Duration;

/// Maximum gap between focus switches to count as a co-edit cycle.
/// If the user switches A->B and then B->A within this window, it counts.
const MAX_CO_EDIT_GAP: Duration = Duration::from_secs(5 * 60);

/// A pair of documents that are frequently edited together.
#[derive(Debug, Clone)]
pub struct CoEditedPair {
    /// First document path (lexicographically smaller).
    pub path_a: String,
    /// Second document path (lexicographically larger).
    pub path_b: String,
    /// Number of A->B->A co-edit cycles detected.
    pub switch_count: u32,
    /// Average gap in milliseconds between the outgoing and return switches.
    pub avg_gap_ms: f64,
}

/// Detect co-edited file pairs from active sessions.
///
/// A "co-edit cycle" is when focus switches from document A to document B
/// and then back to A, with each leg completing within `MAX_CO_EDIT_GAP`.
/// Pairs with at least `min_switches` cycles are returned, sorted by
/// switch_count descending.
pub fn detect_co_edited_files(
    sessions: &HashMap<String, DocumentSession>,
    min_switches: u32,
) -> Vec<CoEditedPair> {
    // Build a timeline of focus switches per session: each record tells us
    // "while editing <path>, focus went to <target_app> at <lost_at> and
    // came back at <regained_at>". We need to match these with the *other*
    // session's path to detect A->B transitions.
    //
    // Strategy: for each pair (path_a, path_b), scan path_a's focus_switches
    // for records where the user switched to an app, and check if path_b's
    // focus_switches show a corresponding gain around the same time. Since
    // focus_switches record target_app (not target_path), we use timing
    // correlation: if A loses focus at time T and B gains focus within a
    // small window, the switch was A->B.

    let paths: Vec<&String> = sessions.keys().collect();
    if paths.len() < 2 {
        return Vec::new();
    }

    // For each session, build a list of (lost_at_ms, regained_at_ms) pairs
    // representing intervals when focus was away.
    let away_intervals: HashMap<&String, Vec<(i64, i64)>> = sessions
        .iter()
        .map(|(path, session)| {
            let intervals: Vec<(i64, i64)> = session
                .focus_switches
                .iter()
                .filter_map(|fs| {
                    let lost = system_time_to_ms(&fs.lost_at)?;
                    let regained = system_time_to_ms(&fs.regained_at?)?;
                    Some((lost, regained))
                })
                .collect();
            (path, intervals)
        })
        .collect();

    // For each ordered pair (a, b), count how many times a's "away" interval
    // overlaps with b being focused (i.e. b does NOT have an away interval
    // covering that time), AND the reverse trip also happens shortly after.
    let mut pair_stats: HashMap<(&String, &String), (u32, Vec<f64>)> = HashMap::new();

    for i in 0..paths.len() {
        for j in (i + 1)..paths.len() {
            let (path_a, path_b) = if paths[i] < paths[j] {
                (paths[i], paths[j])
            } else {
                (paths[j], paths[i])
            };

            let intervals_a = match away_intervals.get(path_a) {
                Some(v) => v,
                None => continue,
            };
            let intervals_b = match away_intervals.get(path_b) {
                Some(v) => v,
                None => continue,
            };

            let max_gap_ms =
                i64::try_from(MAX_CO_EDIT_GAP.as_millis()).unwrap_or(i64::MAX);

            // For each time A loses focus, check if B gains focus around
            // that time (B has a regained_at near A's lost_at). Then check
            // if B subsequently loses focus and A regains, forming a cycle.
            let mut count: u32 = 0;
            let mut gaps: Vec<f64> = Vec::new();

            for &(a_lost, a_regained) in intervals_a {
                // A was away from a_lost to a_regained.
                // Check if B had focus during that window by looking for a
                // B away-interval whose regained_at is near a_lost (B came
                // back just before or at A's loss) and whose lost_at is
                // near a_regained (B lost focus when A came back).
                //
                // Simpler: find a B away-interval that starts within a
                // small window of a_lost (B lost focus because A came back
                // to itself, which means this B interval is *the same
                // switch*). Actually, the cleaner approach is: B should
                // have an away-interval that starts near a_regained
                // (when A comes back, B loses focus).
                //
                // The co-edit cycle A->B->A means:
                //   1. A loses focus at a_lost
                //   2. B gains focus ~ a_lost (B's previous away ends)
                //   3. B loses focus ~ a_regained (B starts a new away)
                //   4. A regains focus at a_regained
                //
                // So we look for a B interval where regained_at ~ a_lost
                // (or B just gained focus). But that requires B to have
                // been away before. A simpler model: look for B away
                // intervals whose lost_at is within [a_lost, a_regained].
                // That means B started being away (lost focus) while A was
                // also away, suggesting B had focus between a_lost and
                // b_lost, forming the A->B leg. Then B losing focus at
                // b_lost corresponds to A regaining at a_regained.

                for &(b_lost, _b_regained) in intervals_b {
                    // B lost focus during A's away period
                    if b_lost >= a_lost && b_lost <= a_regained {
                        let gap = (a_regained - a_lost).abs();
                        if gap <= max_gap_ms {
                            count += 1;
                            gaps.push(gap as f64);
                            break; // count at most one B match per A interval
                        }
                    }
                }
            }

            if count > 0 {
                pair_stats.insert((path_a, path_b), (count, gaps));
            }
        }
    }

    let mut results: Vec<CoEditedPair> = pair_stats
        .into_iter()
        .filter(|(_, (count, _))| *count >= min_switches)
        .map(|((path_a, path_b), (count, gaps))| {
            let avg_gap_ms = if gaps.is_empty() {
                0.0
            } else {
                gaps.iter().sum::<f64>() / gaps.len() as f64
            };
            CoEditedPair {
                path_a: path_a.clone(),
                path_b: path_b.clone(),
                switch_count: count,
                avg_gap_ms,
            }
        })
        .collect();

    results.sort_by(|a, b| b.switch_count.cmp(&a.switch_count));
    results
}

/// Convert `SystemTime` to milliseconds since UNIX epoch, returning `None`
/// on error (clock before epoch).
fn system_time_to_ms(t: &std::time::SystemTime) -> Option<i64> {
    t.duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_millis()).ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ObfuscatedString;
    use std::collections::VecDeque;
    use std::time::{Duration, SystemTime};

    /// Create a minimal `DocumentSession` with the given path and focus switches.
    fn mock_session(path: &str, switches: Vec<FocusSwitchRecord>) -> DocumentSession {
        let mut session = DocumentSession::new(
            path.to_string(),
            "com.test.app".to_string(),
            "Test App".to_string(),
            ObfuscatedString::new("test"),
        );
        session.focus_switches = VecDeque::from(switches);
        session
    }

    fn make_switch(lost_offset_ms: u64, regained_offset_ms: u64) -> FocusSwitchRecord {
        let base = SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        FocusSwitchRecord {
            lost_at: base + Duration::from_millis(lost_offset_ms),
            regained_at: Some(base + Duration::from_millis(regained_offset_ms)),
            target_app: "Other App".to_string(),
            target_bundle_id: "com.other.app".to_string(),
        }
    }

    #[test]
    fn test_no_sessions() {
        let sessions = HashMap::new();
        let result = detect_co_edited_files(&sessions, 3);
        assert!(result.is_empty());
    }

    #[test]
    fn test_single_session() {
        let mut sessions = HashMap::new();
        sessions.insert(
            "/a.md".to_string(),
            mock_session("/a.md", vec![make_switch(0, 1000)]),
        );
        let result = detect_co_edited_files(&sessions, 1);
        assert!(result.is_empty());
    }

    #[test]
    fn test_co_edit_detected() {
        // Simulate 4 co-edit cycles between A and B:
        // A loses focus, B has focus, B loses focus, A regains.
        let mut sessions = HashMap::new();

        // A's away intervals: A is away during [0..2000], [5000..7000],
        // [10000..12000], [15000..17000]
        let a_switches = vec![
            make_switch(0, 2000),
            make_switch(5000, 7000),
            make_switch(10000, 12000),
            make_switch(15000, 17000),
        ];

        // B's away intervals: B loses focus at times that fall within A's
        // away windows. B lost at 1000 (within A's [0..2000]), etc.
        let b_switches = vec![
            make_switch(1000, 3000),
            make_switch(6000, 8000),
            make_switch(11000, 13000),
            make_switch(16000, 18000),
        ];

        sessions.insert("/a.md".to_string(), mock_session("/a.md", a_switches));
        sessions.insert("/b.md".to_string(), mock_session("/b.md", b_switches));

        let result = detect_co_edited_files(&sessions, 3);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].path_a, "/a.md");
        assert_eq!(result[0].path_b, "/b.md");
        assert!(result[0].switch_count >= 4);
        assert!(result[0].avg_gap_ms > 0.0);
    }

    #[test]
    fn test_below_min_switches_threshold() {
        let mut sessions = HashMap::new();

        // Only 1 co-edit cycle
        let a_switches = vec![make_switch(0, 2000)];
        let b_switches = vec![make_switch(1000, 3000)];

        sessions.insert("/a.md".to_string(), mock_session("/a.md", a_switches));
        sessions.insert("/b.md".to_string(), mock_session("/b.md", b_switches));

        // Require 3, only have 1
        let result = detect_co_edited_files(&sessions, 3);
        assert!(result.is_empty());

        // Require 1, should find it
        let result = detect_co_edited_files(&sessions, 1);
        assert_eq!(result.len(), 1);
    }

    #[test]
    fn test_gap_exceeds_max_window() {
        let mut sessions = HashMap::new();

        // A is away for 6 minutes (360_000 ms), exceeds 5-minute max
        let a_switches = vec![make_switch(0, 360_000)];
        let b_switches = vec![make_switch(100_000, 400_000)];

        sessions.insert("/x.md".to_string(), mock_session("/x.md", a_switches));
        sessions.insert("/y.md".to_string(), mock_session("/y.md", b_switches));

        let result = detect_co_edited_files(&sessions, 1);
        assert!(result.is_empty());
    }

    #[test]
    fn test_sorted_by_switch_count_descending() {
        let mut sessions = HashMap::new();

        // A-B: 4 cycles
        let a_switches = vec![
            make_switch(0, 2000),
            make_switch(5000, 7000),
            make_switch(10000, 12000),
            make_switch(15000, 17000),
        ];
        let b_switches = vec![
            make_switch(1000, 3000),
            make_switch(6000, 8000),
            make_switch(11000, 13000),
            make_switch(16000, 18000),
        ];

        // A-C: 2 cycles
        let c_switches = vec![
            make_switch(1000, 3000),
            make_switch(6000, 8000),
        ];

        sessions.insert("/a.md".to_string(), mock_session("/a.md", a_switches));
        sessions.insert("/b.md".to_string(), mock_session("/b.md", b_switches));
        sessions.insert("/c.md".to_string(), mock_session("/c.md", c_switches));

        let result = detect_co_edited_files(&sessions, 1);
        assert!(result.len() >= 2);
        // First result should have higher switch_count
        assert!(result[0].switch_count >= result[1].switch_count);
    }

    #[test]
    fn test_unregained_focus_switches_ignored() {
        let mut sessions = HashMap::new();

        // Switch with no regained_at should be ignored
        let a_switches = vec![FocusSwitchRecord {
            lost_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_700_000_000),
            regained_at: None,
            target_app: "Other".to_string(),
            target_bundle_id: "com.other".to_string(),
        }];
        let b_switches = vec![make_switch(0, 2000)];

        sessions.insert("/a.md".to_string(), mock_session("/a.md", a_switches));
        sessions.insert("/b.md".to_string(), mock_session("/b.md", b_switches));

        let result = detect_co_edited_files(&sessions, 1);
        assert!(result.is_empty());
    }
}
