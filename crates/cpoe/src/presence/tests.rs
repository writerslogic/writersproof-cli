// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::*;
use std::time::Duration;

fn test_config() -> Config {
    Config {
        challenge_interval: Duration::from_secs(1),
        interval_variance: 0.0,
        response_window: Duration::from_secs(60),
        enabled_challenges: vec![
            ChallengeType::TypePhrase,
            ChallengeType::SimpleMath,
            ChallengeType::TypeWord,
        ],
    }
}

#[test]
fn test_challenge_lifecycle_type_word() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..Default::default()
    })
    .unwrap();

    let _session = verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue challenge");

    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt format");
    let ok = verifier
        .respond_to_challenge(&challenge.id, word)
        .expect("respond");
    assert!(ok);

    let session = verifier.end_session().expect("end session");
    assert_eq!(session.challenges_passed, 1);
    assert_eq!(session.challenges_failed, 0);
    assert_eq!(session.challenges_missed, 0);
}

#[test]
fn test_challenge_lifecycle_type_phrase() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypePhrase],
        ..test_config()
    })
    .unwrap();

    let _session = verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue challenge");

    let phrase = challenge
        .prompt
        .strip_prefix("Type the phrase: ")
        .expect("prompt format");
    let ok = verifier
        .respond_to_challenge(&challenge.id, phrase)
        .expect("respond");
    assert!(ok);

    let session = verifier.end_session().expect("end session");
    assert_eq!(session.challenges_passed, 1);
}

#[test]
fn test_challenge_lifecycle_simple_math() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::SimpleMath],
        ..test_config()
    })
    .unwrap();

    let _session = verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue challenge");

    let prompt = challenge
        .prompt
        .strip_prefix("Solve: ")
        .expect("prompt format");
    let prompt = prompt.strip_suffix(" = ?").expect("prompt suffix");

    let parts: Vec<&str> = prompt.split_whitespace().collect();
    assert_eq!(parts.len(), 3);
    let a: i32 = parts[0].parse().expect("first operand");
    let op = parts[1];
    let b: i32 = parts[2].parse().expect("second operand");

    let result = match op {
        "+" => a + b,
        "-" => a - b,
        "*" => a * b,
        _ => panic!("unknown operator"),
    };

    let ok = verifier
        .respond_to_challenge(&challenge.id, &result.to_string())
        .expect("respond");
    assert!(ok);

    let session = verifier.end_session().expect("end session");
    assert_eq!(session.challenges_passed, 1);
}

#[test]
fn test_start_session_while_active() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    verifier.start_session().expect("start session");
    let err = verifier.start_session().unwrap_err();
    assert!(err.contains("already active"));
}

#[test]
fn test_end_session_no_active() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    let err = verifier.end_session().unwrap_err();
    assert!(err.contains("no active session"));
}

#[test]
fn test_end_session_already_ended() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    verifier.start_session().expect("start session");
    verifier.end_session().expect("end session");
    let err = verifier.end_session().unwrap_err();
    assert!(err.contains("no active session"));
}

#[test]
fn test_issue_challenge_no_session() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    let err = verifier.issue_challenge().unwrap_err();
    assert!(err.contains("no active session"));
}

#[test]
fn test_respond_no_session() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    let err = verifier
        .respond_to_challenge("some-id", "response")
        .unwrap_err();
    assert!(err.contains("no active session"));
}

#[test]
fn test_respond_challenge_not_found() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    verifier.start_session().expect("start session");
    let err = verifier
        .respond_to_challenge("nonexistent-id", "response")
        .unwrap_err();
    assert!(err.contains("challenge not found"));
}

#[test]
fn test_wrong_response_fails() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue challenge");

    let ok = verifier
        .respond_to_challenge(&challenge.id, "completely wrong answer")
        .expect("respond");
    assert!(!ok);

    let session = verifier.end_session().expect("end session");
    assert_eq!(session.challenges_passed, 0);
    assert_eq!(session.challenges_failed, 1);
}

#[test]
fn test_respond_twice_to_same_challenge() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue challenge");

    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt format");
    verifier
        .respond_to_challenge(&challenge.id, word)
        .expect("first respond");

    let err = verifier
        .respond_to_challenge(&challenge.id, word)
        .unwrap_err();
    assert!(err.contains("already resolved"));
}

#[test]
fn test_multiple_challenges() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");

    for _ in 0..5 {
        let challenge = verifier.issue_challenge().expect("issue");
        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");
    }

    let session = verifier.end_session().expect("end session");
    assert_eq!(session.challenges_issued, 5);
    assert_eq!(session.challenges_passed, 5);
    assert_eq!(session.verification_rate, 1.0);
}

#[test]
fn test_verification_rate_calculation() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");

    for _ in 0..2 {
        let challenge = verifier.issue_challenge().expect("issue");
        let word = challenge
            .prompt
            .strip_prefix("Type the word: ")
            .expect("prompt");
        verifier
            .respond_to_challenge(&challenge.id, word)
            .expect("respond");
    }

    for _ in 0..2 {
        let challenge = verifier.issue_challenge().expect("issue");
        verifier
            .respond_to_challenge(&challenge.id, "wrong")
            .expect("respond");
    }

    let session = verifier.end_session().expect("end session");
    assert_eq!(session.challenges_issued, 4);
    assert_eq!(session.challenges_passed, 2);
    assert_eq!(session.challenges_failed, 2);
    assert_eq!(session.verification_rate, 0.5);
}

#[test]
fn test_active_session() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    assert!(verifier.active_session().is_none());

    verifier.start_session().expect("start session");
    assert!(verifier.active_session().is_some());
    assert!(verifier.active_session().expect("active session").active);

    verifier.end_session().expect("end session");
    assert!(verifier.active_session().is_none());
}

#[test]
fn test_next_challenge_time_no_session() {
    let mut verifier = Verifier::new(test_config()).unwrap();
    assert!(verifier.next_challenge_time().unwrap().is_none());
}

#[test]
fn test_next_challenge_time_with_session() {
    let mut verifier = Verifier::new(test_config()).unwrap();
    verifier.start_session().expect("start session");

    let next_time = verifier.next_challenge_time().expect("no error");
    assert!(next_time.is_some());
}

#[test]
fn test_should_issue_challenge() {
    let mut verifier = Verifier::new(Config {
        challenge_interval: Duration::from_millis(1),
        interval_variance: 0.0,
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    std::thread::sleep(Duration::from_millis(10));
    assert!(verifier.should_issue_challenge().expect("no error"));
}

#[test]
fn test_should_issue_challenge_no_session() {
    let mut verifier = Verifier::new(test_config()).unwrap();
    assert!(!verifier.should_issue_challenge().expect("no error"));
}

/// H-057: next_challenge_time must propagate a duration conversion error rather than
/// silently substituting a default window.
#[test]
fn test_next_challenge_time_no_implicit_window_substitution() {
    // A challenge_interval near Duration::MAX causes from_std to fail because the
    // nanosecond count overflows i64 (chrono's internal representation). Confirm the
    // error surfaces rather than being replaced with an arbitrary fallback window.
    let huge_interval = Duration::from_secs(u64::MAX / 2);
    // Validation only checks zero / variance bounds, not chrono overflow, so new() succeeds.
    let config = Config {
        challenge_interval: huge_interval,
        interval_variance: 0.0,
        response_window: Duration::from_secs(60),
        enabled_challenges: vec![ChallengeType::TypePhrase],
    };
    let mut verifier = Verifier::new(config).unwrap();
    verifier.start_session().expect("start session");
    let result = verifier.next_challenge_time();
    assert!(
        result.is_err(),
        "out-of-range interval must return Err, not a substituted window"
    );
}

#[test]
fn test_case_insensitive_response() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue");

    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt");
    let uppercase = word.to_uppercase();

    let ok = verifier
        .respond_to_challenge(&challenge.id, &uppercase)
        .expect("respond");
    assert!(ok);
}

#[test]
fn test_response_with_whitespace() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue");

    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt");
    let with_spaces = format!("  {}  ", word);

    let ok = verifier
        .respond_to_challenge(&challenge.id, &with_spaces)
        .expect("respond");
    assert!(ok);
}

#[test]
fn test_session_encode_decode() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue");
    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt");
    verifier
        .respond_to_challenge(&challenge.id, word)
        .expect("respond");
    let session = verifier.end_session().expect("end session");

    let encoded = session.encode().expect("encode");
    let decoded = Session::decode(&encoded).expect("decode");

    assert_eq!(decoded.id, session.id);
    assert_eq!(decoded.challenges.len(), session.challenges.len());
    assert_eq!(decoded.challenges_passed, session.challenges_passed);
}

#[test]
fn test_compile_evidence_empty() {
    let evidence = compile_evidence(&[]);
    assert_eq!(evidence.total_challenges, 0);
    assert_eq!(evidence.total_passed, 0);
    assert_eq!(evidence.overall_rate, 0.0);
}

#[test]
fn test_compile_evidence_multiple_sessions() {
    let mut verifier1 = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();
    verifier1.start_session().expect("start");
    let c1 = verifier1.issue_challenge().expect("issue");
    let w1 = c1.prompt.strip_prefix("Type the word: ").expect("prompt");
    verifier1.respond_to_challenge(&c1.id, w1).expect("respond");
    let session1 = verifier1.end_session().expect("end");

    let mut verifier2 = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();
    verifier2.start_session().expect("start");
    let c2 = verifier2.issue_challenge().expect("issue");
    verifier2
        .respond_to_challenge(&c2.id, "wrong")
        .expect("respond");
    let session2 = verifier2.end_session().expect("end");

    let evidence = compile_evidence(&[session1, session2]);
    assert_eq!(evidence.total_challenges, 2);
    assert_eq!(evidence.total_passed, 1);
    assert_eq!(evidence.overall_rate, 0.5);
}

#[test]
fn test_default_config() {
    let config = Config::default();
    assert_eq!(config.challenge_interval, Duration::from_secs(10 * 60));
    assert_eq!(config.interval_variance, 0.5);
    assert_eq!(config.response_window, Duration::from_secs(60));
    assert_eq!(config.enabled_challenges.len(), 3);
}

#[test]
fn test_empty_enabled_challenges_falls_back() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue challenge");

    assert!(challenge.prompt.starts_with("Type the phrase:"));
}

#[test]
fn test_challenge_status_transitions() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue");
    assert_eq!(challenge.status, ChallengeStatus::Pending);

    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt");
    verifier
        .respond_to_challenge(&challenge.id, word)
        .expect("respond");

    let session = verifier.active_session().expect("active session");
    assert_eq!(session.challenges[0].status, ChallengeStatus::Passed);
}

#[test]
fn test_session_has_unique_id() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    let session1 = verifier.start_session().expect("start 1");
    verifier.end_session().expect("end 1");

    let session2 = verifier.start_session().expect("start 2");
    verifier.end_session().expect("end 2");

    assert_ne!(session1.id, session2.id);
}

#[test]
fn test_challenge_has_unique_id() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let c1 = verifier.issue_challenge().expect("issue 1");
    let c2 = verifier.issue_challenge().expect("issue 2");

    assert_ne!(c1.id, c2.id);
}

#[test]
fn test_challenge_timestamps() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        response_window: Duration::from_secs(60),
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue");

    assert!(challenge.expires_at > challenge.issued_at);
    assert_eq!(challenge.window, Duration::from_secs(60));
}

#[test]
fn test_session_timestamps() {
    let mut verifier = Verifier::new(test_config()).unwrap();

    let session = verifier.start_session().expect("start");
    let start_time = session.start_time;
    assert!(session.end_time.is_none());

    std::thread::sleep(Duration::from_millis(10));
    let ended = verifier.end_session().expect("end");
    assert!(ended.end_time.is_some());
    assert!(ended.end_time.expect("end time set") > start_time);
}

#[test]
fn test_challenge_response_recorded() {
    let mut verifier = Verifier::new(Config {
        enabled_challenges: vec![ChallengeType::TypeWord],
        ..test_config()
    })
    .unwrap();

    verifier.start_session().expect("start session");
    let challenge = verifier.issue_challenge().expect("issue");
    let word = challenge
        .prompt
        .strip_prefix("Type the word: ")
        .expect("prompt");

    verifier
        .respond_to_challenge(&challenge.id, word)
        .expect("respond");

    let session = verifier.active_session().expect("active session");
    assert!(session.challenges[0].responded_at.is_some());
    assert!(session.challenges[0].response_hash.is_some());
}

#[test]
fn test_all_challenge_types_verifiable() {
    for challenge_type in [
        ChallengeType::TypePhrase,
        ChallengeType::SimpleMath,
        ChallengeType::TypeWord,
    ] {
        let mut verifier = Verifier::new(Config {
            enabled_challenges: vec![challenge_type.clone()],
            ..test_config()
        })
        .unwrap();

        verifier.start_session().expect("start session");
        let challenge = verifier.issue_challenge().expect("issue");

        match challenge_type {
            ChallengeType::TypePhrase => {
                assert!(challenge.prompt.starts_with("Type the phrase:"))
            }
            ChallengeType::SimpleMath => assert!(challenge.prompt.starts_with("Solve:")),
            ChallengeType::TypeWord => assert!(challenge.prompt.starts_with("Type the word:")),
        }

        verifier.end_session().expect("end session");
    }
}
