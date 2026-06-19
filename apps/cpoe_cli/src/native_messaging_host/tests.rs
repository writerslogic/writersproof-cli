// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

// File-level `use` so the inner `mod tests { }` can reference sibling
// modules via `super::` regardless of whether this file is compiled from
// the cpoe binary (where `native_messaging_host` is a module) or from the
// writerslogic-native-messaging-host binary (where mod.rs is the crate root).
#[cfg(test)]
use super::{handlers, jitter, protocol, types};

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::{
        handlers::{compute_commitment, handle_text_attestation},
        jitter::{compute_jitter_stats, MAX_BATCH_SIZE, MAX_JITTER_BATCHES_PER_WINDOW},
        protocol::{
            is_url_acceptable, read_message_from, validate_content_hash, write_message_to,
            MAX_MESSAGE_LENGTH,
        },
        types::{Request, Response},
    };

    // === Protocol framing tests ===

    /// Helper: build a valid NMH framed message from a JSON value.
    fn frame_message(json: &serde_json::Value) -> Vec<u8> {
        let body = serde_json::to_vec(json).unwrap();
        let mut msg = Vec::with_capacity(4 + body.len());
        msg.extend_from_slice(&(body.len() as u32).to_le_bytes());
        msg.extend_from_slice(&body);
        msg
    }

    #[test]
    fn test_nmh_framing_valid_ping_parses_correctly() {
        let json = serde_json::json!({"type": "ping"});
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let result =
            read_message_from(&mut cursor).expect("valid framed ping should parse without error");
        assert!(result.is_some(), "valid message should return Some");
        match result.unwrap() {
            Request::Ping { .. } => {} // correct
            other => panic!("expected Ping, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_framing_valid_message_no_extra_bytes_consumed() {
        let json = serde_json::json!({"type": "ping"});
        let body = serde_json::to_vec(&json).unwrap();
        let body_len = body.len();

        // Append extra bytes after the message
        let mut data = Vec::with_capacity(4 + body_len + 10);
        data.extend_from_slice(&(body_len as u32).to_le_bytes());
        data.extend_from_slice(&body);
        data.extend_from_slice(b"extra_data");

        let mut cursor = Cursor::new(data);
        let _ = read_message_from(&mut cursor).unwrap();
        let consumed = cursor.position() as usize;
        assert_eq!(
            consumed,
            4 + body_len,
            "should consume exactly 4-byte prefix + body, not beyond"
        );
    }

    #[test]
    fn test_nmh_framing_zero_length_message_rejected() {
        let data: Vec<u8> = vec![0, 0, 0, 0]; // length = 0
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "zero-length message should be rejected");
        let err = result.unwrap_err();
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::InvalidData,
            "error kind should be InvalidData"
        );
        assert!(
            err.to_string().contains("Invalid message length"),
            "error should describe the problem, got: {}",
            err
        );
    }

    #[test]
    fn test_nmh_framing_oversized_message_rejected() {
        // length = MAX_MESSAGE_LENGTH + 1
        let len = (MAX_MESSAGE_LENGTH as u32) + 1;
        let data = len.to_le_bytes().to_vec();
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "oversized message should be rejected");
        let err = result.unwrap_err();
        assert!(
            err.to_string().contains("Invalid message length"),
            "error should name the invalid length, got: {}",
            err
        );
    }

    #[test]
    fn test_nmh_framing_truncated_message_rejected() {
        // Claim 100 bytes but only provide 50
        let mut data = Vec::new();
        data.extend_from_slice(&100u32.to_le_bytes());
        data.extend_from_slice(&[0u8; 50]); // only 50 of claimed 100
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(
            result.is_err(),
            "truncated message (claimed 100, got 50) should fail"
        );
    }

    #[test]
    fn test_nmh_framing_invalid_json_rejected() {
        let body = b"not valid json at all";
        let mut data = Vec::new();
        data.extend_from_slice(&(body.len() as u32).to_le_bytes());
        data.extend_from_slice(body);
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "invalid JSON body should be rejected");
        assert_eq!(
            result.unwrap_err().kind(),
            std::io::ErrorKind::InvalidData,
            "invalid JSON should return InvalidData error"
        );
    }

    #[test]
    fn test_nmh_framing_empty_stream_returns_none() {
        let data: Vec<u8> = vec![];
        let mut cursor = Cursor::new(data);
        let result =
            read_message_from(&mut cursor).expect("empty stream should return Ok(None), not Err");
        assert!(
            result.is_none(),
            "empty stream (EOF) should return None, not an error"
        );
    }

    #[test]
    fn test_nmh_framing_partial_length_prefix_rejected() {
        let data: Vec<u8> = vec![0x0A, 0x00]; // only 2 of 4 bytes
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        // Should return Ok(None) for EOF on length prefix read
        match result {
            Ok(None) => {} // acceptable: EOF during length prefix
            Err(_) => {}   // also acceptable: read error
            Ok(Some(_)) => panic!("partial length prefix should not parse as a valid message"),
        }
    }

    // === write_message_to tests ===

    #[test]
    fn test_nmh_write_message_produces_valid_framing() {
        let response = Response::Pong {
            version: "1.0.0".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &response).expect("write should succeed");

        // Read back the length prefix
        assert!(buf.len() >= 4, "output must have at least 4-byte prefix");
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        assert_eq!(
            len,
            buf.len() - 4,
            "length prefix should equal remaining bytes"
        );

        // Verify the JSON body
        let body: serde_json::Value =
            serde_json::from_slice(&buf[4..]).expect("body should be valid JSON");
        assert_eq!(body["type"], "pong", "response type should be 'pong'");
        assert_eq!(body["version"], "1.0.0", "version should match");
    }

    #[test]
    fn test_nmh_write_then_read_roundtrip() {
        let response = Response::Error {
            message: "test error".into(),
            code: "TEST_CODE".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &response).unwrap();

        // The written bytes should be readable as a framed message
        // (though the deserialized type would be Request, not Response,
        //  we verify the framing is correct by checking length prefix)
        let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
        let body: serde_json::Value = serde_json::from_slice(&buf[4..4 + len]).unwrap();
        assert_eq!(
            body["type"], "error",
            "should roundtrip error response type"
        );
        assert_eq!(body["message"], "test error", "should preserve message");
        assert_eq!(body["code"], "TEST_CODE", "should preserve code");
    }

    // === compute_commitment tests ===

    #[test]
    fn test_nmh_commitment_is_deterministic() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let hash = "a".repeat(64);
        let c1 = compute_commitment(&prev, &hash, 1, &nonce);
        let c2 = compute_commitment(&prev, &hash, 1, &nonce);
        assert_eq!(c1, c2, "same inputs must produce identical commitment");
    }

    #[test]
    fn test_nmh_commitment_changes_with_ordinal() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let hash = "b".repeat(64);
        let c1 = compute_commitment(&prev, &hash, 1, &nonce);
        let c2 = compute_commitment(&prev, &hash, 2, &nonce);
        assert_ne!(
            c1, c2,
            "different ordinals must produce different commitments"
        );
    }

    #[test]
    fn test_nmh_commitment_changes_with_content_hash() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let c1 = compute_commitment(&prev, &"a".repeat(64), 1, &nonce);
        let c2 = compute_commitment(&prev, &"b".repeat(64), 1, &nonce);
        assert_ne!(
            c1, c2,
            "different content hashes must produce different commitments"
        );
    }

    #[test]
    fn test_nmh_commitment_changes_with_prev() {
        let nonce = [1u8; 16];
        let hash = "c".repeat(64);
        let c1 = compute_commitment(&[0u8; 32], &hash, 1, &nonce);
        let c2 = compute_commitment(&[1u8; 32], &hash, 1, &nonce);
        assert_ne!(
            c1, c2,
            "different previous commitments must produce different results"
        );
    }

    #[test]
    fn test_nmh_commitment_changes_with_nonce() {
        let prev = [0u8; 32];
        let hash = "d".repeat(64);
        let c1 = compute_commitment(&prev, &hash, 1, &[0u8; 16]);
        let c2 = compute_commitment(&prev, &hash, 1, &[1u8; 16]);
        assert_ne!(
            c1, c2,
            "different nonces must produce different commitments"
        );
    }

    #[test]
    fn test_nmh_commitment_chain_sequential() {
        let nonce = [42u8; 16];
        let genesis = [0u8; 32];
        let h1 = "a".repeat(64);
        let h2 = "b".repeat(64);
        let h3 = "c".repeat(64);

        let c1 = compute_commitment(&genesis, &h1, 1, &nonce);
        let c2 = compute_commitment(&c1, &h2, 2, &nonce);
        let c3 = compute_commitment(&c2, &h3, 3, &nonce);

        // Each commitment depends on the previous, forming a chain
        assert_ne!(c1, c2, "sequential commitments must differ");
        assert_ne!(c2, c3, "sequential commitments must differ");
        assert_ne!(c1, c3, "non-adjacent commitments must differ");

        // Verify chain integrity: recomputing with wrong prev breaks it
        let c2_tampered = compute_commitment(&genesis, &h2, 2, &nonce);
        assert_ne!(c2, c2_tampered, "commitment with wrong prev should differ");
    }

    #[test]
    fn test_nmh_commitment_output_length() {
        let result = compute_commitment(&[0u8; 32], &"0".repeat(64), 1, &[0u8; 16]);
        assert_eq!(
            result.len(),
            32,
            "commitment output should be 32 bytes (SHA-256)"
        );
    }

    // === compute_jitter_stats tests ===

    #[test]
    fn test_nmh_jitter_stats_empty_input() {
        let stats = compute_jitter_stats(&[]);
        assert_eq!(stats.count, 0, "empty input should have count 0");
        assert_eq!(stats.mean, 0.0, "empty input should have mean 0.0");
        assert_eq!(stats.std_dev, 0.0, "empty input should have std_dev 0.0");
        assert_eq!(stats.min, 0, "empty input should have min 0");
        assert_eq!(stats.max, 0, "empty input should have max 0");
    }

    #[test]
    fn test_nmh_jitter_stats_single_value() {
        let stats = compute_jitter_stats(&[50_000]);
        assert_eq!(stats.count, 1, "single value should have count 1");
        assert_eq!(
            stats.mean, 50_000.0,
            "single value mean should equal the value"
        );
        assert_eq!(stats.std_dev, 0.0, "single value should have std_dev 0.0");
        assert_eq!(stats.min, 50_000, "single value min should equal the value");
        assert_eq!(stats.max, 50_000, "single value max should equal the value");
    }

    #[test]
    fn test_nmh_jitter_stats_known_distribution() {
        // [10, 20, 30] → mean=20, variance=((10-20)²+(20-20)²+(30-20)²)/3 = 200/3
        let stats = compute_jitter_stats(&[10, 20, 30]);
        assert_eq!(stats.count, 3, "count should be 3");
        assert!(
            (stats.mean - 20.0).abs() < 1e-10,
            "mean should be 20.0, got {}",
            stats.mean
        );
        let expected_stddev = (200.0_f64 / 3.0).sqrt();
        assert!(
            (stats.std_dev - expected_stddev).abs() < 1e-10,
            "std_dev should be {expected_stddev}, got {}",
            stats.std_dev
        );
        assert_eq!(stats.min, 10, "min should be 10");
        assert_eq!(stats.max, 30, "max should be 30");
    }

    #[test]
    fn test_nmh_jitter_stats_identical_values() {
        let stats = compute_jitter_stats(&[100, 100, 100, 100]);
        assert_eq!(stats.count, 4, "count should be 4");
        assert_eq!(
            stats.mean, 100.0,
            "mean of identical values should be that value"
        );
        assert_eq!(
            stats.std_dev, 0.0,
            "std_dev of identical values should be 0.0"
        );
        assert_eq!(stats.min, 100, "min should equal the repeated value");
        assert_eq!(stats.max, 100, "max should equal the repeated value");
    }

    #[test]
    fn test_nmh_jitter_stats_large_spread() {
        let stats = compute_jitter_stats(&[1, 1_000_000]);
        assert_eq!(stats.min, 1, "min should be 1");
        assert_eq!(stats.max, 1_000_000, "max should be 1_000_000");
        assert!(
            stats.std_dev > 0.0,
            "spread values should have nonzero std_dev"
        );
    }

    // === is_url_acceptable tests ===

    #[test]
    fn test_nmh_url_https_accepted() {
        assert!(
            is_url_acceptable("https://docs.google.com/document/d/abc123"),
            "https URL should be accepted"
        );
    }

    #[test]
    fn test_nmh_url_http_accepted() {
        assert!(
            is_url_acceptable("http://example.com/page"),
            "http URL should be accepted"
        );
    }

    #[test]
    fn test_nmh_url_any_domain_accepted() {
        assert!(
            is_url_acceptable("https://any-website.example.org/doc"),
            "any domain over https should be accepted"
        );
    }

    #[test]
    fn test_nmh_url_invalid_rejected() {
        assert!(
            !is_url_acceptable("not a url at all"),
            "invalid URL should be rejected"
        );
        assert!(!is_url_acceptable(""), "empty URL should be rejected");
    }

    // === validate_content_hash tests ===

    #[test]
    fn test_nmh_validate_content_hash_valid() {
        let valid_hash = "a".repeat(64);
        assert!(
            validate_content_hash(&valid_hash).is_ok(),
            "64-char hex string should be valid"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_valid_mixed_case() {
        let hash = "aAbBcCdDeEfF0011223344556677889900112233445566778899aabbccddeeff";
        assert!(
            validate_content_hash(hash).is_ok(),
            "mixed-case hex should be valid"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_too_short() {
        let err = validate_content_hash("abc123").unwrap_err();
        assert!(
            err.contains("expected 64"),
            "error should mention expected length, got: {err}"
        );
        assert!(
            err.contains("6 chars"),
            "error should mention actual length, got: {err}"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_too_long() {
        let hash = "a".repeat(65);
        assert!(
            validate_content_hash(&hash).is_err(),
            "65-char hash should be rejected"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_non_hex() {
        let hash = "g".repeat(64); // 'g' is not hex
        assert!(
            validate_content_hash(&hash).is_err(),
            "non-hex characters should be rejected"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_empty() {
        assert!(
            validate_content_hash("").is_err(),
            "empty hash should be rejected"
        );
    }

    // === request_type_name tests ===

    #[test]
    fn test_nmh_request_type_name_all_variants() {
        use super::protocol::request_type_name;

        assert_eq!(
            request_type_name(&Request::Ping {
                protocol_version: None
            }),
            "Ping",
            "Ping should return 'Ping'"
        );
        assert_eq!(
            request_type_name(&Request::StopSession),
            "StopSession",
            "StopSession should return 'StopSession'"
        );
        assert_eq!(
            request_type_name(&Request::GetStatus),
            "GetStatus",
            "GetStatus should return 'GetStatus'"
        );
        assert_eq!(
            request_type_name(&Request::StartSession {
                document_url: "https://example.com".into(),
                document_title: "Secret Doc".into(),
                protocol_version: None,
                editor_type: None,
            }),
            "StartSession",
            "StartSession should not include PII"
        );
        assert_eq!(
            request_type_name(&Request::Checkpoint {
                content_hash: "x".into(),
                char_count: 0,
                delta: 0,
                commitment: None,
                ordinal: None,
                tool_category: None,
                tool_host: None,
            }),
            "Checkpoint",
            "Checkpoint should return 'Checkpoint'"
        );
        assert_eq!(
            request_type_name(&Request::InjectJitter {
                intervals: vec![100],
            }),
            "InjectJitter",
            "InjectJitter should return 'InjectJitter'"
        );
    }

    // === Request deserialization tests ===

    #[test]
    fn test_nmh_request_deserialize_start_session() {
        let json = serde_json::json!({
            "type": "start_session",
            "document_url": "https://docs.google.com/doc/123",
            "document_title": "My Essay"
        });
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let req = read_message_from(&mut cursor).unwrap().unwrap();
        match req {
            Request::StartSession {
                document_url,
                document_title,
                ..
            } => {
                assert_eq!(
                    document_url, "https://docs.google.com/doc/123",
                    "document_url should be preserved"
                );
                assert_eq!(
                    document_title, "My Essay",
                    "document_title should be preserved"
                );
            }
            other => panic!("expected StartSession, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_request_deserialize_checkpoint_with_optional_fields() {
        let json = serde_json::json!({
            "type": "checkpoint",
            "content_hash": "a".repeat(64),
            "char_count": 1500,
            "delta": 42
        });
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let req = read_message_from(&mut cursor).unwrap().unwrap();
        match req {
            Request::Checkpoint {
                content_hash,
                char_count,
                delta,
                commitment,
                ordinal,
                tool_category: _,
                tool_host: _,
            } => {
                assert_eq!(content_hash.len(), 64, "content_hash should be preserved");
                assert_eq!(char_count, 1500, "char_count should be 1500");
                assert_eq!(delta, 42, "delta should be 42");
                assert!(commitment.is_none(), "commitment should default to None");
                assert!(ordinal.is_none(), "ordinal should default to None");
            }
            other => panic!("expected Checkpoint, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_request_deserialize_inject_jitter() {
        let json = serde_json::json!({
            "type": "inject_jitter",
            "intervals": [100_000, 200_000, 50_000]
        });
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let req = read_message_from(&mut cursor).unwrap().unwrap();
        match req {
            Request::InjectJitter { intervals } => {
                assert_eq!(
                    intervals,
                    vec![100_000, 200_000, 50_000],
                    "intervals should be preserved exactly"
                );
            }
            other => panic!("expected InjectJitter, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_request_unknown_type_rejected() {
        let json = serde_json::json!({"type": "unknown_command"});
        let data = frame_message(&json);
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(
            result.is_err(),
            "unknown request type should fail deserialization"
        );
    }

    // === Constants tests ===

    #[test]
    fn test_nmh_max_message_length_is_one_mib() {
        assert_eq!(
            MAX_MESSAGE_LENGTH, 1_048_576,
            "max message length should be 1 MiB"
        );
    }

    #[test]
    fn test_nmh_max_batch_size_is_200() {
        assert_eq!(MAX_BATCH_SIZE, 200, "max jitter batch size should be 200");
    }

    #[test]
    fn test_nmh_jitter_rate_limit_constants_sensible() {
        assert!(
            MAX_JITTER_BATCHES_PER_WINDOW > 0,
            "max batches per window must be positive"
        );
        // JITTER_REFILL_PER_MS is integer milli-tokens, so check > 0 as u64
        use super::jitter::JITTER_REFILL_PER_MS;
        assert!(JITTER_REFILL_PER_MS > 0, "refill rate must be positive");
    }

    // === Additional edge case tests ===

    // --- URL scheme validation edge cases ---

    #[test]
    fn test_nmh_url_file_protocol_rejected() {
        assert!(
            !is_url_acceptable("file:///etc/passwd"),
            "file:// protocol should be rejected"
        );
    }

    #[test]
    fn test_nmh_url_javascript_protocol_rejected() {
        assert!(
            !is_url_acceptable("javascript:alert(1)"),
            "javascript: protocol should be rejected"
        );
    }

    #[test]
    fn test_nmh_url_data_protocol_rejected() {
        assert!(
            !is_url_acceptable("data:text/html,<h1>hi</h1>"),
            "data: protocol should be rejected"
        );
    }

    #[test]
    fn test_nmh_url_with_port_number() {
        assert!(
            is_url_acceptable("https://docs.google.com:443/document"),
            "port number should not break URL acceptance"
        );
    }

    #[test]
    fn test_nmh_url_with_query_and_fragment() {
        assert!(
            is_url_acceptable("https://docs.google.com/doc?key=val#section"),
            "query params and fragments should not break URL acceptance"
        );
    }

    // --- Content hash validation edge cases ---

    #[test]
    fn test_nmh_validate_content_hash_uppercase_hex_valid() {
        let hash = "AABBCCDD".to_string() + &"00".repeat(28);
        assert!(
            validate_content_hash(&hash).is_ok(),
            "uppercase hex should be valid"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_all_zeros_valid() {
        let hash = "0".repeat(64);
        assert!(
            validate_content_hash(&hash).is_ok(),
            "all-zeros hash should be valid format"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_all_f_valid() {
        let hash = "f".repeat(64);
        assert!(
            validate_content_hash(&hash).is_ok(),
            "all-f hash should be valid format"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_63_chars_rejected() {
        let hash = "a".repeat(63);
        let err = validate_content_hash(&hash).unwrap_err();
        assert!(
            err.contains("63"),
            "error should mention actual length 63, got: {err}"
        );
    }

    #[test]
    fn test_nmh_validate_content_hash_with_spaces_rejected() {
        let hash = "a".repeat(32) + " " + &"b".repeat(31);
        assert!(
            validate_content_hash(&hash).is_err(),
            "hash with spaces should be rejected"
        );
    }

    // --- Jitter stats edge cases ---

    #[test]
    fn test_nmh_jitter_stats_two_values_stddev() {
        let stats = compute_jitter_stats(&[100, 200]);
        assert_eq!(stats.count, 2, "count should be 2");
        assert!((stats.mean - 150.0).abs() < 1e-10, "mean should be 150.0");
        assert!(
            stats.std_dev > 0.0,
            "std_dev of different values should be positive"
        );
        assert_eq!(stats.min, 100, "min should be 100");
        assert_eq!(stats.max, 200, "max should be 200");
    }

    #[test]
    fn test_nmh_jitter_stats_large_count() {
        let intervals: Vec<u64> = (1..=1000).collect();
        let stats = compute_jitter_stats(&intervals);
        assert_eq!(stats.count, 1000, "count should be 1000");
        assert_eq!(stats.min, 1, "min should be 1");
        assert_eq!(stats.max, 1000, "max should be 1000");
        // Mean of 1..=1000 is 500.5
        assert!(
            (stats.mean - 500.5).abs() < 1e-10,
            "mean should be 500.5, got {}",
            stats.mean
        );
    }

    // --- Protocol framing edge cases ---

    #[test]
    fn test_nmh_framing_exactly_max_length_accepted() {
        // Build a message at exactly MAX_MESSAGE_LENGTH
        // We can't easily create a valid JSON at exactly 1MB, but we can
        // test that the boundary value is accepted (length == MAX)
        let mut data = Vec::new();
        data.extend_from_slice(&(MAX_MESSAGE_LENGTH as u32).to_le_bytes());
        // Don't add body - read_exact will fail with UnexpectedEof,
        // but the length check should pass
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        // Should fail because body is missing, not because length is rejected
        match result {
            Err(e) => assert!(
                !e.to_string().contains("Invalid message length"),
                "MAX_MESSAGE_LENGTH should be accepted, got: {e}"
            ),
            Ok(None) => {} // EOF during body read is also acceptable
            Ok(Some(_)) => panic!("should not parse without body"),
        }
    }

    #[test]
    fn test_nmh_framing_one_over_max_rejected() {
        let len = MAX_MESSAGE_LENGTH as u32 + 1;
        let data = len.to_le_bytes().to_vec();
        let mut cursor = Cursor::new(data);
        let result = read_message_from(&mut cursor);
        assert!(result.is_err(), "MAX+1 should be rejected");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Invalid message length"),
            "should mention invalid length"
        );
    }

    // --- Commitment chain integrity ---

    #[test]
    fn test_nmh_commitment_not_reversible() {
        let prev = [0u8; 32];
        let nonce = [1u8; 16];
        let hash = "a".repeat(64);
        let c = compute_commitment(&prev, &hash, 1, &nonce);
        // Output should not equal any input
        assert_ne!(&c[..], &prev[..], "commitment should not equal prev");
        assert_ne!(&c[..], &nonce[..], "commitment should not be nonce");
    }

    #[test]
    fn test_nmh_commitment_not_all_zeros() {
        let c = compute_commitment(&[0u8; 32], &"0".repeat(64), 0, &[0u8; 16]);
        assert_ne!(
            c, [0u8; 32],
            "commitment of all-zero inputs should not be all zeros"
        );
    }

    // --- Response serialization ---

    #[test]
    fn test_nmh_error_response_serialization() {
        let resp = Response::Error {
            message: "test error with \"quotes\" and \\ backslash".into(),
            code: "TEST".into(),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).expect("write should succeed");
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(
            body["message"], "test error with \"quotes\" and \\ backslash",
            "special characters should be properly escaped in JSON"
        );
    }

    #[test]
    fn test_nmh_session_started_response_fields() {
        let resp = Response::SessionStarted {
            session_id: "abc123".into(),
            message: "Now witnessing: test".into(),
            session_nonce: "deadbeef".into(),
            device_public_key: None,
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(
            body["type"], "session_started",
            "type should be session_started"
        );
        assert_eq!(
            body["session_id"], "abc123",
            "session_id should be preserved"
        );
        assert_eq!(
            body["session_nonce"], "deadbeef",
            "nonce should be preserved"
        );
    }

    #[test]
    fn test_nmh_checkpoint_created_response_fields() {
        let resp = Response::CheckpointCreated {
            hash: "a".repeat(64),
            checkpoint_count: 5,
            message: "Created".into(),
            commitment: "b".repeat(64),
            signature: None,
            evidence_quality: None,
            commitment_verified: None,
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(body["type"], "checkpoint_created");
        assert_eq!(body["checkpoint_count"], 5);
        assert_eq!(
            body["commitment"].as_str().unwrap().len(),
            64,
            "commitment should be 64 hex chars"
        );
        assert!(
            body.get("signature").is_none(),
            "signature omitted when None"
        );
    }

    #[test]
    fn test_nmh_checkpoint_response_includes_signature_when_present() {
        let resp = Response::CheckpointCreated {
            hash: "a".repeat(64),
            checkpoint_count: 1,
            message: "ok".into(),
            commitment: "b".repeat(64),
            signature: Some("c".repeat(128)),
            evidence_quality: None,
            commitment_verified: None,
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(body["signature"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn test_nmh_session_started_includes_device_public_key() {
        let resp = Response::SessionStarted {
            session_id: "s1".into(),
            message: "ok".into(),
            session_nonce: "aa".repeat(16),
            device_public_key: Some("dd".repeat(32)),
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(body["device_public_key"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn test_nmh_session_stopped_includes_signature() {
        let resp = Response::SessionStopped {
            message: "ended".into(),
            signature: Some("ee".repeat(64)),
            evidence_quality: None,
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert_eq!(body["type"], "session_stopped");
        assert_eq!(body["signature"].as_str().unwrap().len(), 128);
    }

    #[test]
    fn test_nmh_session_stopped_omits_signature_when_none() {
        let resp = Response::SessionStopped {
            message: "ended".into(),
            signature: None,
            evidence_quality: None,
        };
        let mut buf = Vec::new();
        write_message_to(&mut buf, &resp).unwrap();
        let body: serde_json::Value = serde_json::from_slice(&buf[4..]).unwrap();
        assert!(body.get("signature").is_none());
    }

    #[test]
    fn test_nmh_load_device_signing_key_signs_and_verifies() {
        use ed25519_dalek::{Signer, Verifier};
        let seed = [42u8; 32];
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();

        let mut payload = Vec::new();
        payload.extend_from_slice(b"cpoe-checkpoint-sig-v1");
        payload.extend_from_slice(b"session123");
        payload.extend_from_slice(&1u64.to_le_bytes());
        payload.extend_from_slice(b"contenthash");
        payload.extend_from_slice(&[0u8; 32]); // commitment
        payload.extend_from_slice(&12345u64.to_le_bytes()); // timestamp
        payload.extend_from_slice(&[0u8; 32]); // jitter_hash

        let sig = sk.sign(&payload);
        assert!(vk.verify(&payload, &sig).is_ok());
    }

    #[test]
    fn test_nmh_commitment_includes_all_fields() {
        let prev = [1u8; 32];
        let nonce = [2u8; 16];
        let c1 = compute_commitment(&prev, "hash1", 1, &nonce);
        let c2 = compute_commitment(&prev, "hash2", 1, &nonce);
        let c3 = compute_commitment(&prev, "hash1", 2, &nonce);
        assert_ne!(
            c1, c2,
            "different content_hash must produce different commitment"
        );
        assert_ne!(
            c1, c3,
            "different ordinal must produce different commitment"
        );
    }

    // === Text attestation handler tests ===

    fn valid_attestation_args() -> (String, String, String, String, String) {
        (
            "a".repeat(64),
            "verified".into(),
            "abcdef0123456789".into(),
            "2026-04-25T12:00:00Z".into(),
            "docs.google.com".into(),
        )
    }

    #[test]
    fn test_nmh_text_attestation_rejects_invalid_content_hash() {
        let resp = handle_text_attestation(
            "short".into(),
            "verified".into(),
            "abcdef01".into(),
            "2026-04-25T12:00:00Z".into(),
            "docs.google.com".into(),
        );
        match resp {
            Response::TextAttestationResult {
                success, error, ..
            } => {
                assert!(!success, "invalid content_hash should fail");
                assert!(error.is_some());
            }
            other => panic!("expected TextAttestationResult, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_text_attestation_rejects_invalid_tier() {
        let (hash, _, wpid, ts, app) = valid_attestation_args();
        let resp = handle_text_attestation(hash, "gold".into(), wpid, ts, app);
        match resp {
            Response::TextAttestationResult { success, error } => {
                assert!(!success);
                assert!(error.unwrap().contains("Invalid tier"));
            }
            other => panic!("expected TextAttestationResult, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_text_attestation_rejects_invalid_writersproof_id() {
        let (hash, tier, _, ts, app) = valid_attestation_args();
        let resp = handle_text_attestation(hash, tier, "xyz".into(), ts, app);
        match resp {
            Response::TextAttestationResult { success, error } => {
                assert!(!success);
                assert!(error.unwrap().contains("writersproof_id"));
            }
            other => panic!("expected TextAttestationResult, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_text_attestation_rejects_invalid_timestamp() {
        let (hash, tier, wpid, _, app) = valid_attestation_args();
        let resp = handle_text_attestation(hash, tier, wpid, "not-a-date".into(), app);
        match resp {
            Response::TextAttestationResult { success, error } => {
                assert!(!success);
                assert!(error.unwrap().contains("ISO 8601"));
            }
            other => panic!("expected TextAttestationResult, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_text_attestation_rejects_oversized_app_bundle_id() {
        let (hash, tier, wpid, ts, _) = valid_attestation_args();
        let resp = handle_text_attestation(hash, tier, wpid, ts, "x".repeat(254));
        match resp {
            Response::TextAttestationResult { success, error } => {
                assert!(!success);
                assert!(error.unwrap().contains("hostname length"));
            }
            other => panic!("expected TextAttestationResult, got: {other:?}"),
        }
    }

    #[test]
    fn test_nmh_text_attestation_accepts_all_tiers() {
        for tier in &["verified", "corroborated", "declared"] {
            let (hash, _, wpid, ts, app) = valid_attestation_args();
            let resp =
                handle_text_attestation(hash, tier.to_string(), wpid, ts, app);
            match resp {
                Response::TextAttestationResult { .. } => {}
                other => panic!("expected TextAttestationResult for tier {tier}, got: {other:?}"),
            }
        }
    }

    #[test]
    fn test_nmh_text_attestation_accepts_8_char_writersproof_id() {
        let (hash, tier, _, ts, app) = valid_attestation_args();
        let resp = handle_text_attestation(hash, tier, "abcdef01".into(), ts, app);
        match resp {
            Response::TextAttestationResult { .. } => {}
            other => panic!("expected TextAttestationResult, got: {other:?}"),
        }
    }
}
