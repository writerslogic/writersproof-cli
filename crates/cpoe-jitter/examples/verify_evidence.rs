// SPDX-License-Identifier: Apache-2.0
//! Evidence chain verification example.
//!
//! Run with: `cargo run --example verify_evidence`

use cpoe_jitter::{Evidence, EvidenceChain, JitterEngine, PureJitter};

fn main() {
    let secret = [42u8; 32];
    let engine = PureJitter::default();

    let inputs: Vec<&[u8]> = vec![b"key1", b"key2", b"key3", b"key4", b"key5"];
    let mut chain = EvidenceChain::with_secret(&secret);

    println!("Building evidence chain...");
    for input in &inputs {
        let jitter = engine.compute_jitter(&secret, input, [0u8; 32].into());
        chain.append(Evidence::pure(jitter)).unwrap();
        println!(
            "  Added evidence for {:?} -> {}μs",
            String::from_utf8_lossy(input),
            jitter
        );
    }

    println!("\nVerifying chain integrity...");
    let integrity_ok = chain.verify_integrity(&secret);
    println!(
        "  Integrity check: {}",
        if integrity_ok { "PASSED" } else { "FAILED" }
    );

    let chain_ok = chain.verify_chain(&secret, &inputs, &engine);
    println!(
        "  Chain verification: {}",
        if chain_ok { "PASSED" } else { "FAILED" }
    );

    let wrong_inputs: Vec<&[u8]> = vec![b"wrong1", b"wrong2", b"wrong3", b"wrong4", b"wrong5"];
    let wrong_ok = chain.verify_chain(&secret, &wrong_inputs, &engine);
    println!(
        "  Wrong inputs check: {}",
        if !wrong_ok {
            "CORRECTLY REJECTED"
        } else {
            "ERROR"
        }
    );

    println!("\nTamper detection demo...");
    // Simulate tampering via serialization round-trip with a modified jitter value.
    let json = serde_json::to_string(&chain).unwrap();
    let tampered_json = json.replacen("\"jitter\":1", "\"jitter\":9999", 1);
    if let Ok(tampered_chain) = serde_json::from_str::<EvidenceChain>(&tampered_json) {
        let tamper_detected = !tampered_chain.verify_integrity(&secret);
        println!(
            "  Tamper detected: {}",
            if tamper_detected { "YES" } else { "NO" }
        );
    } else {
        println!("  Tampered JSON failed to parse (also a detection signal)");
    }
}
