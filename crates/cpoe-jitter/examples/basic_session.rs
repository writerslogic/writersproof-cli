// SPDX-License-Identifier: Apache-2.0
//! Basic session usage example.
//!
//! Run with: `cargo run --example basic_session`

use cpoe_jitter::Session;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // In production, derive this from a secure source!
    let secret = [42u8; 32];
    let mut session = Session::new(&secret);

    let keystrokes = ["H", "e", "l", "l", "o", " ", "W", "o", "r", "l", "d", "!"];

    println!("Simulating {} keystrokes...", keystrokes.len());

    for keystroke in keystrokes {
        let jitter_us = session.sample(keystroke.as_bytes())?;
        println!("  '{}' -> {}μs jitter", keystroke, jitter_us);

        // In a real application, you would apply this delay
        // std::thread::sleep(std::time::Duration::from_micros(jitter_us as u64));
    }

    for i in 0..20 {
        session.sample(format!("extra{}", i).as_bytes())?;
    }

    let result = session.validate();
    println!("\nValidation Results:");
    println!("  Is human: {}", result.is_human);
    println!("  Confidence: {:.2}", result.confidence);
    println!("  Anomalies: {}", result.anomalies.len());

    let _json = session.export_json()?;
    println!("\nEvidence chain has {} records", session.evidence().len());
    println!("Physics ratio: {:.1}%", session.phys_ratio() * 100.0);

    Ok(())
}
