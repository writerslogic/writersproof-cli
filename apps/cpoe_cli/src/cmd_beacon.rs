// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Commercial

use anyhow::Result;
use std::path::PathBuf;

use crate::cli::BeaconAction;
use crate::output::OutputMode;
use crate::util::{check_ffi_result, path_str};

pub(crate) fn cmd_beacon(action: BeaconAction, out: &OutputMode) -> Result<()> {
    match action {
        BeaconAction::Submit { path, timeout } => cmd_beacon_submit(&path, timeout, out),
        BeaconAction::Status { path } => cmd_beacon_status(&path, out),
        BeaconAction::List { path } => cmd_beacon_list(&path, out),
    }
}

fn beacon_to_json(b: &cpoe::ffi::beacon::FfiBeaconResult) -> serde_json::Value {
    serde_json::json!({
        "anchor_id": b.anchor_id,
        "timestamp_epoch_ms": b.timestamp_epoch_ms,
        "drand_round": b.drand_round,
        "nist_pulse": b.nist_pulse,
        "wp_signature_hex": b.wp_signature_hex,
        "verification_url": b.verification_url,
    })
}

fn print_beacon(b: &cpoe::ffi::beacon::FfiBeaconResult) {
    if let Some(id) = &b.anchor_id {
        println!("  Anchor ID:    {}", id);
    }
    if let Some(ts) = b.timestamp_epoch_ms {
        println!("  Timestamp:    {} ms", ts);
    }
    if let Some(round) = b.drand_round {
        println!("  drand Round:  {}", round);
    }
    if let Some(pulse) = b.nist_pulse {
        println!("  NIST Pulse:   {}", pulse);
    }
    if let Some(url) = &b.verification_url {
        println!("  Verify URL:   {}", url);
    }
}

fn cmd_beacon_submit(path: &PathBuf, timeout: u64, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let result = cpoe::ffi::beacon::ffi_submit_beacon(path_str, timeout);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        println!("{}", beacon_to_json(&result));
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("Beacon submitted successfully.");
    print_beacon(&result);

    Ok(())
}

fn cmd_beacon_status(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let result = cpoe::ffi::beacon::ffi_check_beacon_status(path_str);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        println!("{}", beacon_to_json(&result));
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Beacon Status ===");
    println!();
    print_beacon(&result);

    Ok(())
}

fn cmd_beacon_list(path: &PathBuf, out: &OutputMode) -> Result<()> {
    let path_str = path_str(path);
    let result = cpoe::ffi::beacon::ffi_list_beacons(path_str);

    check_ffi_result(result.success, &result.error_message)?;

    if out.json {
        let items: Vec<serde_json::Value> =
            result.beacons.iter().map(beacon_to_json).collect();
        println!("{}", serde_json::Value::Array(items));
        return Ok(());
    }

    if result.beacons.is_empty() {
        if !out.quiet {
            println!("No beacons found for this document.");
        }
        return Ok(());
    }

    if out.quiet {
        return Ok(());
    }

    println!("=== Beacons ({}) ===", result.beacons.len());
    for (i, beacon) in result.beacons.iter().enumerate() {
        println!();
        println!("Beacon #{}:", i + 1);
        print_beacon(beacon);
    }

    Ok(())
}
