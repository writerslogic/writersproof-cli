// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use anyhow::{anyhow, Result};
use base64::engine::general_purpose;
use base64::Engine as _;
use std::net::UdpSocket;
use std::time::Duration;

/// Roughtime server descriptor with address and Ed25519 public key.
#[derive(Debug)]
pub struct RoughtimeServer {
    pub name: &'static str,
    pub address: &'static str,
    pub public_key_base64: &'static str,
}

/// Owned variant of [`RoughtimeServer`] for config-driven server lists.
#[derive(Debug, Clone)]
pub struct RoughtimeServerOwned {
    pub name: String,
    pub address: String,
    pub public_key_base64: String,
}

impl RoughtimeServerOwned {
    /// Parse a `"name|address|base64_pubkey"` config string.
    pub fn from_config_str(s: &str) -> Result<Self> {
        let parts: Vec<&str> = s.splitn(3, '|').collect();
        if parts.len() != 3 {
            return Err(anyhow!(
                "roughtime server config must be 'name|address|base64_pubkey', got: {s}"
            ));
        }
        Ok(Self {
            name: parts[0].to_string(),
            address: parts[1].to_string(),
            public_key_base64: parts[2].to_string(),
        })
    }
}

// Source: https://github.com/cloudflare/roughtime/blob/master/ecosystem.json
const SERVERS: &[RoughtimeServer] = &[
    RoughtimeServer {
        name: "Cloudflare-Roughtime-2",
        address: "roughtime.cloudflare.com:2003",
        public_key_base64: "0GD7c3yP8xEc4Zl2zeuN2SlLvDVVocjsPSL8/Rl/7zg=",
    },
    RoughtimeServer {
        name: "int08h-Roughtime",
        address: "roughtime.int08h.com:2002",
        public_key_base64: "AW5uAoTSTDfG5NfY1bTh08GUnOqlRb+HVhbJ3ODJvsE=",
    },
    RoughtimeServer {
        name: "roughtime.se",
        address: "roughtime.se:2002",
        public_key_base64: "S3AzfZJ5CjSdkJ21ZJGbxqdYP/SoE8fXKY0+aicsehI=",
    },
    RoughtimeServer {
        name: "time.txryan.com",
        address: "time.txryan.com:2002",
        public_key_base64: "iBVjxg/1j7y1+kQUTBYdTabxCppesU/07D4PMDJk2WA=",
    },
];

/// Timeout for Roughtime UDP requests.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);

/// Minimum number of servers that must agree for quorum.
const QUORUM_MIN: usize = 2;

/// Maximum allowed disagreement between servers (10 seconds in microseconds).
const QUORUM_TOLERANCE_US: u64 = 10_000_000;

/// Client for querying Roughtime servers with quorum-based verification.
#[derive(Debug)]
pub struct RoughtimeClient;

impl RoughtimeClient {
    /// Core implementation: fetch verified time from server identified by borrowed strings.
    fn fetch_time_inner(name: &str, address: &str, public_key_base64: &str) -> Result<u64> {
        use roughenough_protocol::cursor::ParseCursor;
        use roughenough_protocol::request::Request;
        use roughenough_protocol::response::Response;
        use roughenough_protocol::tags::Nonce;
        use roughenough_protocol::wire::{FromFrame, ToFrame};

        let public_key_bytes = general_purpose::STANDARD
            .decode(public_key_base64)
            .map_err(|e| anyhow!("Invalid server public key: {e}"))?;
        if public_key_bytes.len() != 32 {
            return Err(anyhow!("Invalid server public key length"));
        }
        let server_long_term_key = {
            use ed25519_dalek::VerifyingKey;
            let bytes: [u8; 32] = public_key_bytes
                .as_slice()
                .try_into()
                .map_err(|_| anyhow!("Failed to convert public key bytes"))?;
            VerifyingKey::from_bytes(&bytes)
                .map_err(|e| anyhow!("Invalid Ed25519 public key for {name}: {e}"))?
        };

        let mut nonce_bytes = [0u8; 32];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow!("Failed to generate nonce: {e}"))?;
        let nonce = Nonce::from(nonce_bytes);

        let request = Request::new(&nonce);
        let request_bytes = request
            .as_frame_bytes()
            .map_err(|e| anyhow!("Failed to serialize request: {e}"))?;

        let socket =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| anyhow!("Failed to bind UDP socket: {e}"))?;
        socket
            .set_read_timeout(Some(REQUEST_TIMEOUT))
            .map_err(|e| anyhow!("Failed to set socket timeout: {e}"))?;
        socket
            .send_to(&request_bytes, address)
            .map_err(|e| anyhow!("Failed to send request to {name}: {e}"))?;

        let mut recv_buf = vec![0u8; 4096];
        let (size, _) = socket
            .recv_from(&mut recv_buf)
            .map_err(|e| anyhow!("Failed to receive response from {name}: {e}"))?;
        recv_buf.truncate(size);

        let mut cursor = ParseCursor::new(&mut recv_buf);
        let response = Response::from_frame(&mut cursor)
            .map_err(|e| anyhow!("Failed to parse response from {name}: {e}"))?;

        if response.nonc() != &nonce {
            return Err(anyhow!("Nonce mismatch in response from {name}"));
        }

        // Verify the certificate: server long-term key signs the DELE (delegation) bytes.
        // Then verify the response SIG: the delegate key signs the SREP bytes.
        {
            use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
            use roughenough_protocol::wire::ToWire;

            let cert = response.cert();
            let dele = cert.dele();
            let version = response.srep().ver();

            // Step 1: verify CERT.SIG = sign(server_long_term_key, dele_prefix || DELE bytes)
            let dele_bytes = dele
                .as_bytes()
                .map_err(|e| anyhow!("Failed to serialize DELE for {name}: {e}"))?;
            let mut dele_msg = Vec::with_capacity(version.dele_prefix().len() + dele_bytes.len());
            dele_msg.extend_from_slice(version.dele_prefix());
            dele_msg.extend_from_slice(&dele_bytes);
            let cert_sig_bytes: [u8; 64] = cert
                .sig()
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("Invalid CERT.SIG length from {name}"))?;
            let cert_sig = Ed25519Sig::from_bytes(&cert_sig_bytes);
            server_long_term_key
                .verify(&dele_msg, &cert_sig)
                .map_err(|e| anyhow!("CERT signature verification failed for {name}: {e}"))?;

            // Step 2: extract delegate key from DELE, verify response SIG over SREP bytes.
            let dele_pubk_bytes: [u8; 32] = dele
                .pubk()
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("Invalid DELE.PUBK length from {name}"))?;
            let delegate_key = VerifyingKey::from_bytes(&dele_pubk_bytes)
                .map_err(|e| anyhow!("Invalid delegate key from {name}: {e}"))?;
            let srep_bytes = response
                .srep()
                .as_bytes()
                .map_err(|e| anyhow!("Failed to serialize SREP for {name}: {e}"))?;
            let mut srep_msg = Vec::with_capacity(version.srep_prefix().len() + srep_bytes.len());
            srep_msg.extend_from_slice(version.srep_prefix());
            srep_msg.extend_from_slice(&srep_bytes);
            let resp_sig_bytes: [u8; 64] = response
                .sig()
                .as_ref()
                .try_into()
                .map_err(|_| anyhow!("Invalid response SIG length from {name}"))?;
            let resp_sig = Ed25519Sig::from_bytes(&resp_sig_bytes);
            delegate_key
                .verify(&srep_msg, &resp_sig)
                .map_err(|e| anyhow!("Response signature verification failed for {name}: {e}"))?;
        }

        let midpoint = response.srep().midp();
        if midpoint == 0 {
            return Err(anyhow!("Zero midpoint in response from {name}"));
        }

        log::info!(
            "roughtime: received verified time from {} (midpoint: {}, radius: {})",
            name,
            midpoint,
            response.srep().radi()
        );

        Ok(midpoint)
    }

    /// Fetch verified time from a static Roughtime server descriptor.
    pub fn fetch_time(server: &RoughtimeServer) -> Result<u64> {
        Self::fetch_time_inner(server.name, server.address, server.public_key_base64)
    }

    /// Fetch verified time from an owned Roughtime server descriptor.
    pub fn fetch_time_owned(server: &RoughtimeServerOwned) -> Result<u64> {
        Self::fetch_time_inner(&server.name, &server.address, &server.public_key_base64)
    }

    /// Find the largest group of timestamps that agree within tolerance,
    /// returning the median if the group meets quorum.
    fn find_quorum(timestamps: &mut [(u64, &str)]) -> Result<u64> {
        timestamps.sort_by_key(|(t, _)| *t);

        let mut best_start = 0;
        let mut best_count = 0;

        for i in 0..timestamps.len() {
            let mut count = 1;
            for j in (i + 1)..timestamps.len() {
                if timestamps[j].0.saturating_sub(timestamps[i].0) <= QUORUM_TOLERANCE_US {
                    count += 1;
                } else {
                    break;
                }
            }
            if count > best_count {
                best_count = count;
                best_start = i;
            }
        }

        if best_count < QUORUM_MIN {
            let names: Vec<&str> = timestamps.iter().map(|(_, n)| *n).collect();
            return Err(anyhow!(
                "Roughtime quorum failed: only {} server(s) responded {:?}, need {}",
                timestamps.len(),
                names,
                QUORUM_MIN
            ));
        }

        let median_idx = best_start + best_count / 2;
        let chosen = timestamps[median_idx].0;
        log::info!(
            "roughtime: quorum reached with {}/{} servers (median from {})",
            best_count,
            timestamps.len(),
            timestamps[median_idx].1
        );
        Ok(chosen)
    }

    /// Query multiple Roughtime servers and return a quorum-verified time.
    ///
    /// At least 2 servers must agree within 10 seconds. Returns `Err` if
    /// quorum cannot be reached — the caller decides on fallback policy
    /// (e.g. local time, offline mode).
    pub fn get_verified_time() -> Result<u64> {
        let mut results: Vec<(u64, &str)> = Vec::new();

        for server in SERVERS {
            match Self::fetch_time(server) {
                Ok(time) => results.push((time, server.name)),
                Err(e) => log::warn!("roughtime: {} failed: {}", server.name, e),
            }
        }

        Self::find_quorum(&mut results)
    }

    /// Query a caller-supplied list of Roughtime servers and return quorum time.
    ///
    /// Falls back to the built-in server list when `servers` is empty.
    /// At least 2 servers in the list must agree within 10 seconds.
    pub fn get_verified_time_with_servers(servers: &[RoughtimeServerOwned]) -> Result<u64> {
        if servers.is_empty() {
            return Self::get_verified_time();
        }
        let mut results: Vec<(u64, String)> = Vec::new();
        for server in servers {
            match Self::fetch_time_owned(server) {
                Ok(time) => results.push((time, server.name.clone())),
                Err(e) => log::warn!("roughtime: {} failed: {}", server.name, e),
            }
        }
        // find_quorum requires &str names; build a parallel vec of tuples.
        let mut ref_results: Vec<(u64, &str)> =
            results.iter().map(|(t, n)| (*t, n.as_str())).collect();
        Self::find_quorum(&mut ref_results)
    }

    /// Query the default servers multiple times and return per-sample microsecond timestamps.
    ///
    /// Used by the calibration path to build a skew distribution.
    /// Each successful quorum result becomes one sample.
    pub fn collect_samples(count: usize, servers: &[RoughtimeServerOwned]) -> Vec<u64> {
        (0..count)
            .filter_map(|_| {
                if servers.is_empty() {
                    Self::get_verified_time().ok()
                } else {
                    Self::get_verified_time_with_servers(servers).ok()
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore] // Requires network access to Roughtime servers; flaky in CI
    fn test_get_verified_time_returns_reasonable_value() {
        if let Ok(ts) = RoughtimeClient::get_verified_time() {
            assert!(ts > 1_600_000_000_000_000);
        }
    }

    #[test]
    fn test_invalid_server_key() {
        let server = RoughtimeServer {
            name: "Bad-Server",
            address: "127.0.0.1:1",
            public_key_base64: "AAAA",
        };
        let result = RoughtimeClient::fetch_time(&server);
        assert!(result.is_err());
    }

    #[test]
    fn test_multiple_servers_configured() {
        assert!(
            SERVERS.len() >= 3,
            "need at least 3 servers for meaningful quorum"
        );
    }

    #[test]
    fn test_quorum_succeeds_with_agreeing_timestamps() {
        let base = 1_700_000_000_000_000u64;
        let mut timestamps = vec![
            (base, "server-a"),
            (base + 1_000_000, "server-b"), // 1s apart
            (base + 5_000_000, "server-c"), // 5s apart
        ];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_ok());
        let t = result.unwrap();
        assert!(t >= base && t <= base + 5_000_000);
    }

    #[test]
    fn test_quorum_fails_with_divergent_timestamps() {
        let mut timestamps = vec![
            (1_000_000_000_000_000, "server-a"),
            (2_000_000_000_000_000, "server-b"), // ~31 years apart
        ];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_fails_with_single_server() {
        let mut timestamps = vec![(1_700_000_000_000_000, "server-a")];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_fails_with_no_servers() {
        let mut timestamps: Vec<(u64, &str)> = vec![];
        let result = RoughtimeClient::find_quorum(&mut timestamps);
        assert!(result.is_err());
    }

    #[test]
    fn test_quorum_picks_median_of_agreeing_group() {
        let base = 1_700_000_000_000_000u64;
        let mut timestamps = vec![
            (base, "server-a"),
            (base + 2_000_000, "server-b"),
            (base + 4_000_000, "server-c"),
            (base + 100_000_000_000, "outlier"), // 100s away, excluded
        ];
        let result = RoughtimeClient::find_quorum(&mut timestamps).unwrap();
        // Median of [base, base+2M, base+4M] = base+2M
        assert_eq!(result, base + 2_000_000);
    }
}
