// SPDX-License-Identifier: Apache-2.0

//! Format-aware serde helpers for hex, base64, and raw byte serialization.
//!
//! All helpers are format-aware: when the serializer reports `is_human_readable()` (JSON,
//! TOML, etc.), data is encoded as hex or base64 strings. For compact formats (CBOR,
//! bincode), raw bytes are used instead.
//!
//! Use these modules with `#[serde(with = "...")]` on struct fields.

use serde::{de, Deserialize, Deserializer, Serializer};
use std::fmt;

/// Maximum decoded byte length for variable-length hex fields (1 MiB).
pub const MAX_HEX_BYTES: usize = 1_048_576;

// ---------------------------------------------------------------------------
// 1. Fixed-Size Arrays [u8; N] — hex (human-readable) or raw bytes (compact)
// ---------------------------------------------------------------------------

pub mod hex_array {
    use super::*;

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&format_args!("{}", hex::encode(bytes)))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor<const N: usize>;
            impl<const N: usize> de::Visitor<'_> for HexVisitor<N> {
                type Value = [u8; N];
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex string of length {}", N * 2)
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    let mut arr = [0u8; N];
                    if v.len() != N * 2 {
                        return Err(E::custom(format!(
                            "expected {} hex chars, got {}",
                            N * 2,
                            v.len()
                        )));
                    }
                    hex::decode_to_slice(v, &mut arr).map_err(E::custom)?;
                    Ok(arr)
                }
            }
            deserializer.deserialize_str(HexVisitor::<N>)
        } else {
            struct BytesVisitor<const N: usize>;
            impl<'de, const N: usize> de::Visitor<'de> for BytesVisitor<N> {
                type Value = [u8; N];
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "{} bytes", N)
                }
                fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                    v.try_into()
                        .map_err(|_| E::custom(format!("expected {} bytes, got {}", N, v.len())))
                }
                fn visit_seq<A: de::SeqAccess<'de>>(
                    self,
                    mut seq: A,
                ) -> Result<Self::Value, A::Error> {
                    let mut arr = [0u8; N];
                    for (i, byte) in arr.iter_mut().enumerate() {
                        *byte = seq
                            .next_element()?
                            .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                    }
                    Ok(arr)
                }
            }
            deserializer.deserialize_any(BytesVisitor::<N>)
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Optional Fixed-Size Arrays Option<[u8; N]> — hex or raw bytes
// ---------------------------------------------------------------------------

pub mod hex_array_opt {
    use super::*;

    pub fn serialize<S, const N: usize>(
        opt: &Option<[u8; N]>,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match opt {
            Some(bytes) => super::hex_array::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D, const N: usize>(
        deserializer: D,
    ) -> Result<Option<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct OptHexVisitor<const N: usize>;
            impl<'de, const N: usize> de::Visitor<'de> for OptHexVisitor<N> {
                type Value = Option<[u8; N]>;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "an optional {}-byte hex string or null", N)
                }
                fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                    Ok(None)
                }
                fn visit_some<D2: Deserializer<'de>>(
                    self,
                    d: D2,
                ) -> Result<Self::Value, D2::Error> {
                    struct InnerVisitor<const N: usize>;
                    impl<'de, const N: usize> de::Visitor<'de> for InnerVisitor<N> {
                        type Value = [u8; N];
                        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            write!(f, "a {}-byte hex string", N)
                        }
                        fn visit_str<E: de::Error>(self, v: &str) -> Result<[u8; N], E> {
                            if v.len() != N * 2 {
                                return Err(E::custom(format!(
                                    "expected {} hex chars, got {}",
                                    N * 2,
                                    v.len()
                                )));
                            }
                            let mut arr = [0u8; N];
                            hex::decode_to_slice(v, &mut arr).map_err(E::custom)?;
                            Ok(arr)
                        }
                    }
                    d.deserialize_str(InnerVisitor::<N>).map(Some)
                }
            }
            deserializer.deserialize_option(OptHexVisitor::<N>)
        } else {
            Option::<Vec<u8>>::deserialize(deserializer)?
                .map(|v| {
                    v.try_into()
                        .map_err(|_| de::Error::custom(format!("expected {} bytes", N)))
                })
                .transpose()
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Byte Vectors Vec<u8> — hex or raw bytes
// ---------------------------------------------------------------------------

pub mod hex_vec {
    use super::*;

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&hex::encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor;
            impl de::Visitor<'_> for HexVisitor {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex-encoded byte string")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                    let bytes = hex::decode(v).map_err(E::custom)?;
                    if bytes.len() > super::MAX_HEX_BYTES {
                        return Err(E::custom(format!(
                            "hex_vec length {} exceeds maximum {}",
                            bytes.len(),
                            super::MAX_HEX_BYTES
                        )));
                    }
                    Ok(bytes)
                }
            }
            deserializer.deserialize_str(HexVisitor)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Optional Byte Vectors Option<Vec<u8>> — hex or raw bytes
// ---------------------------------------------------------------------------

pub mod hex_vec_opt {
    use super::*;

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => super::hex_vec::serialize(bytes, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptVecVisitor;
        impl<'de> de::Visitor<'de> for OptVecVisitor {
            type Value = Option<Vec<u8>>;
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an optional hex-encoded byte string or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                super::hex_vec::deserialize(d).map(Some)
            }
        }
        deserializer.deserialize_option(OptVecVisitor)
    }
}

// ---------------------------------------------------------------------------
// 5. Base64 Byte Vectors Vec<u8> — base64 (human-readable) or raw bytes
// ---------------------------------------------------------------------------

pub mod base64_vec {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&STANDARD.encode(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct B64Visitor;
            impl de::Visitor<'_> for B64Visitor {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a base64-encoded byte string")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                    STANDARD.decode(v).map_err(E::custom)
                }
            }
            deserializer.deserialize_str(B64Visitor)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Raw Bytes — always serialized as bytes (no hex/base64 encoding)
// ---------------------------------------------------------------------------

pub mod raw_array {
    use super::*;

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BytesVisitor<const N: usize>;
        impl<'de, const N: usize> de::Visitor<'de> for BytesVisitor<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{} bytes", N)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Self::Value, E> {
                v.try_into()
                    .map_err(|_| E::custom(format!("expected {} bytes, got {}", N, v.len())))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Self::Value, A::Error> {
                let mut arr = [0u8; N];
                for (i, byte) in arr.iter_mut().enumerate() {
                    *byte = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }
        deserializer.deserialize_any(BytesVisitor::<N>)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_array_roundtrip_json() {
        let original: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let json_str = format!(r#""{}""#, hex::encode(original));
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let decoded: [u8; 4] = hex_array::deserialize(v).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_vec_roundtrip_json() {
        let original = vec![0xca, 0xfe, 0xba, 0xbe];
        let json_str = format!(r#""{}""#, hex::encode(&original));
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let decoded: Vec<u8> = hex_vec::deserialize(v).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_vec_roundtrip_json() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let original = vec![0xde, 0xad, 0xbe, 0xef];
        let json_str = format!(r#""{}""#, STANDARD.encode(&original));
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let decoded: Vec<u8> = base64_vec::deserialize(v).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn hex_array_opt_none() {
        let json_str = "null";
        let v: serde_json::Value = serde_json::from_str(json_str).unwrap();
        let decoded: Option<[u8; 32]> = hex_array_opt::deserialize(v).unwrap();
        assert!(decoded.is_none());
    }

    #[test]
    fn hex_vec_rejects_oversized() {
        let huge = hex::encode(vec![0u8; MAX_HEX_BYTES + 1]);
        let json_str = format!(r#""{huge}""#);
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let result: Result<Vec<u8>, _> = hex_vec::deserialize(v);
        assert!(result.is_err());
    }
}
