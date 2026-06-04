// SPDX-License-Identifier: Apache-2.0

//! Shared serde helpers for hex-encoded byte fields in RFC structures.
//!
//! Consolidates the duplicated `mod hex_bytes` / `mod hex_bytes_vec` helpers
//! that were previously copy-pasted across multiple rfc submodules.

/// Hex serde for fixed-size byte arrays (const-generic).
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes")]`
pub(crate) mod hex_bytes {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexVisitor<const N: usize>;
        impl<'a, const N: usize> de::Visitor<'a> for HexVisitor<N> {
            type Value = [u8; N];
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
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
        deserializer.deserialize_str(HexVisitor::<N>)
    }
}

/// Hex serde for variable-length byte vectors.
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes_vec")]`
pub(crate) mod hex_bytes_vec {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    /// Maximum decoded byte length for variable-length hex fields (1 MiB).
    pub const MAX_HEX_BYTES: usize = 1_048_576;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct HexVecVisitor;
        impl<'a> de::Visitor<'a> for HexVecVisitor {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a hex-encoded byte string")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                let bytes = hex::decode(v).map_err(E::custom)?;
                if bytes.len() > MAX_HEX_BYTES {
                    return Err(E::custom(format!(
                        "hex_bytes_vec length {} exceeds maximum {}",
                        bytes.len(),
                        MAX_HEX_BYTES
                    )));
                }
                Ok(bytes)
            }
        }
        deserializer.deserialize_str(HexVecVisitor)
    }
}

/// Hex serde for optional fixed-size 32-byte arrays.
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes_32_opt")]`
pub(crate) mod hex_bytes_32_opt {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptVisitor;
        impl<'a> de::Visitor<'a> for OptVisitor {
            type Value = Option<[u8; 32]>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "an optional 32-byte hex string or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D2: de::Deserializer<'a>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                struct InnerVisitor;
                impl<'b> de::Visitor<'b> for InnerVisitor {
                    type Value = [u8; 32];
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "a 32-byte hex string")
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> Result<[u8; 32], E> {
                        if v.len() != 64 {
                            return Err(E::custom(format!(
                                "expected 64 hex chars, got {}",
                                v.len()
                            )));
                        }
                        let mut arr = [0u8; 32];
                        hex::decode_to_slice(v, &mut arr).map_err(E::custom)?;
                        Ok(arr)
                    }
                }
                d.deserialize_str(InnerVisitor).map(Some)
            }
        }
        deserializer.deserialize_option(OptVisitor)
    }
}

/// Hex serde for optional variable-length byte vectors.
///
/// Usage: `#[serde(with = "crate::rfc::serde_helpers::hex_bytes_vec_opt")]`
pub(crate) mod hex_bytes_vec_opt {
    use serde::{de, Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_str(&hex::encode(bytes)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptVecVisitor;
        impl<'a> de::Visitor<'a> for OptVecVisitor {
            type Value = Option<Vec<u8>>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "an optional hex-encoded byte string or null")
            }
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }
            fn visit_some<D2: de::Deserializer<'a>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                struct InnerVisitor;
                impl<'b> de::Visitor<'b> for InnerVisitor {
                    type Value = Vec<u8>;
                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "a hex-encoded byte string")
                    }
                    fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                        let bytes = hex::decode(v).map_err(E::custom)?;
                        if bytes.len() > super::hex_bytes_vec::MAX_HEX_BYTES {
                            return Err(E::custom(format!(
                                "hex_bytes_vec_opt length {} exceeds maximum {}",
                                bytes.len(),
                                super::hex_bytes_vec::MAX_HEX_BYTES
                            )));
                        }
                        Ok(bytes)
                    }
                }
                d.deserialize_str(InnerVisitor).map(Some)
            }
        }
        deserializer.deserialize_option(OptVecVisitor)
    }
}
