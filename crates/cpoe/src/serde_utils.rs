// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use serde::{de, Deserialize, Deserializer, Serializer};
use std::fmt;

struct LazyHexDisplay<'a>(&'a [u8]);

impl fmt::Display for LazyHexDisplay<'_> {
    #[inline(always)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &byte in self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

pub mod hex_array {
    use super::*;

    #[inline]
    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&LazyHexDisplay(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    #[inline]
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor<const N: usize>;
            impl<'de, const N: usize> de::Visitor<'de> for HexVisitor<N> {
                type Value = [u8; N];
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex string of length {}", N * 2)
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Self::Value, E> {
                    let mut arr = [0u8; N];
                    if v.len() != N * 2 {
                        return Err(E::custom(format_args!(
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
            super::raw_array::deserialize(deserializer)
        }
    }
}

pub mod hex_array_opt {
    use super::*;

    #[inline]
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

    #[inline]
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<Option<[u8; N]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct OptHexVisitor<const N: usize> {
            is_human: bool,
        }

        impl<'de, const N: usize> de::Visitor<'de> for OptHexVisitor<N> {
            type Value = Option<[u8; N]>;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "an optional {}-byte entry or null", N)
            }

            #[inline]
            fn visit_none<E: de::Error>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            #[inline]
            fn visit_some<D2: Deserializer<'de>>(self, d: D2) -> Result<Self::Value, D2::Error> {
                if self.is_human {
                    struct InnerVisitor<const N: usize>;
                    impl<'b, const N: usize> de::Visitor<'b> for InnerVisitor<N> {
                        type Value = [u8; N];
                        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                            write!(f, "a {}-byte hex string", N)
                        }
                        fn visit_str<E: de::Error>(self, v: &str) -> Result<[u8; N], E> {
                            if v.len() != N * 2 {
                                return Err(E::custom(format_args!(
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
                } else {
                    super::raw_array::deserialize(d).map(Some)
                }
            }
        }

        let is_human = deserializer.is_human_readable();
        deserializer.deserialize_option(OptHexVisitor::<N> { is_human })
    }
}

pub mod hex_vec {
    use super::*;

    #[inline]
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&LazyHexDisplay(bytes))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    #[inline]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct HexVisitor;
            impl<'a> de::Visitor<'a> for HexVisitor {
                type Value = Vec<u8>;
                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(f, "a hex-encoded byte string")
                }
                fn visit_str<E: de::Error>(self, v: &str) -> Result<Vec<u8>, E> {
                    hex::decode(v).map_err(E::custom)
                }
            }
            deserializer.deserialize_str(HexVisitor)
        } else {
            Vec::<u8>::deserialize(deserializer)
        }
    }
}

pub mod base64_vec {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[inline]
    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&base64::display::Base64Display::new(bytes, &STANDARD))
        } else {
            serializer.serialize_bytes(bytes)
        }
    }

    #[inline]
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            struct B64Visitor;
            impl<'a> de::Visitor<'a> for B64Visitor {
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

pub mod raw_array {
    use super::*;

    #[inline]
    pub fn serialize<S, const N: usize>(bytes: &[u8; N], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(bytes)
    }

    #[inline]
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
                    .map_err(|_| E::custom(format_args!("expected {} bytes, got {}", N, v.len())))
            }
            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
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

pub mod hex_bytes_32 {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        super::hex_array::serialize(bytes, s)
    }
    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        super::hex_array::deserialize(d)
    }
}

pub mod hex_bytes_64 {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S: Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        super::hex_array::serialize(bytes, s)
    }
    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        super::hex_array::deserialize(d)
    }
}

pub mod hex_serde {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S, T>(data: T, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
        T: AsRef<[u8]>,
    {
        if serializer.is_human_readable() {
            serializer.collect_str(&super::LazyHexDisplay(data.as_ref()))
        } else {
            serializer.serialize_bytes(data.as_ref())
        }
    }
    #[inline]
    pub fn deserialize<'de, D, const N: usize>(deserializer: D) -> Result<[u8; N], D::Error>
    where
        D: Deserializer<'de>,
    {
        super::hex_array::deserialize(deserializer)
    }
}

pub mod hex_vec_serde {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        super::hex_vec::serialize(data, s)
    }
    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::hex_vec::deserialize(d)
    }
}

pub mod base64_serde {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S: Serializer>(data: &[u8], s: S) -> Result<S::Ok, S::Error> {
        super::base64_vec::serialize(data, s)
    }
    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        super::base64_vec::deserialize(d)
    }
}

pub mod serde_array_32 {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S: Serializer>(value: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error> {
        super::raw_array::serialize(value, serializer)
    }
    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 32], D::Error> {
        super::raw_array::deserialize(deserializer)
    }
}

pub mod serde_array_64 {
    use serde::{Deserializer, Serializer};
    #[inline]
    pub fn serialize<S: Serializer>(value: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error> {
        super::raw_array::serialize(value, serializer)
    }
    #[inline]
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<[u8; 64], D::Error> {
        super::raw_array::deserialize(deserializer)
    }
}

macro_rules! optional_hex_serde {
    ($ser:ident, $de:ident, $size:expr) => {
        #[inline]
        pub fn $ser<S>(bytes: &Option<[u8; $size]>, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            crate::serde_utils::hex_array_opt::serialize(bytes, serializer)
        }

        #[inline]
        pub fn $de<'de, D>(deserializer: D) -> Result<Option<[u8; $size]>, D::Error>
        where
            D: Deserializer<'de>,
        {
            crate::serde_utils::hex_array_opt::deserialize(deserializer)
        }
    };
}

optional_hex_serde!(serialize_optional_nonce, deserialize_optional_nonce, 32);
optional_hex_serde!(
    serialize_optional_signature,
    deserialize_optional_signature,
    64
);
optional_hex_serde!(serialize_optional_pubkey, deserialize_optional_pubkey, 32);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_visitor_roundtrip() {
        let original: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
        let json_str = format!(r#""{}""#, hex::encode(original));
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let decoded: [u8; 4] = hex_array::deserialize(v).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn b64_visitor_roundtrip() {
        use base64::{engine::general_purpose::STANDARD, Engine};
        let original = vec![0xde, 0xad, 0xbe, 0xef];
        let json_str = format!(r#""{}""#, STANDARD.encode(&original));
        let v: serde_json::Value = serde_json::from_str(&json_str).unwrap();
        let decoded: Vec<u8> = base64_vec::deserialize(v).unwrap();
        assert_eq!(decoded, original);
    }
}
