// SPDX-License-Identifier: SSPL-1.0 OR LicenseRef-Commercial

use super::{
    default_pcr_selection, Attestation, Binding, Capabilities, PcrSelection, PcrValue, Provider,
    Quote, TpmError,
};
use crate::MutexRecover;
use chrono::Utc;
use sha2::{Digest as Sha2Digest, Sha256};
use std::sync::Mutex;
use tss_esapi::attributes::{NvIndexAttributes, ObjectAttributesBuilder};
use tss_esapi::constants::SessionType;
use tss_esapi::handles::SessionHandle;
use tss_esapi::handles::{KeyHandle, NvIndexHandle, NvIndexTpmHandle};
use tss_esapi::interface_types::algorithm::{
    HashingAlgorithm, PublicAlgorithm, RsaSchemeAlgorithm,
};
use tss_esapi::interface_types::key_bits::RsaKeyBits;
use tss_esapi::interface_types::resource_handles::{Hierarchy, NvAuth, Provision};
use tss_esapi::interface_types::session_handles::{AuthSession, PolicySession};
use tss_esapi::structures::{
    Auth, CreatePrimaryKeyResult, Data, Digest as TssDigest, EccPoint, EccScheme, HashScheme,
    HashcheckTicket, KeyedHashScheme, NvPublicBuilder, PcrSelectionList, PcrSlot, Private, Public,
    PublicBuilder, PublicEccParametersBuilder, PublicKeyRsa, PublicKeyedHashParameters,
    PublicRsaParametersBuilder, RsaExponent, RsaScheme, SensitiveData, SignatureScheme,
    SymmetricDefinition, SymmetricDefinitionObject,
};
use tss_esapi::tcti_ldr::{DeviceConfig, TctiNameConf};
use tss_esapi::traits::{Marshall, UnMarshall};
use tss_esapi::tss2_esys::TPMT_TK_HASHCHECK;
use tss_esapi::Context;

/// TPM2_RH_NULL: indicates data was hashed outside the TPM.
const TPM2_RH_NULL: u32 = 0x40000007;
/// TPM2_ST_HASHCHECK: tag for externally-computed hash tickets (TPM 2.0 Part 2, Table 19).
const TPM2_ST_HASHCHECK: u16 = 0x8024;

const NV_COUNTER_INDEX: u32 = 0x01500001;
const NV_COUNTER_SIZE: usize = 8;

struct LinuxState {
    context: Context,
    ak_handle: Option<KeyHandle>,
    ak_public: Vec<u8>,
    counter_init: bool,
    cached_device_id: Option<String>,
}

impl Drop for LinuxState {
    fn drop(&mut self) {
        if let Some(handle) = self.ak_handle.take() {
            if let Err(e) = self.context.flush_context(handle.into()) {
                log::warn!("Failed to flush AK handle on drop: {e}");
            }
        }
    }
}

/// Linux TPM 2.0 provider via tss-esapi.
///
/// The inner `Mutex` serializes all TPM operations. This is required because
/// `tss_esapi::Context` is not thread-safe and the TPM device (`/dev/tpmrm0`)
/// processes commands sequentially. The lock duration covers the full TPM
/// command (quote, sign, seal, etc.) which is inherent to the hardware.
pub struct LinuxTpmProvider {
    inner: Mutex<LinuxState>,
}

/// Initialize the Linux TPM provider, returning `None` if no TPM is available.
pub fn try_init() -> Option<LinuxTpmProvider> {
    let tcti = TctiNameConf::Device(match "/dev/tpmrm0".parse() {
        Ok(p) => p,
        Err(e) => {
            log::warn!("TPM device path parse failed, using default: {e}");
            DeviceConfig::default()
        }
    });
    let context = Context::new(tcti)
        .or_else(|_| Context::new(TctiNameConf::Device(DeviceConfig::default())))
        .ok()?;

    let mut state = LinuxState {
        context,
        ak_handle: None,
        ak_public: Vec::new(),
        counter_init: false,
        cached_device_id: None,
    };

    let (ak, pub_bytes) = create_ak(&mut state).ok()?;
    state.ak_handle = Some(ak);
    state.ak_public = pub_bytes;

    Some(LinuxTpmProvider {
        inner: Mutex::new(state),
    })
}

impl Provider for LinuxTpmProvider {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            hardware_backed: true,
            supports_pcrs: true,
            supports_sealing: true,
            supports_attestation: true,
            monotonic_counter: true,
            secure_clock: false,
        }
    }

    fn device_id(&self) -> String {
        format_device_id(&mut self.inner.lock_recover())
    }

    fn algorithm(&self) -> coset::iana::Algorithm {
        coset::iana::Algorithm::PS256
    }

    fn public_key(&self) -> Vec<u8> {
        self.inner.lock_recover().ak_public.clone()
    }

    fn quote(&self, nonce: &[u8], pcrs: &[u32]) -> Result<Quote, TpmError> {
        let mut state = self.inner.lock_recover();
        let ak_handle = state.ak_handle.ok_or(TpmError::NotAvailable)?;

        let mut pcr_list = if pcrs.is_empty() {
            default_pcr_selection().pcrs
        } else {
            pcrs.to_vec()
        };
        // TPM returns digests in ascending PCR-index order (bitmask layout);
        // sort the request list so read_pcrs' positional mapping stays correct.
        pcr_list.sort_unstable();
        let selection = build_pcr_selection(&pcr_list)?;
        let qualifying = if nonce.len() > 64 {
            Sha256::digest(nonce).to_vec()
        } else {
            nonce.to_vec()
        };

        // H-049: Read PCRs before quote so the returned values match the
        // state captured in the TPM2_Quote attestation structure.
        let pcr_values = read_pcrs(&mut state, &pcr_list)?;

        let (attest, signature) = state
            .context
            .quote(
                ak_handle,
                Data::try_from(qualifying)
                    .map_err(|e| TpmError::Quote(format!("bad nonce: {e}").into()))?,
                SignatureScheme::RsaSsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                selection,
            )
            .map_err(|e| TpmError::Quote(format!("quote failed: {e}").into()))?;

        let attest_data = attest
            .marshall()
            .map_err(|e| TpmError::Quote(format!("attest marshal: {e}").into()))?;
        let sig_data = signature
            .marshall()
            .map_err(|e| TpmError::Quote(format!("sig marshal: {e}").into()))?;

        let device_id = format_device_id(&mut state);

        Ok(Quote {
            provider_type: "tpm2-linux".to_string(),
            device_id,
            timestamp: Utc::now(),
            nonce: nonce.to_vec(),
            attested_data: attest_data,
            signature: sig_data,
            public_key: state.ak_public.clone(),
            pcr_values,
            extra: Default::default(),
        })
    }

    fn bind(&self, data: &[u8]) -> Result<Binding, TpmError> {
        let mut state = self.inner.lock_recover();
        let ak_handle = state.ak_handle.ok_or(TpmError::NotAvailable)?;

        let timestamp = Utc::now();
        let data_hash = Sha256::digest(data).to_vec();
        let dev_id = format_device_id(&mut state);
        let payload = super::build_binding_payload(&data_hash, &timestamp, &dev_id);

        let digest = Sha256::digest(&payload);

        let signature = state
            .context
            .sign(
                ak_handle,
                TssDigest::try_from(digest.as_slice())
                    .map_err(|e| TpmError::Signing(format!("digest: {e}").into()))?,
                SignatureScheme::RsaSsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                null_hashcheck_ticket()?,
            )
            .map_err(|e| TpmError::Signing(format!("sign failed: {e}").into()))?
            .marshall()
            .map_err(|e| TpmError::Signing(format!("sig marshal: {e}").into()))?;

        let counter = match increment_counter(&mut state) {
            Ok(val) => Some(val),
            Err(e) => {
                log::warn!("TPM counter increment failed: {e}");
                None
            }
        };

        Ok(Binding {
            version: 1,
            provider_type: "tpm2-linux".to_string(),
            device_id: dev_id,
            timestamp,
            attested_hash: data_hash,
            signature,
            public_key: state.ak_public.clone(),
            monotonic_counter: counter,
            safe_clock: None,
            attestation: Some(Attestation {
                payload,
                quote: None,
            }),
        })
    }

    fn verify(&self, binding: &Binding) -> Result<(), TpmError> {
        super::verification::verify_binding(binding)
    }

    fn sign(&self, data: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut state = self.inner.lock_recover();
        let ak_handle = state.ak_handle.ok_or(TpmError::NotAvailable)?;

        let data_hash = Sha256::digest(data).to_vec();

        let signature = state
            .context
            .sign(
                ak_handle,
                TssDigest::try_from(data_hash.as_slice())
                    .map_err(|e| TpmError::Signing(format!("digest: {e}").into()))?,
                SignatureScheme::RsaSsa {
                    hash_scheme: HashScheme::new(HashingAlgorithm::Sha256),
                },
                null_hashcheck_ticket()?,
            )
            .map_err(|e| TpmError::Signing(format!("sign failed: {e}").into()))?
            .marshall()
            .map_err(|e| TpmError::Signing(format!("sig marshal failed: {e}").into()))?;

        Ok(signature)
    }

    /// Seal data to the TPM's current PCR state.
    ///
    /// `_policy` is ignored: the sealing policy is always derived from the
    /// hardcoded PCR selection (`default_pcr_selection()`). A custom policy
    /// parameter would require building an arbitrary policy digest, which is
    /// not needed for the current security model where PCR binding is sufficient.
    fn seal(&self, data: &[u8], _policy: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut state = self.inner.lock_recover();
        let pcrs = default_pcr_selection();
        let srk = create_srk(&mut state)?;
        let srk_handle = srk.key_handle;

        // Track handles acquired inside the closure so they are flushed on every
        // exit path, including failures between acquisition and the closure's
        // Ok return.
        let mut session_handle: Option<SessionHandle> = None;

        let result = (|| -> Result<Vec<u8>, TpmError> {
            let session = create_policy_session(&mut state, &pcrs)?;
            session_handle = Some(session.into());

            // Apply the PCR policy session before creating the sealed object
            state.context.set_sessions((Some(session), None, None));

            let sealing_public = create_sealing_public()?;

            let result = state
                .context
                .create(
                    srk_handle,
                    sealing_public,
                    None,
                    Some(
                        SensitiveData::try_from(data.to_vec())
                            .map_err(|_| TpmError::Sealing("data".into()))?,
                    ),
                    None,
                    None,
                )
                .map_err(|_| TpmError::Sealing("create".into()))?;

            // Clear sessions after sealing
            state.context.clear_sessions();

            let pub_bytes = result
                .out_public
                .marshall()
                .map_err(|_| TpmError::Sealing("public".into()))?;
            let priv_bytes = result.out_private.value().to_vec();

            let mut sealed = Vec::with_capacity(8 + pub_bytes.len() + priv_bytes.len());
            sealed.extend_from_slice(&(pub_bytes.len() as u32).to_be_bytes());
            sealed.extend_from_slice(&pub_bytes);
            sealed.extend_from_slice(&(priv_bytes.len() as u32).to_be_bytes());
            sealed.extend_from_slice(&priv_bytes);

            Ok(sealed)
        })();

        if let Some(sh) = session_handle {
            if let Err(e) = state.context.flush_context(sh.into()) {
                log::error!("TPM handle leak: failed to flush session after seal: {e}");
            }
        }
        if let Err(e) = state.context.flush_context(srk_handle.into()) {
            log::error!("TPM handle leak: failed to flush SRK after seal: {e}");
        }

        result
    }

    fn clock_info(&self) -> Result<super::ClockInfo, TpmError> {
        // tss-esapi 7.x does not expose ReadClock; capabilities() already
        // reports secure_clock: false, so fall back to host monotonic time.
        let elapsed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        Ok(super::ClockInfo {
            clock: elapsed,
            reset_count: 0,
            restart_count: 0,
            safe: false,
        })
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, TpmError> {
        let mut state = self.inner.lock_recover();
        let (pub_bytes, priv_bytes) = super::parse_sealed_blob(sealed)?;

        let public =
            Public::unmarshall(pub_bytes).map_err(|_| TpmError::Unsealing("public".into()))?;
        let private =
            Private::try_from(priv_bytes).map_err(|_| TpmError::Unsealing("private".into()))?;

        let srk = create_srk(&mut state)?;
        let srk_handle = srk.key_handle;

        // Track handles acquired inside the closure so they are flushed on every
        // exit path, including failures between acquisition and the closure's
        // Ok return.
        let mut load_handle_opt: Option<KeyHandle> = None;
        let mut session_handle: Option<SessionHandle> = None;

        let result = (|| -> Result<Vec<u8>, TpmError> {
            let load_handle = state
                .context
                .load(srk_handle, private, public)
                .map_err(|_| TpmError::Unsealing("load".into()))?;
            load_handle_opt = Some(load_handle);

            let session = create_policy_session(&mut state, &default_pcr_selection())?;
            session_handle = Some(session.into());

            state.context.set_sessions((Some(session), None, None));

            let unsealed = state
                .context
                .unseal(load_handle.into())
                .map_err(|_| TpmError::Unsealing("unseal".into()))?;

            state.context.clear_sessions();

            Ok(unsealed.value().to_vec())
        })();

        if let Some(sh) = session_handle {
            if let Err(e) = state.context.flush_context(sh.into()) {
                log::error!("TPM handle leak: failed to flush session after unseal: {e}");
            }
        }
        if let Some(lh) = load_handle_opt {
            if let Err(e) = state.context.flush_context(lh.into()) {
                log::error!("TPM handle leak: failed to flush object after unseal: {e}");
            }
        }
        if let Err(e) = state.context.flush_context(srk_handle.into()) {
            log::error!("TPM handle leak: failed to flush SRK after unseal: {e}");
        }

        result
    }
}

fn null_hashcheck_ticket() -> Result<HashcheckTicket, TpmError> {
    HashcheckTicket::try_from(TPMT_TK_HASHCHECK {
        tag: TPM2_ST_HASHCHECK,
        hierarchy: TPM2_RH_NULL,
        digest: tss_esapi::tss2_esys::TPM2B_DIGEST {
            size: 0,
            buffer: [0; 64],
        },
    })
    .map_err(|e| TpmError::Signing(format!("null hashcheck ticket: {e}").into()))
}

fn create_ak(state: &mut LinuxState) -> Result<(KeyHandle, Vec<u8>), TpmError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_sign_encrypt(true)
        .build()
        .map_err(|_| TpmError::NotAvailable)?;

    let rsa_params = PublicRsaParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_scheme(
            RsaScheme::create(RsaSchemeAlgorithm::RsaSsa, Some(HashingAlgorithm::Sha256))
                .map_err(|_| TpmError::NotAvailable)?,
        )
        .with_key_bits(RsaKeyBits::Rsa2048)
        .with_exponent(RsaExponent::default())
        .build()
        .map_err(|_| TpmError::NotAvailable)?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_rsa_parameters(rsa_params)
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|_| TpmError::NotAvailable)?;

    let auth = {
        let mut auth_bytes = zeroize::Zeroizing::new([0u8; 32]);
        getrandom::getrandom(auth_bytes.as_mut_slice()).map_err(|_| TpmError::NotAvailable)?;
        Auth::try_from(auth_bytes.as_slice().to_vec()).map_err(|_| TpmError::NotAvailable)?
        // auth_bytes zeroized on drop here
    };

    let result = state
        .context
        .create_primary(Hierarchy::Endorsement, public, Some(auth), None, None, None)
        .map_err(|_| TpmError::NotAvailable)?;

    let pub_bytes = result
        .out_public
        .marshall()
        .map_err(|_| TpmError::NotAvailable)?;

    Ok((result.key_handle, pub_bytes))
}

fn create_sealing_public() -> Result<Public, TpmError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_user_with_auth(true)
        .build()
        .map_err(|_| TpmError::Sealing("attributes".into()))?;

    PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::KeyedHash)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_keyed_hash_parameters(PublicKeyedHashParameters::new(KeyedHashScheme::Null))
        .with_keyed_hash_unique_identifier(TssDigest::default())
        .build()
        .map_err(|_| TpmError::Sealing("sealing public".into()))
}

fn create_srk(state: &mut LinuxState) -> Result<CreatePrimaryKeyResult, TpmError> {
    let object_attributes = ObjectAttributesBuilder::new()
        .with_fixed_tpm(true)
        .with_fixed_parent(true)
        .with_sensitive_data_origin(true)
        .with_user_with_auth(true)
        .with_restricted(true)
        .with_decrypt(true)
        .build()
        .map_err(|_| TpmError::Sealing("attributes".into()))?;

    let ecc_params = PublicEccParametersBuilder::new()
        .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
        .with_ecc_scheme(EccScheme::Null)
        .with_curve(tss_esapi::interface_types::ecc::EccCurve::NistP256)
        .build()
        .map_err(|_| TpmError::Sealing("ecc params".into()))?;

    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Ecc)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(object_attributes)
        .with_ecc_parameters(ecc_params)
        .with_ecc_unique_identifier(EccPoint::default())
        .build()
        .map_err(|_| TpmError::Sealing("public".into()))?;

    state
        .context
        .create_primary(Hierarchy::Owner, public, None, None, None, None)
        .map_err(|_| TpmError::Sealing("create primary".into()))
}

fn format_device_id(state: &mut LinuxState) -> String {
    if let Some(ref cached) = state.cached_device_id {
        return cached.clone();
    }
    let id = match get_device_id(state) {
        Ok(raw) => format!("tpm-{}", crate::utils::short_hex_id(&raw)),
        Err(_) => return "tpm-unknown".to_string(),
    };
    state.cached_device_id = Some(id.clone());
    id
}

fn get_device_id(state: &mut LinuxState) -> Result<Vec<u8>, TpmError> {
    let public = PublicBuilder::new()
        .with_public_algorithm(PublicAlgorithm::Rsa)
        .with_name_hashing_algorithm(HashingAlgorithm::Sha256)
        .with_object_attributes(
            ObjectAttributesBuilder::new()
                .with_fixed_tpm(true)
                .with_fixed_parent(true)
                .with_sensitive_data_origin(true)
                .with_user_with_auth(false)
                .with_decrypt(true)
                .with_restricted(true)
                .build()
                .map_err(|_| TpmError::NotAvailable)?,
        )
        .with_rsa_parameters(
            PublicRsaParametersBuilder::new()
                .with_symmetric(SymmetricDefinitionObject::AES_128_CFB)
                .with_scheme(
                    RsaScheme::create(RsaSchemeAlgorithm::Null, None)
                        .map_err(|_| TpmError::NotAvailable)?,
                )
                .with_key_bits(RsaKeyBits::Rsa2048)
                .with_exponent(RsaExponent::default())
                .build()
                .map_err(|_| TpmError::NotAvailable)?,
        )
        .with_rsa_unique_identifier(PublicKeyRsa::default())
        .build()
        .map_err(|_| TpmError::NotAvailable)?;

    let result = state
        .context
        .create_primary(Hierarchy::Endorsement, public, None, None, None, None)
        .map_err(|_| TpmError::NotAvailable)?;

    let key_handle = result.key_handle;
    let marshalled = result.out_public.marshall();

    if let Err(e) = state.context.flush_context(key_handle.into()) {
        log::warn!("flush_context after fingerprint: {e}");
    }

    let pub_bytes = marshalled.map_err(|_| TpmError::NotAvailable)?;
    let hash = Sha256::digest(&pub_bytes);
    Ok(hash.to_vec())
}

fn build_pcr_selection(pcrs: &[u32]) -> Result<PcrSelectionList, TpmError> {
    let mut selection = vec![];
    for pcr in pcrs {
        selection.push(PcrSlot::try_from(*pcr).map_err(|_| TpmError::NotAvailable)?);
    }

    PcrSelectionList::builder()
        .with_selection(HashingAlgorithm::Sha256, &selection)
        .build()
        .map_err(|_| TpmError::NotAvailable)
}

fn read_pcrs(state: &mut LinuxState, pcrs: &[u32]) -> Result<Vec<PcrValue>, TpmError> {
    let selection = build_pcr_selection(pcrs)?;
    let (_, _, digests) = state
        .context
        .pcr_read(selection)
        .map_err(|_| TpmError::Quote("pcr read".into()))?;

    let mut values = Vec::new();
    for (idx, pcr) in pcrs.iter().enumerate() {
        if let Some(digest) = digests.value().get(idx) {
            values.push(PcrValue {
                index: *pcr,
                value: digest.value().to_vec(),
            });
        }
    }

    Ok(values)
}

/// NV counter uses `Auth::default()` (empty). In the current threat model, only
/// the app process accesses `/dev/tpmrm0`.
fn init_counter(state: &mut LinuxState) -> Result<(), TpmError> {
    let nv_index = NvIndexTpmHandle::new(NV_COUNTER_INDEX).map_err(|_| TpmError::CounterNotInit)?;
    let nv_handle = NvIndexHandle::from(NV_COUNTER_INDEX);

    if let Ok((nv_public, _)) = state.context.nv_read_public(nv_handle) {
        let actual_size = nv_public.data_size();
        if actual_size != NV_COUNTER_SIZE {
            return Err(TpmError::CounterNotInit);
        }
        state.counter_init = true;
        return Ok(());
    }

    let attributes = NvIndexAttributes::builder()
        .with_nv_index_type(tss_esapi::constants::NvIndexType::Counter)
        .with_owner_write(true)
        .with_owner_read(true)
        .build()
        .map_err(|_| TpmError::CounterNotInit)?;

    let public = NvPublicBuilder::new()
        .with_nv_index(nv_index)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attributes)
        .with_data_area_size(NV_COUNTER_SIZE)
        .build()
        .map_err(|_| TpmError::CounterNotInit)?;

    state
        .context
        .nv_define_space(Provision::Owner, Some(Auth::default()), public)
        .map_err(|_| TpmError::CounterNotInit)?;

    state.counter_init = true;
    Ok(())
}

fn read_counter(state: &mut LinuxState) -> Result<u64, TpmError> {
    let nv_handle = NvIndexHandle::from(NV_COUNTER_INDEX);
    let data = state
        .context
        .nv_read(
            NvAuth::NvIndex(nv_handle),
            nv_handle,
            NV_COUNTER_SIZE as u16,
            0,
        )
        .map_err(|_| TpmError::CounterNotInit)?;

    let bytes = data.value();
    if bytes.len() < 8 {
        return Err(TpmError::CounterNotInit);
    }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&bytes[..8]);
    Ok(u64::from_be_bytes(buf))
}

fn increment_counter(state: &mut LinuxState) -> Result<u64, TpmError> {
    if !state.counter_init {
        init_counter(state)?;
    }

    let nv_handle = NvIndexHandle::from(NV_COUNTER_INDEX);
    state
        .context
        .nv_increment(NvAuth::NvIndex(nv_handle), nv_handle)
        .map_err(|_| TpmError::CounterNotInit)?;
    read_counter(state)
}

fn create_policy_session(
    state: &mut LinuxState,
    pcrs: &PcrSelection,
) -> Result<AuthSession, TpmError> {
    let selection = build_pcr_selection(&pcrs.pcrs)?;
    let session = state
        .context
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Policy,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )
        .map_err(|_| TpmError::Sealing("session".into()))?
        .ok_or_else(|| TpmError::Sealing("no session returned".into()))?;

    let policy_session: PolicySession = session
        .try_into()
        .map_err(|_| TpmError::Sealing("session conversion".into()))?;

    state
        .context
        .policy_pcr(policy_session, TssDigest::default(), selection)
        .map_err(|_| TpmError::Sealing("policy".into()))?;

    Ok(session)
}
