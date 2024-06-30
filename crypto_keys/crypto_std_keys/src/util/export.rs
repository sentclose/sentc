use alloc::string::String;

use base64ct::{Base64, Encoding};
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::{export_key_to_pem, import_key_from_pem};

use crate::core::{
	PublicKey,
	Signature,
	VerifyKey,
	DILITHIUM_OUTPUT,
	ECIES_KYBER_HYBRID_OUTPUT,
	ECIES_OUTPUT,
	ED25519_DILITHIUM_HYBRID_OUTPUT,
	ED25519_OUTPUT,
	KYBER_OUTPUT,
};
use crate::util::HybridPublicKeyExportFormat;

pub fn import_public_key_from_pem_with_alg(public_key: &str, alg: &str) -> Result<PublicKey, SdkUtilError>
{
	match alg {
		ECIES_OUTPUT => {
			let bytes = import_key_from_pem(public_key)?;
			Ok(PublicKey::ecies_from_bytes_owned(bytes)?)
		},
		KYBER_OUTPUT => {
			let bytes = import_key_from_pem(public_key)?;
			Ok(PublicKey::kyber_from_bytes_owned(bytes)?)
		},
		ECIES_KYBER_HYBRID_OUTPUT => {
			let key: HybridPublicKeyExportFormat = serde_json::from_str(public_key).map_err(SdkUtilError::JsonParseFailed)?;

			let bytes_x = import_key_from_pem(&key.x)?;
			let bytes_k = import_key_from_pem(&key.k)?;

			Ok(PublicKey::ecies_kyber_hybrid_from_bytes_owned(bytes_x, bytes_k)?)
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

pub fn import_verify_key_from_pem_with_alg(verify_key: &str, alg: &str) -> Result<VerifyKey, SdkUtilError>
{
	match alg {
		ED25519_OUTPUT => {
			let bytes = import_key_from_pem(verify_key)?;
			Ok(VerifyKey::ed25519_from_bytes_owned(bytes)?)
		},
		DILITHIUM_OUTPUT => {
			let bytes = import_key_from_pem(verify_key)?;
			Ok(VerifyKey::dilithium_from_bytes_owned(bytes)?)
		},
		ED25519_DILITHIUM_HYBRID_OUTPUT => {
			let key: HybridPublicKeyExportFormat = serde_json::from_str(verify_key).map_err(SdkUtilError::JsonParseFailed)?;

			let bytes_x = import_key_from_pem(&key.x)?;
			let bytes_k = import_key_from_pem(&key.k)?;

			Ok(VerifyKey::ed25519_dilithium_hybrid_from_bytes_owned(
				bytes_x, bytes_k,
			)?)
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

pub fn import_sig_from_string(sig: &str, alg: &str) -> Result<Signature, SdkUtilError>
{
	match alg {
		ED25519_OUTPUT => {
			let bytes = Base64::decode_vec(sig).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;
			Ok(Signature::ed25519_from_bytes_owned(bytes)?)
		},
		DILITHIUM_OUTPUT => {
			let bytes = Base64::decode_vec(sig).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;
			Ok(Signature::dilithium_from_bytes_owned(bytes)?)
		},
		ED25519_DILITHIUM_HYBRID_OUTPUT => {
			let key: HybridPublicKeyExportFormat = serde_json::from_str(sig).map_err(SdkUtilError::JsonParseFailed)?;

			let x = Base64::decode_vec(&key.x).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;
			let k = Base64::decode_vec(&key.k).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;

			Ok(Signature::ed25519_dilithium_hybrid_from_bytes_owned(x, k)?)
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

pub fn sig_to_string(sig: &Signature) -> String
{
	match sig {
		Signature::Ed25519(s) => Base64::encode_string(s.as_ref()),
		Signature::Dilithium(s) => Base64::encode_string(s.as_ref()),
		Signature::Ed25519DilithiumHybrid(s) => {
			let (x, k) = s.get_raw_keys();

			let x = Base64::encode_string(x);
			let k = Base64::encode_string(k);

			serde_json::to_string(&HybridPublicKeyExportFormat {
				x,
				k,
			})
			.unwrap()
		},
	}
}

pub fn export_raw_public_key_to_pem(key: &PublicKey) -> Result<String, SdkUtilError>
{
	match key {
		//match against the public key variants
		PublicKey::Ecies(k) => export_key_to_pem(k.as_ref()),
		PublicKey::Kyber(k) => export_key_to_pem(k.as_ref()),
		PublicKey::EciesKyberHybrid(key) => {
			let (x, k) = key.get_raw_keys();

			let x = export_key_to_pem(x)?;
			let k = export_key_to_pem(k)?;

			serde_json::to_string(&HybridPublicKeyExportFormat {
				x,
				k,
			})
			.map_err(|_| SdkUtilError::JsonToStringFailed)
		},
	}
}

pub fn export_raw_verify_key_to_pem(key: &VerifyKey) -> Result<String, SdkUtilError>
{
	match key {
		VerifyKey::Ed25519(k) => export_key_to_pem(k.as_ref()),
		VerifyKey::Dilithium(k) => export_key_to_pem(k.as_ref()),
		VerifyKey::Ed25519DilithiumHybrid(key) => {
			let (x, k) = key.get_raw_keys();

			let x = export_key_to_pem(x)?;
			let k = export_key_to_pem(k)?;

			serde_json::to_string(&HybridPublicKeyExportFormat {
				x,
				k,
			})
			.map_err(|_| SdkUtilError::JsonToStringFailed)
		},
	}
}
