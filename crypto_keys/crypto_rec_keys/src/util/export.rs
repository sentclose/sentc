use openssl::base64::{decode_block, encode_block};
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::{export_key_to_pem, import_key_from_pem};

use crate::core::asym::{PublicKey, ECIES_ML_KEM_REC_HYBRID_OUTPUT, ECIES_REC_OUTPUT, ML_KEM_REC_OUTPUT};
use crate::core::sign::{Signature, VerifyKey, ED25519_ML_DSA_HYBRID_REC_OUTPUT, FIPS_OPENSSL_ED25519, ML_DSA_REC_OUTPUT};
use crate::util::HybridPublicKeyExportFormat;

pub fn import_public_key_from_pem_with_alg(public_key: &str, alg: &str) -> Result<PublicKey, SdkUtilError>
{
	match alg {
		ECIES_REC_OUTPUT => {
			let bytes = import_key_from_pem(public_key)?;
			Ok(PublicKey::ecies_from_bytes_owned(bytes)?)
		},
		ML_KEM_REC_OUTPUT => {
			let bytes = import_key_from_pem(public_key)?;
			Ok(PublicKey::ml_kem_from_bytes_owned(bytes))
		},
		ECIES_ML_KEM_REC_HYBRID_OUTPUT => {
			let key: HybridPublicKeyExportFormat = serde_json::from_str(public_key).map_err(SdkUtilError::JsonParseFailed)?;

			let bytes_x = import_key_from_pem(&key.x)?;
			let bytes_k = import_key_from_pem(&key.k)?;

			Ok(PublicKey::ecies_ml_kem_hybrid_from_bytes_owned(bytes_x, bytes_k)?)
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

pub fn import_verify_key_from_pem_with_alg(verify_key: &str, alg: &str) -> Result<VerifyKey, SdkUtilError>
{
	match alg {
		FIPS_OPENSSL_ED25519 => {
			let bytes = import_key_from_pem(verify_key)?;
			Ok(VerifyKey::ed25519_from_bytes_owned(bytes)?)
		},
		ML_DSA_REC_OUTPUT => {
			let bytes = import_key_from_pem(verify_key)?;
			Ok(VerifyKey::ml_dsa_from_bytes_owned(bytes))
		},
		ED25519_ML_DSA_HYBRID_REC_OUTPUT => {
			let key: HybridPublicKeyExportFormat = serde_json::from_str(verify_key).map_err(SdkUtilError::JsonParseFailed)?;

			let bytes_x = import_key_from_pem(&key.x)?;
			let bytes_k = import_key_from_pem(&key.k)?;

			Ok(VerifyKey::ed25519_ml_dsa_hybrid_from_bytes_owned(bytes_x, bytes_k)?)
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

pub fn import_sig_from_string(sig: &str, alg: &str) -> Result<Signature, SdkUtilError>
{
	match alg {
		FIPS_OPENSSL_ED25519 => {
			let bytes = decode_block(sig).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;
			Ok(Signature::ed25519_from_bytes_owned(bytes))
		},
		ML_DSA_REC_OUTPUT => {
			let bytes = decode_block(sig).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;
			Ok(Signature::ml_dsa_from_bytes_owned(bytes))
		},
		ED25519_ML_DSA_HYBRID_REC_OUTPUT => {
			let key: HybridPublicKeyExportFormat = serde_json::from_str(sig).map_err(SdkUtilError::JsonParseFailed)?;

			let bytes_x = decode_block(&key.x).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;
			let bytes_k = decode_block(&key.k).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;

			Ok(Signature::ed25519_ml_dsa_hybrid_from_bytes_owned(bytes_x, bytes_k))
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

pub fn sig_to_string(sig: &Signature) -> String
{
	match sig {
		Signature::Ed25519(s) => encode_block(s.as_ref()),
		Signature::MlDsa(s) => encode_block(s.as_ref()),
		Signature::Ed25519MlDsaHybrid(s) => {
			let (x, k) = s.get_raw_sig();

			let x = encode_block(x);
			let k = encode_block(k);

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
		PublicKey::Ecies(key) => export_key_to_pem(&key.export()?),
		PublicKey::MlKem(key) => export_key_to_pem(key.as_ref()),
		PublicKey::EciesMlKemHybrid(key) => {
			let (x, k) = key.prepare_export()?;

			let x = export_key_to_pem(&x)?;
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
		VerifyKey::Ed25519(key) => export_key_to_pem(&key.export()?),
		VerifyKey::MlDsa(key) => export_key_to_pem(key.as_ref()),
		VerifyKey::Ed25519MlDsaHybrid(key) => {
			let (x, k) = key.prepare_export()?;

			let x = export_key_to_pem(&x)?;
			let k = export_key_to_pem(k)?;

			serde_json::to_string(&HybridPublicKeyExportFormat {
				x,
				k,
			})
			.map_err(|_| SdkUtilError::JsonToStringFailed)
		},
	}
}
