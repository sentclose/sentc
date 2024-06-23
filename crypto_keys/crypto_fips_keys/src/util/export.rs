use openssl::base64::{decode_block, encode_block};
use pem_rfc7468::LineEnding;
use sentc_crypto_utils::error::SdkUtilError;

use crate::core::asym::{RsaPk, FIPS_OPENSSL_RSA_OAEP_WRAP};
use crate::core::sign::{Ed25519FIPSSig, Ed25519FIPSVerifyK, FIPS_OPENSSL_ED25519};

pub fn import_key_from_pem(pem: &str) -> Result<Vec<u8>, SdkUtilError>
{
	let (_type_label, data) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| SdkUtilError::ImportingKeyFromPemFailed)?;

	Ok(data)
}

pub fn export_key_to_pem(key: &[u8]) -> Result<String, SdkUtilError>
{
	//export should not panic because we are creating the keys
	let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::default(), key).map_err(|_| SdkUtilError::ExportingPublicKeyFailed)?;

	Ok(key)
}

pub fn import_public_key_from_pem_with_alg(public_key: &str, alg: &str) -> Result<RsaPk, SdkUtilError>
{
	if alg != FIPS_OPENSSL_RSA_OAEP_WRAP {
		return Err(SdkUtilError::AlgNotFound);
	}

	let bytes = import_key_from_pem(public_key)?;

	Ok(RsaPk::import(&bytes)?)
}

pub fn import_verify_key_from_pem_with_alg(verify_key: &str, alg: &str) -> Result<Ed25519FIPSVerifyK, SdkUtilError>
{
	if alg != FIPS_OPENSSL_ED25519 {
		return Err(SdkUtilError::AlgNotFound);
	}

	let bytes = import_key_from_pem(verify_key)?;

	Ok(Ed25519FIPSVerifyK::import(&bytes)?)
}

pub fn export_raw_public_key_to_pem(key: &RsaPk) -> Result<String, SdkUtilError>
{
	export_key_to_pem(&key.export()?)
}

pub fn export_raw_verify_key_to_pem(key: &Ed25519FIPSVerifyK) -> Result<String, SdkUtilError>
{
	export_key_to_pem(&key.export()?)
}

pub fn sig_to_string(sig: &Ed25519FIPSSig) -> String
{
	encode_block(sig.as_ref())
}

pub fn import_sig_from_string(sig: &str, alg: &str) -> Result<Ed25519FIPSSig, SdkUtilError>
{
	if alg != FIPS_OPENSSL_ED25519 {
		return Err(SdkUtilError::AlgNotFound);
	}

	let bytes = decode_block(sig).map_err(|_| SdkUtilError::DecodePublicKeyFailed)?;

	Ok(Ed25519FIPSSig::try_from(bytes)?)
}
