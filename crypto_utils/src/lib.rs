#![no_std]
#![allow(clippy::type_complexity)]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use pem_rfc7468::LineEnding;
use sentc_crypto_common::server_default::ServerSuccessOutput;
use sentc_crypto_common::ServerOutput;
use sentc_crypto_core::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	HashedAuthenticationKey,
	PublicKey,
	Signature,
	VerifyKey,
	ARGON_2_OUTPUT,
	DILITHIUM_OUTPUT,
	ECIES_KYBER_HYBRID_OUTPUT,
	ECIES_OUTPUT,
	ED25519_DILITHIUM_HYBRID_OUTPUT,
	ED25519_OUTPUT,
	KYBER_OUTPUT,
};
use serde::Deserialize;

use crate::error::SdkUtilError;
use crate::keys::HybridPublicKeyExportFormat;

pub mod cryptomat;
pub mod error;
#[cfg(all(feature = "crypto_full", any(feature = "rustls", feature = "wasm")))]
pub mod full;
pub mod group;
#[cfg(any(feature = "rustls", feature = "wasm"))]
pub mod http;
pub mod jwt;
pub mod keys;
pub mod user;

pub fn handle_server_response<'de, T: Deserialize<'de>>(res: &'de str) -> Result<T, SdkUtilError>
{
	let server_output = ServerOutput::<T>::from_string(res)?;

	if !server_output.status {
		let err_code = match server_output.err_code {
			Some(c) => c,
			None => return Err(SdkUtilError::JsonParse),
		};

		let err_msg = match server_output.err_msg {
			Some(m) => m,
			None => return Err(SdkUtilError::JsonParse),
		};

		return Err(SdkUtilError::ServerErr(err_code, err_msg));
	}

	match server_output.result {
		Some(r) => Ok(r),
		None => Err(SdkUtilError::JsonParse),
	}
}

pub type StdDeviceKeyDataInt = user::DeviceKeyDataInt<keys::SecretKey, keys::PublicKey, keys::SignKey, keys::VerifyKey>;
pub type StdUserPreVerifyLogin = user::UserPreVerifyLogin<keys::SecretKey, keys::PublicKey, keys::SignKey, keys::VerifyKey>;

/**
Getting the result of a simple server response.
 */
pub fn handle_general_server_response(res: &str) -> Result<(), SdkUtilError>
{
	handle_server_response::<ServerSuccessOutput>(res)?;

	Ok(())
}

pub fn client_random_value_to_string(client_random_value: &ClientRandomValue) -> String
{
	let out = client_random_value.prepare_export();

	Base64::encode_string(out)
}

pub fn hashed_authentication_key_to_string(hashed_authentication_key_bytes: &HashedAuthenticationKey) -> String
{
	let out = hashed_authentication_key_bytes.prepare_export();

	Base64::encode_string(out)
}

pub fn export_key_to_pem(key: &[u8]) -> Result<String, SdkUtilError>
{
	//export should not panic because we are creating the keys
	let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::default(), key).map_err(|_| SdkUtilError::ExportingPublicKeyFailed)?;

	Ok(key)
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

pub fn derive_auth_key_for_auth_to_string(derive_auth_key_for_auth: &DeriveAuthKeyForAuth) -> String
{
	let out = derive_auth_key_for_auth.prepare_export();

	Base64::encode_string(out)
}

pub fn import_key_from_pem(pem: &str) -> Result<Vec<u8>, SdkUtilError>
{
	let (_type_label, data) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| SdkUtilError::ImportingKeyFromPemFailed)?;

	Ok(data)
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

pub fn client_random_value_from_string(client_random_value: &str, alg: &str) -> Result<ClientRandomValue, SdkUtilError>
{
	//normally not needed only when the client needs to create the rand value, e.g- for key update.
	match alg {
		ARGON_2_OUTPUT => {
			let v = Base64::decode_vec(client_random_value).map_err(|_| SdkUtilError::DecodeRandomValueFailed)?;
			let v = v
				.try_into()
				.map_err(|_| SdkUtilError::DecodeRandomValueFailed)?;

			Ok(ClientRandomValue::Argon2(v))
		},
		_ => Err(SdkUtilError::AlgNotFound),
	}
}

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
