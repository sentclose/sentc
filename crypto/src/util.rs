use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use pem_rfc7468::LineEnding;
use sendclose_crypto_core::{ClientRandomValue, DeriveAuthKeyForAuth, Error, HashedAuthenticationKey, Pk, VerifyK, ECIES_OUTPUT, ED25519_OUTPUT};

pub(crate) fn export_key_to_pem(key: &[u8]) -> Result<String, Error>
{
	//export should not panic because we are creating the keys
	let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::default(), key).map_err(|_| Error::ExportingPublicKeyFailed)?;

	Ok(key)
}

pub(crate) fn import_key_from_pem(pem: &String) -> Result<Vec<u8>, Error>
{
	let (_type_label, data) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| Error::ImportingKeyFromPemFailed)?;

	Ok(data)
}

pub(crate) fn export_public_key_to_pem(key: &Pk) -> Result<String, Error>
{
	match key {
		//match against the public key variants
		Pk::Ecies(k) => export_key_to_pem(k),
	}
}

pub(crate) fn export_verify_key_to_pem(key: &VerifyK) -> Result<String, Error>
{
	match key {
		VerifyK::Ed25519(k) => export_key_to_pem(k),
	}
}

pub(crate) fn client_random_value_to_string(client_random_value: &ClientRandomValue) -> String
{
	match client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(v),
	}
}

pub(crate) fn hashed_authentication_key_to_string(hashed_authentication_key_bytes: &HashedAuthenticationKey) -> String
{
	match hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(h),
	}
}

pub(crate) fn derive_auth_key_for_auth_to_string(derive_auth_key_for_auth: &DeriveAuthKeyForAuth) -> String
{
	match derive_auth_key_for_auth {
		DeriveAuthKeyForAuth::Argon2(h) => Base64::encode_string(h),
	}
}

pub(crate) fn import_public_key_from_pem_with_alg(public_key: &String, alg: &str) -> Result<Pk, Error>
{
	let public_key = import_key_from_pem(public_key)?;

	match alg {
		ECIES_OUTPUT => {
			let public_key = public_key
				.try_into()
				.map_err(|_| Error::DecodePublicKeyFailed)?;
			Ok(Pk::Ecies(public_key))
		},
		_ => Err(Error::AlgNotFound),
	}
}

pub(crate) fn import_verify_key_from_pem_with_alg(verify_key: &String, alg: &str) -> Result<VerifyK, Error>
{
	let verify_key = import_key_from_pem(verify_key)?;

	match alg {
		ED25519_OUTPUT => {
			let verify_key = verify_key
				.try_into()
				.map_err(|_| Error::DecodePublicKeyFailed)?;
			Ok(VerifyK::Ed25519(verify_key))
		},
		_ => Err(Error::AlgNotFound),
	}
}
