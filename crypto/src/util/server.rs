use alloc::string::String;

use base64ct::{Base64, Encoding};
use sentc_crypto_core::cryptomat::{
	ClientRandomValueComposer,
	DeriveAuthKeyForAuth,
	DeriveAuthKeyForAuthComposer,
	HashedAuthenticationKeyComposer,
	Pk,
};
use sentc_crypto_utils::cryptomat::StaticKeyComposerWrapper;

use crate::util::public::generate_salt_from_base64;
use crate::SdkError;

/**
# Generates a salt

from a base64 encoded client random value

returns the salt as base64 encoded
 */
pub fn generate_salt_from_base64_to_string<C: ClientRandomValueComposer>(
	client_random_value: &str,
	alg: &str,
	add_str: &str,
) -> Result<String, SdkError>
{
	let salt = generate_salt_from_base64::<C>(client_random_value, alg, add_str)?;

	Ok(Base64::encode_string(&salt))
}

/**
# Get the client and server hashed auth keys in the internal format

1. hash the client auth key (which comes from the client to the server)
2. import both hashed auth keys into the internal format and return them to compare them

This is used on the server in done login
 */
pub fn get_auth_keys_from_base64<DAK: DeriveAuthKeyForAuthComposer, HAK: HashedAuthenticationKeyComposer>(
	client_auth_key: &str,
	server_hashed_auth_key: &str,
	alg: &str,
) -> Result<
	(
		HAK::Value,
		<<DAK as DeriveAuthKeyForAuthComposer>::Value as DeriveAuthKeyForAuth>::HAK,
	),
	SdkError,
>
{
	let v_c = Base64::decode_vec(client_auth_key).map_err(|_| SdkError::DecodeHashedAuthKey)?;
	let v_s = Base64::decode_vec(server_hashed_auth_key).map_err(|_| SdkError::DecodeHashedAuthKey)?;

	let client_auth_key = DAK::from_bytes(v_c, alg)?;
	let server_hashed_auth_key = HAK::from_bytes(v_s, alg)?;

	//hash the client key
	let hashed_client_key = client_auth_key.hash_auth_key()?;

	Ok((server_hashed_auth_key, hashed_client_key))
}

pub fn encrypt_ephemeral_group_key_with_public_key<P: StaticKeyComposerWrapper>(
	public_key_in_pem: &str,
	public_key_alg: &str,
	eph_key: &str,
) -> Result<String, SdkError>
{
	let public_key = P::pk_inner_from_pem(public_key_in_pem, public_key_alg)?;

	let eph_key = Base64::decode_vec(eph_key).map_err(|_| SdkError::DecodeSymKeyFailed)?;

	let encrypted_eph_key = public_key.encrypt(&eph_key)?;

	Ok(Base64::encode_string(&encrypted_eph_key))
}

pub fn encrypt_login_verify_challenge<P: StaticKeyComposerWrapper>(
	public_key_in_pem: &str,
	public_key_alg: &str,
	challenge: &str,
) -> Result<String, SdkError>
{
	let public_key = P::pk_inner_from_pem(public_key_in_pem, public_key_alg)?;

	let encrypted_eph_key = public_key.encrypt(challenge.as_bytes())?;

	Ok(Base64::encode_string(&encrypted_eph_key))
}
