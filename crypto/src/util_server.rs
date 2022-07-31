use alloc::string::String;

use base64ct::{Base64, Encoding};
use sentc_crypto_core::{crypto as crypto_core, hash_auth_key, HashedAuthenticationKey};

use crate::util::{derive_auth_key_from_base64, hashed_authentication_key_from_base64, import_public_key_from_pem_with_alg};
use crate::util_pub::generate_salt_from_base64;
use crate::SdkError;

/**
# Generates a salt

from a base64 encoded client random value

returns the salt as base64 encoded
 */
pub fn generate_salt_from_base64_to_string(client_random_value: &str, alg: &str, add_str: &str) -> Result<String, SdkError>
{
	let salt = generate_salt_from_base64(client_random_value, alg, add_str)?;

	Ok(Base64::encode_string(&salt))
}

/**
# Get the client and server hashed auth keys in the internal format

1. hash the client auth key (which comes from the client to the server)
2. import both hashed auth keys into the internal format and return them to compare them

This is used on the server in done login
 */
pub fn get_auth_keys_from_base64(
	client_auth_key: &str,
	server_hashed_auth_key: &str,
	alg: &str,
) -> Result<(HashedAuthenticationKey, HashedAuthenticationKey), SdkError>
{
	let client_auth_key = derive_auth_key_from_base64(client_auth_key, alg)?;
	let server_hashed_auth_key = hashed_authentication_key_from_base64(server_hashed_auth_key, alg)?;

	//hash the client key
	let hashed_client_key = hash_auth_key(&client_auth_key)?;

	Ok((server_hashed_auth_key, hashed_client_key))
}

pub fn encrypt_ephemeral_group_key_with_public_key(public_key_in_pem: &str, public_key_alg: &str, eph_key: &str) -> Result<String, SdkError>
{
	let public_key = import_public_key_from_pem_with_alg(public_key_in_pem, public_key_alg)?;

	let eph_key = Base64::decode_vec(eph_key).map_err(|_| SdkError::DecodeSymKeyFailed)?;

	let encrypted_eph_key = crypto_core::encrypt_asymmetric(&public_key, &eph_key)?;

	Ok(Base64::encode_string(&encrypted_eph_key))
}
