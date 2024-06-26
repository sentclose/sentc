use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_core::cryptomat::{ClientRandomValueComposer, DeriveAuthKeyForAuth, DeriveAuthKeyForAuthComposer, Pk};
use sentc_crypto_utils::cryptomat::StaticKeyComposerWrapper;

use crate::util::public::generate_salt_from_base64;
use crate::SdkError;

#[macro_export]
macro_rules! traverse_keys {
	// Base case: No more types to try, return an error
	($method:ident, ($($arg:expr),*), []) => {
		Err($crate::SdkError::AlgNotFound)
	};
	 // Recursive case: Try the first type, if it fails with AlgNotFound, try the next types
	($method:ident, ($($arg:expr),*), [$first:ty $(, $rest:ty)*]) => {
		match $method::<$first>($($arg),*) {
            Ok(val) => Ok(val),
            Err(err) => match err {
               $crate::SdkError::Util($crate::sdk_utils::error::SdkUtilError::Base($crate::sdk_core::Error::AlgNotFound)) |
			   $crate::SdkError::Util($crate::sdk_utils::error::SdkUtilError::AlgNotFound) |
			   $crate::SdkError::AlgNotFound => traverse_keys!($method, ($($arg),*), [$($rest),*]),
                _ => Err(err),
            }
        }
	};
}

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

pub fn get_auth_keys_from_base64<DAK: DeriveAuthKeyForAuthComposer>(client_auth_key: &str, alg: &str) -> Result<Vec<u8>, SdkError>
{
	let v_c = Base64::decode_vec(client_auth_key).map_err(|_| SdkError::DecodeHashedAuthKey)?;

	let client_auth_key = DAK::from_bytes(v_c, alg)?;

	//hash the client key

	Ok(client_auth_key.hash_auth_key()?)
}

/**
Use it for the server hashed auth key (from register) and when the client auth key was hashed extern and sent to the server
*/
pub fn get_hashed_auth_key_from_string(hashed_auth_key: &str) -> Result<Vec<u8>, SdkError>
{
	Base64::decode_vec(hashed_auth_key).map_err(|_| SdkError::DecodeHashedAuthKey)
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
