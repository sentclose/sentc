use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{CryptoRng, RngCore};
use sentc_crypto_core::cryptomat::SymKey;
use sentc_crypto_core::Error;
use sha2::{Digest, Sha256};

use crate::core::pw_hash::{ClientRandomValue, DeriveAuthKeyForAuth, DeriveMasterKeyForAuth, HashedAuthenticationKey, PasswordEncryptSalt};
use crate::core::sym::aes_gcm::{raw_decrypt as aes_decrypt, raw_encrypt as aes_encrypt, Aes256GcmKey, AES_GCM_OUTPUT};
use crate::get_rand;

const RECOMMENDED_LENGTH: usize = 16;

const SALT_STRING_MAX_LENGTH: usize = 200; //200 chars

const SALT_HASH_INPUT_LENGTH: usize = RECOMMENDED_LENGTH + SALT_STRING_MAX_LENGTH; //216 bytes

const DERIVED_KEY_LENGTH: usize = 64;

pub(super) const HALF_DERIVED_KEY_LENGTH: usize = DERIVED_KEY_LENGTH / 2;

pub const ARGON_2_OUTPUT: &str = "ARGON-2-SHA256";

/**
# Prepare registration

 */
pub(crate) fn derived_keys_from_password<M: SymKey>(
	password: &[u8],
	master_key: &M,
) -> Result<(ClientRandomValue, HashedAuthenticationKey, Vec<u8>, &'static str), Error>
{
	let (client_random_value, hashed_authentication_key_16bytes, encrypted_master_key, alg) =
		derive_key_with_pw_internally(password, master_key.as_ref(), &mut get_rand())?;

	Ok((
		ClientRandomValue::Argon2(client_random_value),
		HashedAuthenticationKey::Argon2(hashed_authentication_key_16bytes),
		encrypted_master_key,
		alg,
	))
}

/**
# Prepare the login

1. Takes the salt from the api (after sending the username)
2. derived the encryption key (for the master key) and the auth key from the password and the salt
3. return the encryption key and
	return the auth key to send it to the server so the server can check the hashed auth key
 */
pub(crate) fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8]) -> Result<(DeriveMasterKeyForAuth, DeriveAuthKeyForAuth), Error>
{
	let (master_key_encryption_key, auth_key) = derived_keys(password, salt_bytes)?;

	Ok((
		DeriveMasterKeyForAuth::Argon2(master_key_encryption_key),
		DeriveAuthKeyForAuth::Argon2(auth_key),
	))
}

pub(crate) fn password_to_encrypt(password: &[u8]) -> Result<(PasswordEncryptSalt, impl SymKey), Error>
{
	let (aes_key_for_encrypt, salt) = derived_single_key(password, &mut get_rand())?;

	Ok((
		PasswordEncryptSalt::Argon2(salt),
		Aes256GcmKey::from_raw_key(aes_key_for_encrypt),
	))
}

pub(crate) fn password_to_decrypt(password: &[u8], salt: &[u8]) -> Result<impl SymKey, Error>
{
	let key = get_derived_single_key(password, salt)?;

	Ok(Aes256GcmKey::from_raw_key(key))
}

/**
# Hash the auth key

and keep only the first 16 bytes. This is used for registration and done login on the server.
*/
pub(super) fn get_hashed_auth_key(derived_authentication_key_bytes: &[u8]) -> Result<Vec<u8>, Error>
{
	let hashed_authentication_key_16bytes = hash_auth_key(derived_authentication_key_bytes)?;

	Ok(hashed_authentication_key_16bytes.to_vec())
}

/**
# Done Login

split login into two parts:
1. is prepared, after sending username to the server and before sending auth key
2. is decrypt the master key
3. export it as Sym Key enum
 */
pub(crate) fn get_master_key(derived_encryption_key: &[u8; HALF_DERIVED_KEY_LENGTH], encrypted_master_key: &[u8]) -> Result<impl SymKey, Error>
{
	let decrypted_master_key = aes_decrypt(derived_encryption_key, encrypted_master_key)?;

	Aes256GcmKey::try_from(&decrypted_master_key[..])
}

//__________________________________________________________________________________________________
//internally function

#[allow(clippy::type_complexity)]
fn derive_key_with_pw_internally<R: CryptoRng + RngCore>(
	password: &[u8],
	master_key: &[u8],
	rng: &mut R,
) -> Result<([u8; 16], [u8; 16], Vec<u8>, &'static str), Error>
{
	//used for register and pw change

	let client_random_value = generate_random_value(rng);

	let salt = generate_salt(client_random_value, "");

	let (derived_encryption_key_bytes, derived_authentication_key_bytes) = derived_keys(password, &salt)?;

	let hashed_authentication_key_16bytes = hash_auth_key(&derived_authentication_key_bytes)?;

	let encrypted_master_key = aes_encrypt(&derived_encryption_key_bytes, master_key)?;

	Ok((
		client_random_value,
		hashed_authentication_key_16bytes,
		encrypted_master_key,
		AES_GCM_OUTPUT,
	))
}

fn hash_auth_key(derived_authentication_key_bytes: &[u8]) -> Result<[u8; 16], Error>
{
	// Get a hash of the Authentication Key which the API will use for authentication at login time
	let mut hasher = Sha256::new();
	hasher.update(derived_authentication_key_bytes);

	let result = hasher.finalize();

	// Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
	let hashed_authentication_key_16bytes: [u8; 16] = match result[..16].as_ref().try_into() {
		Err(_e) => return Err(Error::HashAuthKeyFailed),
		Ok(bytes) => bytes,
	};

	Ok(hashed_authentication_key_16bytes)
}

fn derived_keys(password: &[u8], salt_bytes: &[u8]) -> Result<([u8; HALF_DERIVED_KEY_LENGTH], [u8; HALF_DERIVED_KEY_LENGTH]), Error>
{
	let params = Params::new(
		Params::DEFAULT_M_COST,
		Params::DEFAULT_T_COST,
		Params::DEFAULT_P_COST,
		Some(DERIVED_KEY_LENGTH),
	)
	.map_err(|_| Error::PwHashFailed)?;

	let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

	//should be 512 bits long
	let mut derived_key = [0u8; DERIVED_KEY_LENGTH];

	argon2
		.hash_password_into(password, salt_bytes, &mut derived_key)
		.map_err(|_| Error::PwHashFailed)?;

	//left is the encryption key for the master key
	let left: [u8; HALF_DERIVED_KEY_LENGTH] = match derived_key[..HALF_DERIVED_KEY_LENGTH].as_ref().try_into() {
		Err(_e) => return Err(Error::PwSplitFailedLeft),
		Ok(bytes) => bytes,
	};

	//right is the authentication key
	let right: [u8; HALF_DERIVED_KEY_LENGTH] = match derived_key[HALF_DERIVED_KEY_LENGTH..].as_ref().try_into() {
		Err(_e) => return Err(Error::PwSplitFailedRight),
		Ok(bytes) => bytes,
	};

	Ok((left, right))
}

//this is pub crate because we need this function in later tests
pub(super) fn generate_salt(client_random_value: [u8; RECOMMENDED_LENGTH], add_str: &str) -> Vec<u8>
{
	//on server side, put the user identifier as add str to get unique checking time
	let mut salt_string = "sentc".to_owned() + add_str;

	//pad the salt string to 200 chars with the letter P
	for _i in salt_string.len()..SALT_STRING_MAX_LENGTH {
		salt_string += "P";
	}

	let salt_string = salt_string.as_bytes();

	// Concatenate the Client Random Value bytes to the end of the salt string bytes
	let mut salt_input_bytes_concatenated = Vec::with_capacity(SALT_HASH_INPUT_LENGTH);
	salt_input_bytes_concatenated.extend_from_slice(salt_string);
	salt_input_bytes_concatenated.extend_from_slice(&client_random_value);

	//create a sha 256
	let mut hasher = Sha256::new();

	hasher.update(salt_input_bytes_concatenated);

	let result = hasher.finalize();

	result.to_vec()
}

fn generate_random_value<R: CryptoRng + RngCore>(rng: &mut R) -> [u8; RECOMMENDED_LENGTH]
{
	let mut bytes = [0u8; RECOMMENDED_LENGTH];
	rng.fill_bytes(&mut bytes);

	bytes
}

fn derived_single_key<R: CryptoRng + RngCore>(password: &[u8], rng: &mut R) -> Result<([u8; 32], [u8; RECOMMENDED_LENGTH]), Error>
{
	//just generate a normal salt not for auth like register
	let salt = generate_random_value(rng);

	let derived_key = get_derived_single_key(password, &salt)?;

	//return the key for encrypt / decrypt derived from pw, and the random value for the decrypt
	//for decrypt use the @get_derived_single_key function again but with this salt and this pw
	Ok((derived_key, salt))
}

fn get_derived_single_key(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Error>
{
	//aes 256 key
	let params = Params::new(
		Params::DEFAULT_M_COST,
		Params::DEFAULT_T_COST,
		Params::DEFAULT_P_COST,
		Some(32),
	)
	.map_err(|_| Error::PwHashFailed)?;

	let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

	let mut derived_key = [0u8; 32];

	argon2
		.hash_password_into(password, salt, &mut derived_key)
		.map_err(|_| Error::PwHashFailed)?;

	Ok(derived_key)
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use sentc_crypto_core::cryptomat::{ClientRandomValue, CryptoAlg, DeriveMasterKeyForAuth, SymKeyGen};

	use super::*;
	use crate::core::sym::aes_gcm::AES_GCM_OUTPUT;

	#[test]
	fn test_derived_keys_from_password()
	{
		let key = Aes256GcmKey::generate().unwrap();

		let (client_random_value, _hashed_authentication_key_bytes, _encrypted_master_key, encrypted_master_key_alg) =
			derived_keys_from_password(b"abc", &key).unwrap();

		assert_eq!(client_random_value.get_alg_str(), ARGON_2_OUTPUT);
		assert_eq!(encrypted_master_key_alg, AES_GCM_OUTPUT);
	}

	#[test]
	fn test_derive_keys_for_auth()
	{
		//prepare register input
		let key = Aes256GcmKey::generate().unwrap();

		let (client_random_value, hashed_authentication_key_bytes, encrypted_master_key, _encrypted_master_key_alg) =
			derived_keys_from_password(b"abc", &key).unwrap();

		//create fake salt. this will be created on the server with the client random value
		let salt = client_random_value.generate_salt("");

		let (master_key_encryption_key, auth_key) = derive_keys_for_auth(b"abc", &salt).unwrap();

		let auth_key = match &auth_key {
			DeriveAuthKeyForAuth::Argon2(k) => k,
		};

		//send the auth key to the server and valid it there
		let mut hasher = Sha256::new();
		hasher.update(auth_key);
		let result = hasher.finalize();
		// Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
		let hashed_authentication_key_16bytes: [u8; 16] = result[..16].as_ref().try_into().unwrap();

		let hashed_authentication_key_bytes = match hashed_authentication_key_bytes {
			HashedAuthenticationKey::Argon2(k) => k,
		};

		assert_eq!(hashed_authentication_key_16bytes, hashed_authentication_key_bytes);

		master_key_encryption_key
			.get_master_key(&encrypted_master_key)
			.unwrap();
	}

	#[test]
	fn test_password_to_encrypt_and_decrypt()
	{
		let test = "plaintext message";

		//encrypt a value with a password, in prod this might be the key of the content
		let (salt, aes_key_for_encrypt) = password_to_encrypt(b"my fancy password").unwrap();

		let salt = match salt {
			PasswordEncryptSalt::Argon2(s) => s,
		};

		let encrypted = aes_key_for_encrypt.encrypt(test.as_ref()).unwrap();

		//decrypt a value with password
		let aes_key_for_decrypt = password_to_decrypt(b"my fancy password", &salt).unwrap();

		let decrypted = aes_key_for_decrypt.decrypt(&encrypted).unwrap();

		let str = from_utf8(&decrypted).unwrap();

		assert_eq!(str, test);
	}
}
