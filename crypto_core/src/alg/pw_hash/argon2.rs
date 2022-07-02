use alloc::borrow::ToOwned;
use alloc::vec::Vec;

use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::alg::sym::aes_gcm::{decrypt_with_generated_key as aes_decrypt, encrypt_with_generated_key as aes_encrypt, AES_GCM_OUTPUT};
use crate::error::Error;
use crate::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveKeyOutput,
	DeriveKeysForAuthOutput,
	DeriveMasterKeyForAuth,
	HashedAuthenticationKey,
	MasterKeyInfo,
	SymKey,
};

const RECOMMENDED_LENGTH: usize = 16;

const SALT_STRING_MAX_LENGTH: usize = 200; //200 chars

const SALT_HASH_INPUT_LENGTH: usize = RECOMMENDED_LENGTH + SALT_STRING_MAX_LENGTH; //216 bytes

const DERIVED_KEY_LENGTH: usize = 64;

const HALF_DERIVED_KEY_LENGTH: usize = DERIVED_KEY_LENGTH / 2;

pub const ARGON_2_OUTPUT: &'static str = "ARGON-2-SHA256";

/**
# Prepare registration

*/
pub(crate) fn derived_keys_from_password(password: &[u8], master_key: &[u8]) -> Result<DeriveKeyOutput, Error>
{
	derive_key_with_pw_internally(password, master_key, &mut OsRng)
}

/**
# Prepare the login

1. Takes the salt from the api (after sending the username)
2. derived the encryption key (for the master key) and the auth key from the password and the salt
3. return the encryption key and
	return the auth key to send it to the server so the server can check the hashed auth key
*/
pub(crate) fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8]) -> Result<DeriveKeysForAuthOutput, Error>
{
	let (master_key_encryption_key, auth_key) = derived_keys(password, salt_bytes)?;

	Ok(DeriveKeysForAuthOutput {
		master_key_encryption_key: DeriveMasterKeyForAuth::Argon2(master_key_encryption_key),
		auth_key: DeriveAuthKeyForAuth::Argon2(auth_key),
	})
}

/**
# Done Login

split login into two parts:
1. is prepare, after sending username to the server and before sending auth key
2. is decrypt the master key
3. export it as Sym Key enum
*/
pub(crate) fn get_master_key(derived_encryption_key: &[u8; HALF_DERIVED_KEY_LENGTH], encrypted_master_key: &[u8]) -> Result<SymKey, Error>
{
	let decrypted_master_key = aes_decrypt(derived_encryption_key, encrypted_master_key)?;

	let decrypted_master_key: [u8; 32] = decrypted_master_key
		.try_into()
		.map_err(|_| Error::KeyDecryptFailed)?;

	Ok(SymKey::Aes(decrypted_master_key))
}

pub(crate) fn password_to_encrypt(password: &[u8]) -> Result<([u8; 32], [u8; 16]), Error>
{
	derived_single_key(password, &mut OsRng)
}

pub(crate) fn password_to_decrypt(password: &[u8], salt: &[u8]) -> Result<[u8; 32], Error>
{
	get_derived_single_key(password, salt)
}

//__________________________________________________________________________________________________
//internally function

fn derive_key_with_pw_internally<R: CryptoRng + RngCore>(password: &[u8], master_key: &[u8], rng: &mut R) -> Result<DeriveKeyOutput, Error>
{
	//used for register and pw change

	let client_random_value = generate_random_value(rng);

	let salt = generate_salt(client_random_value);

	let (derived_encryption_key_bytes, derived_authentication_key_bytes) = derived_keys(password, &salt)?;

	// Get a hash of the Authentication Key which the API will use for authentication at login time
	let mut hasher = Sha256::new();

	hasher.update(derived_authentication_key_bytes);

	let result = hasher.finalize();

	// Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
	let hashed_authentication_key_16bytes: [u8; 16] = match result[..16].as_ref().try_into() {
		Err(_e) => return Err(Error::HashAuthKeyFailed),
		Ok(bytes) => bytes,
	};

	let encrypted_master_key = aes_encrypt(&derived_encryption_key_bytes, master_key)?;

	Ok(DeriveKeyOutput {
		client_random_value: ClientRandomValue::Argon2(client_random_value),
		hashed_authentication_key_bytes: HashedAuthenticationKey::Argon2(hashed_authentication_key_16bytes),
		alg: ARGON_2_OUTPUT,
		master_key_info: MasterKeyInfo {
			encrypted_master_key,
			alg: AES_GCM_OUTPUT,
		},
	})
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
pub(crate) fn generate_salt(client_random_value: [u8; RECOMMENDED_LENGTH]) -> Vec<u8>
{
	let mut salt_string = "sentc".to_owned();

	//pad the salt string to 200 chars with the letter P
	for _i in salt_string.len()..SALT_STRING_MAX_LENGTH {
		salt_string += "P";
	}

	let salt_string = salt_string.as_bytes();

	// Concatenate the Client Random Value bytes to the end of the salt string bytes
	let mut salt_input_bytes_concatenated = Vec::with_capacity(SALT_HASH_INPUT_LENGTH);
	salt_input_bytes_concatenated.extend(salt_string);
	salt_input_bytes_concatenated.extend(client_random_value);

	//create a sha 256
	let mut hasher = Sha256::new();

	hasher.update(salt_input_bytes_concatenated);

	let result = hasher.finalize();

	let mut vec: Vec<u8> = Vec::with_capacity(result[..].len());
	vec.extend(result[..].as_ref());

	vec
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
	let params = Params::new(Params::DEFAULT_M_COST, Params::DEFAULT_T_COST, Params::DEFAULT_P_COST, Some(32)).map_err(|_| Error::PwHashFailed)?;

	let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

	let mut derived_key = [0u8; 32];

	argon2
		.hash_password_into(password, &salt, &mut derived_key)
		.map_err(|_| Error::PwHashFailed)?;

	Ok(derived_key)
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use super::*;
	use crate::alg::sym::aes_gcm::AES_GCM_OUTPUT;
	use crate::{alg, SymKey};

	#[test]
	fn test_derived_keys_from_password()
	{
		let master_key = alg::sym::aes_gcm::generate_key().unwrap();

		let key = match master_key.key {
			SymKey::Aes(k) => k,
		};

		let out = derived_keys_from_password(b"abc", &key).unwrap();

		assert_eq!(out.alg, ARGON_2_OUTPUT);
		assert_eq!(out.master_key_info.alg, AES_GCM_OUTPUT);
	}

	#[test]
	fn test_derive_keys_for_auth()
	{
		//prepare register input
		let master_key = alg::sym::aes_gcm::generate_key().unwrap();

		let key = match master_key.key {
			SymKey::Aes(k) => k,
		};

		let out = derived_keys_from_password(b"abc", &key).unwrap();

		let out_random_value = match out.client_random_value {
			ClientRandomValue::Argon2(r) => r,
		};

		let out_hashed_auth_key = match out.hashed_authentication_key_bytes {
			HashedAuthenticationKey::Argon2(k) => k,
		};

		//create fake salt. this will be created on the server with the client random value
		let salt = generate_salt(out_random_value);

		let derived_out = derive_keys_for_auth(b"abc", &salt).unwrap();

		let master_key_key = match &derived_out.master_key_encryption_key {
			DeriveMasterKeyForAuth::Argon2(k) => k,
		};

		let auth_key = match &derived_out.auth_key {
			DeriveAuthKeyForAuth::Argon2(k) => k,
		};

		//send the auth key to the server and valid it there
		let mut hasher = Sha256::new();
		hasher.update(auth_key);
		let result = hasher.finalize();
		// Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
		let hashed_authentication_key_16bytes: [u8; 16] = result[..16].as_ref().try_into().unwrap();

		assert_eq!(hashed_authentication_key_16bytes, out_hashed_auth_key);

		let decrypted_master_key = get_master_key(master_key_key, &out.master_key_info.encrypted_master_key).unwrap();
		let decrypted_master_key = match decrypted_master_key {
			SymKey::Aes(k) => k,
		};

		assert_eq!(key, decrypted_master_key);
	}

	#[test]
	fn test_password_to_encrypt_and_decrypt()
	{
		let test = "plaintext message";

		//encrypt a value with a password, in prod this might be the key of the content
		let (aes_key_for_encrypt, salt) = password_to_encrypt(b"my fancy password").unwrap();

		let encrypted = alg::sym::aes_gcm::encrypt_with_generated_key(&aes_key_for_encrypt, test.as_ref()).unwrap();

		//decrypt a value with password
		let aes_key_for_decrypt = password_to_decrypt(b"my fancy password", &salt).unwrap();

		let decrypted = alg::sym::aes_gcm::decrypt_with_generated_key(&aes_key_for_decrypt, &encrypted).unwrap();

		let str = from_utf8(&decrypted).unwrap();

		assert_eq!(str, test);
	}
}
