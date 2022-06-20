use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{CryptoRng, OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::alg::sym::aes_gcm::encrypt_with_generated_key as aes_encrypt;
use crate::error::Error;
use crate::{DeriveKeyOutput, MasterKeyInfo};

const RECOMMENDED_LENGTH: usize = 16;

const SALT_STRING_MAX_LENGTH: usize = 200; //200 chars

const SALT_HASH_INPUT_LENGTH: usize = RECOMMENDED_LENGTH + SALT_STRING_MAX_LENGTH; //216 bytes

pub(crate) fn derived_keys_from_password(password: &[u8], master_key: &[u8]) -> Result<DeriveKeyOutput, Error>
{
	derive_key_with_pw_internally(password, master_key, &mut OsRng)
}

// pub(crate) fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), Error>
// {
// 	derived_keys(password, salt_bytes)
// }

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
		client_random_value,
		hashed_authentication_key_16bytes,
		alg: "ARGON-2-SHA256".to_string(),
		master_key_info: MasterKeyInfo {
			encrypted_master_key,
			alg: "AES-GCM-256".to_string(),
		},
	})
}

fn derived_keys(password: &[u8], salt_bytes: &[u8]) -> Result<([u8; 32], [u8; 32]), Error>
{
	let params = Params::new(Params::DEFAULT_M_COST, Params::DEFAULT_T_COST, Params::DEFAULT_P_COST, Some(64)).map_err(|_| Error::PwHashFailed)?;

	let argon2 = Argon2::new(Algorithm::default(), Version::default(), params);

	//should be 512 bits long
	let mut derived_key = [0u8; 64];

	argon2
		.hash_password_into(password, salt_bytes, &mut derived_key)
		.map_err(|_| Error::PwHashFailed)?;

	//left is the encryption key for the master key
	let left: [u8; 32] = match derived_key[..32].as_ref().try_into() {
		Err(_e) => return Err(Error::PwSplitFailedLeft),
		Ok(bytes) => bytes,
	};

	//right is the authentication key
	let right: [u8; 32] = match derived_key[32..].as_ref().try_into() {
		Err(_e) => return Err(Error::PwSplitFailedRight),
		Ok(bytes) => bytes,
	};

	Ok((left, right))
}

fn generate_salt(client_random_value: [u8; RECOMMENDED_LENGTH]) -> Vec<u8>
{
	let mut salt_string = "sendclose".to_string();

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
