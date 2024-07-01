use argon2::{Algorithm, Argon2, Params, Version};
use openssl::rand::rand_bytes;
use openssl::sha;
use sentc_crypto_core::cryptomat::{PwHash, PwPrepareExport, SymKey};
use sentc_crypto_core::{crypto_alg_str_impl, cryptomat, Error};
use sentc_crypto_fips_keys::core::sym::{raw_decrypt, raw_encrypt, Aes256GcmKey, FIPS_OPENSSL_AES_GCM};

macro_rules! prepare_export {
	($st:ty) => {
		impl PwPrepareExport for $st
		{
			fn prepare_export(&self) -> &[u8]
			{
				&self.0
			}
		}
	};
}

macro_rules! pw_hash_composer_impl {
	($st:ty,$tr:ident) => {
		impl cryptomat::$tr for $st
		{
			type Value = Self;

			fn from_bytes(vec: Vec<u8>, alg: &str) -> Result<Self::Value, Error>
			{
				match alg {
					REC_PW_HASH_ALG => {
						let v = vec.try_into().map_err(|_| Error::KeyDecryptFailed)?;

						Ok(Self(v))
					},
					_ => Err(Error::AlgNotFound),
				}
			}
		}
	};
}

pub const REC_PW_HASH_ALG: &str = "Rec_argon2_hmac";

const RECOMMENDED_LENGTH: usize = 16;

const SALT_STRING_MAX_LENGTH: usize = 200; //200 chars

const SALT_HASH_INPUT_LENGTH: usize = RECOMMENDED_LENGTH + SALT_STRING_MAX_LENGTH; //216 bytes

const DERIVED_KEY_LENGTH: usize = 64;

pub(super) const HALF_DERIVED_KEY_LENGTH: usize = DERIVED_KEY_LENGTH / 2;

pub struct ClientRandomValue([u8; RECOMMENDED_LENGTH]);

crypto_alg_str_impl!(ClientRandomValue, REC_PW_HASH_ALG);
prepare_export!(ClientRandomValue);
pw_hash_composer_impl!(ClientRandomValue, ClientRandomValueComposer);

impl cryptomat::ClientRandomValue for ClientRandomValue
{
	fn generate_salt(self, add_str: &str) -> Vec<u8>
	{
		generate_salt(self.0, add_str)
	}
}

pub struct HashedAuthenticationKey([u8; 16]);
prepare_export!(HashedAuthenticationKey);

impl cryptomat::HashedAuthenticationKey for HashedAuthenticationKey {}

pub struct DeriveMasterKeyForAuth([u8; 32]);
prepare_export!(DeriveMasterKeyForAuth);

impl cryptomat::DeriveMasterKeyForAuth for DeriveMasterKeyForAuth
{
	fn get_master_key(&self, encrypted_master_key: &[u8]) -> Result<impl SymKey, Error>
	{
		get_master_key(&self.0, encrypted_master_key)
	}
}

pub struct DeriveAuthKeyForAuth([u8; 32]);
prepare_export!(DeriveAuthKeyForAuth);
pw_hash_composer_impl!(DeriveAuthKeyForAuth, DeriveAuthKeyForAuthComposer);

impl cryptomat::DeriveAuthKeyForAuth for DeriveAuthKeyForAuth
{
	fn hash_auth_key(&self) -> Result<Vec<u8>, Error>
	{
		let hashed_authentication_key_16bytes = hash_auth_key(&self.0)?;

		Ok(hashed_authentication_key_16bytes.to_vec())
	}
}

pub struct PasswordEncryptSalt([u8; 16]);
prepare_export!(PasswordEncryptSalt);

impl cryptomat::PasswordEncryptSalt for PasswordEncryptSalt {}

pub struct PwHasher;

impl PwHash for PwHasher
{
	type CRV = ClientRandomValue;
	type HAK = HashedAuthenticationKey;
	type DMK = DeriveMasterKeyForAuth;
	type DAK = DeriveAuthKeyForAuth;
	type PWS = PasswordEncryptSalt;

	fn derived_keys_from_password<M: SymKey>(
		password: &[u8],
		master_key: &M,
		alg: Option<&str>,
	) -> Result<(Self::CRV, Self::HAK, Vec<u8>, &'static str), Error>
	{
		if let Some(alg) = alg {
			if alg != REC_PW_HASH_ALG {
				return Err(Error::AlgNotFound);
			}
		}

		derived_keys_from_password(password, master_key)
	}

	fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8], alg: &str) -> Result<(Self::DMK, Self::DAK), Error>
	{
		if alg != REC_PW_HASH_ALG {
			return Err(Error::AlgNotFound);
		}

		derive_keys_for_auth(password, salt_bytes)
	}

	fn password_to_encrypt(password: &[u8]) -> Result<(Self::PWS, impl SymKey), Error>
	{
		let (aes_key_for_encrypt, salt) = derived_single_key(password)?;

		Ok((
			PasswordEncryptSalt(salt),
			Aes256GcmKey::from_raw_key(aes_key_for_encrypt),
		))
	}

	fn password_to_decrypt(password: &[u8], salt: &[u8]) -> Result<impl SymKey, Error>
	{
		let key = get_derived_single_key(password, salt)?;

		Ok(Aes256GcmKey::from_raw_key(key))
	}
}

//__________________________________________________________________________________________________

fn get_master_key(derived_encryption_key: &[u8; HALF_DERIVED_KEY_LENGTH], encrypted_master_key: &[u8]) -> Result<impl SymKey, Error>
{
	let decrypted_master_key = raw_decrypt(derived_encryption_key, encrypted_master_key)?;

	Aes256GcmKey::try_from(&decrypted_master_key[..])
}

fn hash_auth_key(derived_authentication_key_bytes: &[u8]) -> Result<[u8; 16], Error>
{
	// Get a hash of the Authentication Key which the API will use for authentication at login time
	let mut hasher = sha::Sha256::new();
	hasher.update(derived_authentication_key_bytes);

	let result = hasher.finish();

	// Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
	let hashed_authentication_key_16bytes: [u8; 16] = result[..16]
		.as_ref()
		.try_into()
		.map_err(|_| Error::HashAuthKeyFailed)?;

	Ok(hashed_authentication_key_16bytes)
}

fn generate_salt(client_random_value: [u8; RECOMMENDED_LENGTH], add_str: &str) -> Vec<u8>
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
	let mut hasher = sha::Sha256::new();

	hasher.update(&salt_input_bytes_concatenated);

	let result = hasher.finish();

	result.to_vec()
}

fn derived_keys_from_password<M: SymKey>(
	password: &[u8],
	master_key: &M,
) -> Result<(ClientRandomValue, HashedAuthenticationKey, Vec<u8>, &'static str), Error>
{
	let mut client_random_value = [0u8; RECOMMENDED_LENGTH];
	rand_bytes(&mut client_random_value).map_err(|_| Error::PwHashFailed)?;

	let salt = generate_salt(client_random_value, "");

	let (derived_encryption_key_bytes, derived_authentication_key_bytes) = derived_keys(password, &salt)?;

	let hashed_authentication_key_16bytes = hash_auth_key(&derived_authentication_key_bytes)?;

	let encrypted_master_key = raw_encrypt(&derived_encryption_key_bytes, master_key.as_ref())?;

	Ok((
		ClientRandomValue(client_random_value),
		HashedAuthenticationKey(hashed_authentication_key_16bytes),
		encrypted_master_key,
		FIPS_OPENSSL_AES_GCM,
	))
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
	let left: [u8; HALF_DERIVED_KEY_LENGTH] = derived_key[..HALF_DERIVED_KEY_LENGTH]
		.as_ref()
		.try_into()
		.map_err(|_| Error::PwSplitFailedLeft)?;

	//right is the authentication key
	let right: [u8; HALF_DERIVED_KEY_LENGTH] = derived_key[HALF_DERIVED_KEY_LENGTH..]
		.as_ref()
		.try_into()
		.map_err(|_| Error::PwSplitFailedRight)?;

	Ok((left, right))
}

fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8]) -> Result<(DeriveMasterKeyForAuth, DeriveAuthKeyForAuth), Error>
{
	let (master_key_encryption_key, auth_key) = derived_keys(password, salt_bytes)?;

	Ok((
		DeriveMasterKeyForAuth(master_key_encryption_key),
		DeriveAuthKeyForAuth(auth_key),
	))
}

fn derived_single_key(password: &[u8]) -> Result<([u8; 32], [u8; RECOMMENDED_LENGTH]), Error>
{
	let mut salt = [0u8; RECOMMENDED_LENGTH];
	rand_bytes(&mut salt).map_err(|_| Error::PwHashFailed)?;

	let derived_key = get_derived_single_key(password, &salt)?;

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

	#[test]
	fn test_derived_keys_from_password()
	{
		let key = Aes256GcmKey::generate().unwrap();

		let (client_random_value, _hashed_authentication_key_bytes, _encrypted_master_key, encrypted_master_key_alg) =
			derived_keys_from_password(b"abc", &key).unwrap();

		assert_eq!(client_random_value.get_alg_str(), REC_PW_HASH_ALG);
		assert_eq!(encrypted_master_key_alg, FIPS_OPENSSL_AES_GCM);
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

		//send the auth key to the server and valid it there
		let mut hasher = sha::Sha256::new();
		hasher.update(&auth_key.0);
		let result = hasher.finish();
		// Keep only the first 128 bits (16 bytes) of the Hashed Authentication Key
		let hashed_authentication_key_16bytes: [u8; 16] = result[..16].as_ref().try_into().unwrap();

		let hashed_authentication_key_bytes = hashed_authentication_key_bytes.0;

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
		let (salt, aes_key_for_encrypt) = PwHasher::password_to_encrypt(b"my fancy password").unwrap();

		let salt = salt.0;

		let encrypted = aes_key_for_encrypt.encrypt(test.as_ref()).unwrap();

		//decrypt a value with password
		let aes_key_for_decrypt = PwHasher::password_to_decrypt(b"my fancy password", &salt).unwrap();

		let decrypted = aes_key_for_decrypt.decrypt(&encrypted).unwrap();

		let str = from_utf8(&decrypted).unwrap();

		assert_eq!(str, test);
	}
}
