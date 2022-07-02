//! # Handle user
//!
//! this functions are used for decoding and encoding the internally values for and from the other implementations
//! we can't work with the enums from the core user mod directly because they must be encoded to base64
//!
//! If rust feature is enabled the rust functions are used. The return is no longer just a json string but rust structs and enums to work with

use base64ct::{Base64, Encoding};
use pem_rfc7468::LineEnding;
use sendclose_crypto_common::user::{ChangePasswordData, DoneLoginInput, KeyDerivedData, MasterKey, RegisterData, ResetPasswordData};
use sendclose_crypto_core::user::{
	change_password as change_password_core,
	done_login as done_login_core,
	password_reset as password_reset_core,
	prepare_login as prepare_login_core,
	register as register_core,
};
use sendclose_crypto_core::{
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveMasterKeyForAuth,
	Error,
	HashedAuthenticationKey,
	Pk,
	SignK,
	Sk,
	VerifyK,
	ECIES_OUTPUT,
	ED25519_OUTPUT,
};

#[cfg(feature = "rust")]
mod user_rust;

#[cfg(not(feature = "rust"))]
pub(crate) mod user;

//export when rust feature is not enabled
#[cfg(not(feature = "rust"))]
pub use self::user::{change_password, done_login, prepare_login, register, reset_password};
//export when rust feature is enabled
#[cfg(feature = "rust")]
pub use self::user_rust::{change_password, done_login, prepare_login, register, reset_password};

pub struct DoneLoginOutput
{
	pub private_key: Sk,
	pub sign_key: SignK,
	pub public_key: Pk,
	pub verify_key: VerifyK,
	pub keypair_encrypt_id: String,
	pub keypair_sign_id: String,
}

fn register_internally(password: String) -> Result<String, Error>
{
	let out = register_core(password.as_str())?;

	//transform the register output into json

	//1. encode the encrypted data to base64
	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//2. export the public keys (decrypt and verify) to a key format
	let public_key = match out.public_key {
		//match against the public key variants
		Pk::Ecies(k) => export_key_to_pem(&k)?,
	};

	let verify_key = match out.verify_key {
		VerifyK::Ed25519(k) => export_key_to_pem(&k)?,
	};

	//3. export the random value
	let client_random_value = match out.client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(&v),
	};

	//4. export the hashed auth key (the first 16 bits)
	let hashed_authentication_key = match out.hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(&h),
	};

	//5. create the structs
	let master_key = MasterKey {
		encrypted_master_key,
		master_key_alg: out.master_key_alg.to_string(),
		encrypted_master_key_alg: out.master_key_info.alg.to_string(),
	};

	let derived = KeyDerivedData {
		public_key,
		verify_key,
		derived_alg: out.derived_alg.to_string(),
		client_random_value,
		encrypted_private_key,
		encrypted_sign_key,
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		keypair_sign_alg: out.keypair_sign_alg.to_string(),
		hashed_authentication_key,
	};

	let register_out = RegisterData {
		master_key,
		derived,
	};

	//use always to string, even for rust feature enable because this data is for the server
	Ok(register_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

/**
# Starts the login process

1. Get the auth key and the master key encryption key from the password.
2. Send the auth key to the server to get the DoneLoginInput back
 */
fn prepare_login_internally(
	password: String,
	salt_string: String,
	derived_encryption_key_alg: String,
) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	let salt = Base64::decode_vec(salt_string.as_str()).map_err(|_| Error::DecodeSaltFailed)?;
	let result = prepare_login_core(password.as_str(), &salt, derived_encryption_key_alg.as_str())?;

	//for the server
	let auth_key = match result.auth_key {
		DeriveAuthKeyForAuth::Argon2(k) => Base64::encode_string(&k),
	};

	Ok((auth_key, result.master_key_encryption_key))
}

/**
# finalize the login process

1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private and sign keys, in pem exported public and verify keys
2. decrypt the master key with the encryption key from @see prepare_login
3. import the public and verify keys to the internal format
 */
fn done_login_internally(master_key_encryption: &DeriveMasterKeyForAuth, server_output: String) -> Result<DoneLoginOutput, Error>
{
	let server_output = DoneLoginInput::from_string(server_output.as_bytes()).map_err(|_| Error::LoginServerOutputWrong)?;

	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_master_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_sign_key = Base64::decode_vec(server_output.encrypted_sign_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;

	let out = done_login_core(
		&master_key_encryption,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.keypair_encrypt_alg.as_str(),
		&encrypted_sign_key,
		server_output.keypair_sign_alg.as_str(),
	)?;

	//now prepare the public and verify key for use

	let public_key = import_key_from_pem(server_output.public_key_string)?;
	let verify_key = import_key_from_pem(server_output.verify_key_string)?;

	let public_key = match server_output.keypair_encrypt_alg.as_str() {
		ECIES_OUTPUT => {
			let public_key = public_key
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;
			Pk::Ecies(public_key)
		},
		_ => return Err(Error::AlgNotFound),
	};

	let verify_key = match server_output.keypair_sign_alg.as_str() {
		ED25519_OUTPUT => {
			let verify_key = verify_key
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;
			VerifyK::Ed25519(verify_key)
		},
		_ => return Err(Error::AlgNotFound),
	};

	Ok(DoneLoginOutput {
		private_key: out.private_key,
		sign_key: out.sign_key,
		public_key,
		verify_key,
		keypair_sign_id: server_output.keypair_sign_id,
		keypair_encrypt_id: server_output.keypair_encrypt_id,
	})
}

fn change_password_internally(
	old_pw: String,
	new_pw: String,
	old_salt: String,
	encrypted_master_key: String,
	derived_encryption_key_alg: String,
) -> Result<String, Error>
{
	let encrypted_master_key = Base64::decode_vec(encrypted_master_key.as_str()).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let old_salt = Base64::decode_vec(old_salt.as_str()).map_err(|_| Error::DecodeSaltFailed)?;

	let output = change_password_core(
		old_pw.as_str(),
		new_pw.as_str(),
		&old_salt,
		&encrypted_master_key,
		derived_encryption_key_alg.as_str(),
	)?;

	//prepare for the server
	let new_encrypted_master_key = Base64::encode_string(&output.master_key_info.encrypted_master_key);

	let new_client_random_value = match output.client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(&v),
	};

	//the 16 bytes of the org. hashed key
	let new_hashed_authentication_key = match output.hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(&h),
	};

	let old_auth_key = match output.old_auth_key {
		DeriveAuthKeyForAuth::Argon2(h) => Base64::encode_string(&h),
	};

	let pw_change_out = ChangePasswordData {
		new_derived_alg: output.derived_alg.to_string(),
		new_encrypted_master_key,
		new_client_random_value,
		new_hashed_authentication_key,
		new_encrypted_master_key_alg: output.master_key_info.alg.to_string(),
		old_auth_key,
	};

	Ok(pw_change_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn reset_password_internally(new_password: String, decrypted_private_key: &Sk, decrypted_sign_key: &SignK) -> Result<String, Error>
{
	let out = password_reset_core(new_password.as_str(), decrypted_private_key, decrypted_sign_key)?;

	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//prepare for the server
	let client_random_value = match out.client_random_value {
		ClientRandomValue::Argon2(v) => Base64::encode_string(&v),
	};

	let hashed_authentication_key = match out.hashed_authentication_key_bytes {
		HashedAuthenticationKey::Argon2(h) => Base64::encode_string(&h),
	};

	let master_key = MasterKey {
		encrypted_master_key,
		master_key_alg: out.master_key_alg.to_string(),
		encrypted_master_key_alg: out.master_key_info.alg.to_string(),
	};

	let data = ResetPasswordData {
		client_random_value,
		hashed_authentication_key,
		master_key,
		derived_alg: out.derived_alg.to_string(),
		encrypted_sign_key,
		encrypted_private_key,
	};

	Ok(data.to_string().map_err(|_| Error::JsonToStringFailed)?)
}

pub(crate) fn export_key_to_pem(key: &[u8]) -> Result<String, Error>
{
	//export should not panic because we are creating the keys
	let key = pem_rfc7468::encode_string("PUBLIC KEY", LineEnding::default(), key).map_err(|_| Error::ExportingPublicKeyFailed)?;

	Ok(key)
}

pub(crate) fn import_key_from_pem(pem: String) -> Result<Vec<u8>, Error>
{
	let (_type_label, data) = pem_rfc7468::decode_vec(pem.as_bytes()).map_err(|_| Error::ImportingKeyFromPemFailed)?;

	Ok(data)
}
