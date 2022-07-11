//! # Handle user
//!
//! this functions are used for decoding and encoding the internally values for and from the other implementations
//! we can't work with the enums from the core user mod directly because they must be encoded to base64
//!
//! If rust feature is enabled the rust functions are used. The return is no longer just a json string but rust structs and enums to work with

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{
	ChangePasswordData,
	DoneLoginServerKeysOutput,
	KeyDerivedData,
	MasterKey,
	MultipleLoginServerOutput,
	PrepareLoginSaltServerOutput,
	RegisterData,
	ResetPasswordData,
};
use sentc_crypto_core::user::{
	change_password as change_password_core,
	done_login as done_login_core,
	password_reset as password_reset_core,
	prepare_login as prepare_login_core,
	register as register_core,
};
use sentc_crypto_core::{generate_salt, DeriveMasterKeyForAuth, Error};

use crate::util::{
	client_random_value_from_string,
	client_random_value_to_string,
	derive_auth_key_for_auth_to_string,
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	hashed_authentication_key_to_string,
	import_public_key_from_pem_with_alg,
	import_verify_key_from_pem_with_alg,
	KeyDataInt,
	PrivateKeyFormatInt,
	PublicKeyFormatInt,
	SignKeyFormatInt,
	VerifyKeyFormatInt,
};

#[cfg(feature = "rust")]
mod user_rust;

#[cfg(not(feature = "rust"))]
mod user;

//export when rust feature is not enabled
#[cfg(not(feature = "rust"))]
pub use self::user::{
	change_password,
	done_login,
	prepare_login,
	prepare_update_user_keys,
	register,
	reset_password,
	MasterKeyFormat,
	PrepareLoginData,
};
//export when rust feature is enabled
#[cfg(feature = "rust")]
pub use self::user_rust::{change_password, done_login, prepare_login, prepare_update_user_keys, register, reset_password};

fn register_internally(password: &str) -> Result<String, Error>
{
	let out = register_core(password)?;

	//transform the register output into json

	//1. encode the encrypted data to base64
	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//2. export the public keys (decrypt and verify) to a key format
	let public_key = export_raw_public_key_to_pem(&out.public_key)?;

	let verify_key = export_raw_verify_key_to_pem(&out.verify_key)?;

	//3. export the random value
	let client_random_value = client_random_value_to_string(&out.client_random_value);

	//4. export the hashed auth key (the first 16 bits)
	let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

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
fn prepare_login_internally(password: &str, server_output: &PrepareLoginSaltServerOutput) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	let salt = Base64::decode_vec(server_output.salt_string.as_str()).map_err(|_| Error::DecodeSaltFailed)?;
	let result = prepare_login_core(password, &salt, server_output.derived_encryption_key_alg.as_str())?;

	//for the server
	let auth_key = derive_auth_key_for_auth_to_string(&result.auth_key);

	Ok((auth_key, result.master_key_encryption_key))
}

/**
# finalize the login process

1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private and sign keys, in pem exported public and verify keys
2. decrypt the master key with the encryption key from @see prepare_login
3. import the public and verify keys to the internal format
 */
fn done_login_internally(master_key_encryption: &DeriveMasterKeyForAuth, server_output: &DoneLoginServerKeysOutput) -> Result<KeyDataInt, Error>
{
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
	let public_key = import_public_key_from_pem_with_alg(server_output.public_key_string.as_str(), server_output.keypair_encrypt_alg.as_str())?;

	let verify_key = import_verify_key_from_pem_with_alg(server_output.verify_key_string.as_str(), server_output.keypair_sign_alg.as_str())?;

	Ok(KeyDataInt {
		private_key: PrivateKeyFormatInt {
			key_id: server_output.keypair_encrypt_id.clone(),
			key: out.private_key,
		},
		sign_key: SignKeyFormatInt {
			key_id: server_output.keypair_sign_id.clone(),
			key: out.sign_key,
		},
		public_key: PublicKeyFormatInt {
			key_id: server_output.keypair_encrypt_id.clone(),
			key: public_key,
		},
		verify_key: VerifyKeyFormatInt {
			key_id: server_output.keypair_sign_id.clone(),
			key: verify_key,
		},
	})
}

fn change_password_internally(
	old_pw: &str,
	new_pw: &str,
	old_salt: &str,
	encrypted_master_key: &str,
	derived_encryption_key_alg: &str,
) -> Result<String, Error>
{
	let encrypted_master_key = Base64::decode_vec(encrypted_master_key).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let old_salt = Base64::decode_vec(old_salt).map_err(|_| Error::DecodeSaltFailed)?;

	let output = change_password_core(old_pw, new_pw, &old_salt, &encrypted_master_key, derived_encryption_key_alg)?;

	//prepare for the server
	let new_encrypted_master_key = Base64::encode_string(&output.master_key_info.encrypted_master_key);

	let new_client_random_value = client_random_value_to_string(&output.client_random_value);

	//the 16 bytes of the org. hashed key
	let new_hashed_authentication_key = hashed_authentication_key_to_string(&output.hashed_authentication_key_bytes);

	let old_auth_key = derive_auth_key_for_auth_to_string(&output.old_auth_key);

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

fn reset_password_internally(
	new_password: &str,
	decrypted_private_key: &PrivateKeyFormatInt,
	decrypted_sign_key: &SignKeyFormatInt,
) -> Result<String, Error>
{
	let out = password_reset_core(new_password, &decrypted_private_key.key, &decrypted_sign_key.key)?;

	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//prepare for the server
	let client_random_value = client_random_value_to_string(&out.client_random_value);
	let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

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

/**
# Prepare update user keys

When changing the user keys so the user can update the old content which was encrypted by the old user keys.

After this step the user got access to all old user keys and
can start decrypting the content with the old keys and encrypt it with the new keys.

This function is used when the user don't new encrypt all content as once but split it around days.
When the user will start new encrypt the next chunks, this function is needed to get the old key too
(because for login we only use the actual keys).

Password change or reset is not possible during the key update.
*/
fn prepare_update_user_keys_internally(password: &str, server_output: &MultipleLoginServerOutput) -> Result<Vec<KeyDataInt>, Error>
{
	let mut encrypted_output = Vec::with_capacity(server_output.logins.len());

	//decrypt all keys via the password, so the sdk can start to decrypt the content with the old keys and encrypt with the new

	let mut i = 0;

	for out in &server_output.logins {
		//get the derived key from the password
		//creat the salt in the client for the old keys. it is ok because the user is already auth
		let client_random_value = client_random_value_from_string(out.client_random_value.as_str(), out.derived_encryption_key_alg.as_str())?;
		let salt = generate_salt(client_random_value);

		let result = prepare_login_core(password, &salt, out.derived_encryption_key_alg.as_str())?;
		let derived_key = result.master_key_encryption_key;

		//now done login
		//should everytime the same len
		let done_login_server_output = match server_output.done_logins.get(i) {
			Some(v) => v,
			None => return Err(Error::KeyDecryptFailed),
		};

		let done_login = done_login_internally(&derived_key, done_login_server_output)?;
		encrypted_output.push(done_login);

		i += 1;
	}

	Ok(encrypted_output)
}

#[cfg(test)]
pub(crate) mod test_fn
{
	use alloc::string::ToString;

	use sentc_crypto_common::user::{KeyDerivedData, RegisterData, UserPublicKeyData, UserVerifyKeyData};

	use super::*;
	use crate::util::{client_random_value_from_string, KeyData};

	pub(crate) fn simulate_server_prepare_login(derived: &KeyDerivedData) -> PrepareLoginSaltServerOutput
	{
		//and now try to login
		//normally the salt gets calc by the api
		let client_random_value = client_random_value_from_string(derived.client_random_value.as_str(), derived.derived_alg.as_str()).unwrap();
		let salt_from_rand_value = generate_salt(client_random_value);
		let salt_string = Base64::encode_string(&salt_from_rand_value);

		PrepareLoginSaltServerOutput {
			salt_string,
			derived_encryption_key_alg: derived.derived_alg.clone(),
			key_id: "1234".to_string(),
		}
	}

	pub(crate) fn simulate_server_done_login(data: RegisterData) -> DoneLoginServerKeysOutput
	{
		let RegisterData {
			derived,
			master_key,
		} = data;

		//get the server output back
		DoneLoginServerKeysOutput {
			encrypted_master_key: master_key.encrypted_master_key,
			encrypted_private_key: derived.encrypted_private_key,
			encrypted_sign_key: derived.encrypted_sign_key,
			public_key_string: derived.public_key,
			verify_key_string: derived.verify_key,
			keypair_encrypt_alg: derived.keypair_encrypt_alg,
			keypair_sign_alg: derived.keypair_sign_alg,
			keypair_encrypt_id: "abc".to_string(),
			keypair_sign_id: "dfg".to_string(),
		}
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn simulate_server_done_login_as_string(data: RegisterData) -> String
	{
		simulate_server_done_login(data).to_string().unwrap()
	}

	#[cfg(feature = "rust")]
	pub(crate) fn create_user() -> (KeyData, UserPublicKeyData, UserVerifyKeyData)
	{
		let password = "12345";

		let out_string = register(password).unwrap();

		let out = RegisterData::from_string(out_string.as_str()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		#[cfg(feature = "rust")]
		let (_, master_key_encryption_key) = prepare_login(password, &server_output).unwrap();

		let user_public_key_data = UserPublicKeyData {
			public_key_pem: out.derived.public_key.to_string(),
			public_key_alg: out.derived.keypair_encrypt_alg.to_string(),
			public_key_id: "abc".to_string(),
		};

		let user_verify_key_data = UserVerifyKeyData {
			verify_key_pem: out.derived.verify_key.to_string(),
			verify_key_alg: out.derived.keypair_sign_alg.to_string(),
			verify_key_id: "dfg".to_string(),
		};

		let server_output = simulate_server_done_login(out);

		#[cfg(feature = "rust")]
		let done_login = done_login(&master_key_encryption_key, &server_output).unwrap();

		#[cfg(feature = "rust")]
		(done_login, user_public_key_data, user_verify_key_data)
	}

	#[cfg(not(feature = "rust"))]
	pub(crate) fn create_user() -> (KeyData, UserPublicKeyData, UserVerifyKeyData)
	{
		let password = "12345";

		let out_string = register(password).unwrap();

		let out = RegisterData::from_string(out_string.as_str()).unwrap();
		let server_output = simulate_server_prepare_login(&out.derived);
		let server_output_string = server_output.to_string().unwrap();
		#[cfg(not(feature = "rust"))]
		let prepare_login_string = prepare_login(password, server_output_string.as_str()).unwrap();

		let PrepareLoginData {
			master_key_encryption_key,
			..
		} = PrepareLoginData::from_string(prepare_login_string.as_str()).unwrap();

		let user_public_key_data = UserPublicKeyData {
			public_key_pem: out.derived.public_key.to_string(),
			public_key_alg: out.derived.keypair_encrypt_alg.to_string(),
			public_key_id: "abc".to_string(),
		};

		let user_verify_key_data = UserVerifyKeyData {
			verify_key_pem: out.derived.verify_key.to_string(),
			verify_key_alg: out.derived.keypair_sign_alg.to_string(),
			verify_key_id: "dfg".to_string(),
		};

		let server_output = simulate_server_done_login(out);

		#[cfg(not(feature = "rust"))]
		let done_login_string = done_login(
			master_key_encryption_key.to_string().unwrap().as_str(),
			server_output.to_string().unwrap().as_str(),
		)
		.unwrap();

		let done_login = KeyData::from_string(done_login_string.as_str()).unwrap();

		#[cfg(not(feature = "rust"))]
		(done_login, user_public_key_data, user_verify_key_data)
	}
}
