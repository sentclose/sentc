#[cfg(not(feature = "rust"))]
#[allow(clippy::module_inception)]
mod user;
#[cfg(feature = "rust")]
mod user_rust;

use alloc::string::{String, ToString};

use base64ct::{Base64, Base64UrlUnpadded, Encoding};
use sentc_crypto_common::group::GroupNewMemberLightInput;
use sentc_crypto_common::user::{
	ChangePasswordData,
	DoneLoginLightOutput,
	DoneLoginServerInput,
	JwtRefreshInput,
	KeyDerivedData,
	MasterKey,
	PrepareLoginSaltServerOutput,
	PrepareLoginServerInput,
	RegisterServerOutput,
	UserDeviceDoneRegisterInputLight,
	UserDeviceRegisterInput,
	UserDeviceRegisterOutput,
	UserIdentifierAvailableServerInput,
	UserIdentifierAvailableServerOutput,
	UserPublicKeyData,
	UserUpdateServerInput,
	UserVerifyKeyData,
};
use sentc_crypto_common::UserId;
use sentc_crypto_core::DeriveMasterKeyForAuth;
use sentc_crypto_utils::error::SdkUtilError;
use sentc_crypto_utils::keys::{PrivateKeyFormatInt, PublicKeyFormatInt, SignKeyFormatInt, VerifyKeyFormatInt};
use sentc_crypto_utils::{
	client_random_value_to_string,
	derive_auth_key_for_auth_to_string,
	export_raw_public_key_to_pem,
	export_raw_verify_key_to_pem,
	handle_server_response,
	hashed_authentication_key_to_string,
	import_public_key_from_pem_with_alg,
	import_verify_key_from_pem_with_alg,
};

#[cfg(not(feature = "rust"))]
pub use self::user::{
	change_password,
	done_check_user_identifier_available,
	done_login,
	done_register,
	done_register_device_start,
	generate_user_register_data,
	prepare_check_user_identifier_available,
	prepare_login,
	prepare_login_start,
	prepare_refresh_jwt,
	prepare_register_device,
	prepare_user_identifier_update,
	register,
	register_typed,
};
#[cfg(feature = "rust")]
pub use self::user_rust::{
	change_password,
	done_check_user_identifier_available,
	done_login,
	done_register,
	done_register_device_start,
	generate_user_register_data,
	prepare_check_user_identifier_available,
	prepare_login,
	prepare_login_start,
	prepare_refresh_jwt,
	prepare_register_device,
	prepare_user_identifier_update,
	register,
	register_typed,
};
use crate::error::SdkLightError;
use crate::{DeviceKeyDataInt, UserDataInt};

fn generate_user_register_data_internally() -> Result<(String, String), SdkLightError>
{
	let (identifier, password) = sentc_crypto_core::generate_user_register_data()?;

	let encoded_identifier = Base64UrlUnpadded::encode_string(&identifier);
	let encoded_password = Base64UrlUnpadded::encode_string(&password);

	Ok((encoded_identifier, encoded_password))
}

fn prepare_check_user_identifier_available_internally(user_identifier: &str) -> Result<String, SdkLightError>
{
	UserIdentifierAvailableServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

fn done_check_user_identifier_available_internally(server_output: &str) -> Result<bool, SdkLightError>
{
	let server_output: UserIdentifierAvailableServerOutput = handle_server_response(server_output)?;

	Ok(server_output.available)
}

fn register_internally(user_identifier: &str, password: &str) -> Result<String, SdkLightError>
{
	//use this also for device register because user and device register are the same in the light version in the client.
	//use this also for reset password data
	let out = prepare_register_device_private_internally(user_identifier, password)?;

	serde_json::to_string(&out).map_err(|_| SdkLightError::JsonToStringFailed)
}

fn done_register_internally(server_output: &str) -> Result<UserId, SdkLightError>
{
	let out: RegisterServerOutput = handle_server_response(server_output)?;

	Ok(out.user_id)
}

fn done_register_device_start_internally(server_output: &str) -> Result<(), SdkLightError>
{
	let _out: UserDeviceRegisterOutput = handle_server_response(server_output)?;

	Ok(())
}

/**
Prepare the user group keys for the new device.

Call this fn from the active device with the server output from register device

Return the public key of the device, for the key session
 */
fn prepare_register_device_internally(server_output: &str) -> Result<String, SdkLightError>
{
	let out: UserDeviceRegisterOutput = handle_server_response(server_output)?;

	serde_json::to_string(&UserDeviceDoneRegisterInputLight {
		user_group: GroupNewMemberLightInput {
			rank: None,
		},
		token: out.token,
	})
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

fn prepare_register_device_private_internally(device_identifier: &str, password: &str) -> Result<UserDeviceRegisterInput, SdkLightError>
{
	let out = sentc_crypto_core::user::register(password)?;

	//encode the encrypted data to base64
	let encrypted_master_key = Base64::encode_string(&out.master_key_info.encrypted_master_key);
	let encrypted_private_key = Base64::encode_string(&out.encrypted_private_key);
	let encrypted_sign_key = Base64::encode_string(&out.encrypted_sign_key);

	//export the public keys (decrypt and verify) to a key format
	let public_key = export_raw_public_key_to_pem(&out.public_key)?;
	let verify_key = export_raw_verify_key_to_pem(&out.verify_key)?;

	//export the random value
	let client_random_value = client_random_value_to_string(&out.client_random_value);
	//export the hashed auth key (the first 16 bits)
	let hashed_authentication_key = hashed_authentication_key_to_string(&out.hashed_authentication_key_bytes);

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

	Ok(UserDeviceRegisterInput {
		master_key,
		derived,
		device_identifier: device_identifier.to_string(),
	})
}

//__________________________________________________________________________________________________
//login

/**
# prepare the data for the server req
 */
fn prepare_login_start_internally(user_identifier: &str) -> Result<String, SdkLightError>
{
	PrepareLoginServerInput {
		user_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

/**
# Starts the login process

1. Get the auth key and the master key encryption key from the password.
2. Send the auth key to the server to get the DoneLoginInput back
 */
fn prepare_login_internally(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, DeriveMasterKeyForAuth), SdkLightError>
{
	let server_output: PrepareLoginSaltServerOutput = handle_server_response(server_output)?;

	let salt = Base64::decode_vec(server_output.salt_string.as_str()).map_err(|_| SdkUtilError::DecodeSaltFailed)?;
	let result = sentc_crypto_core::user::prepare_login(password, &salt, server_output.derived_encryption_key_alg.as_str())?;

	//for the server
	let auth_key = derive_auth_key_for_auth_to_string(&result.auth_key);

	let auth_key = DoneLoginServerInput {
		auth_key,
		device_identifier: user_identifier.to_string(),
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)?;

	Ok((auth_key, result.master_key_encryption_key))
}

/**
# finalize the login process

1. extract the DoneLoginInput from the server. It includes the encrypted master key, encrypted private key, in pem exported public key
2. decrypt the master key with the encryption key from @see prepare_login
3. import the public key to the internal format
 */
fn done_login_internally(master_key_encryption: &DeriveMasterKeyForAuth, server_output: &str) -> Result<UserDataInt, SdkLightError>
{
	let server_output: DoneLoginLightOutput = handle_server_response(server_output)?;

	let device_keys = done_login_internally_with_device_out(master_key_encryption, &server_output)?;

	Ok(UserDataInt {
		jwt: server_output.jwt,
		refresh_token: server_output.refresh_token,
		user_id: server_output.user_id,
		device_id: server_output.device_id,
		device_keys,
	})
}

fn done_login_internally_with_device_out(
	master_key_encryption: &DeriveMasterKeyForAuth,
	server_output: &DoneLoginLightOutput,
) -> Result<DeviceKeyDataInt, SdkLightError>
{
	let encrypted_master_key = Base64::decode_vec(server_output.encrypted_master_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;
	let encrypted_private_key = Base64::decode_vec(server_output.encrypted_private_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;
	let encrypted_sign_key = Base64::decode_vec(server_output.encrypted_sign_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

	let public_key = import_public_key_from_pem_with_alg(
		&server_output.public_key_string,
		server_output.keypair_encrypt_alg.as_str(),
	)?;

	let verify_key = import_verify_key_from_pem_with_alg(
		server_output.verify_key_string.as_str(),
		server_output.keypair_sign_alg.as_str(),
	)?;

	//export this too, so the user can verify the own data
	let exported_public_key = UserPublicKeyData {
		public_key_pem: server_output.public_key_string.to_string(),
		public_key_alg: server_output.keypair_encrypt_alg.to_string(),
		public_key_id: server_output.device_id.clone(),
		public_key_sig: None, //no sig for device keys
		public_key_sig_key_id: None,
	};

	let exported_verify_key = UserVerifyKeyData {
		verify_key_pem: server_output.verify_key_string.to_string(),
		verify_key_alg: server_output.keypair_sign_alg.to_string(),
		verify_key_id: server_output.device_id.clone(),
	};

	//use fake sign key here
	let out = sentc_crypto_core::user::done_login(
		master_key_encryption,
		&encrypted_master_key,
		&encrypted_private_key,
		server_output.keypair_encrypt_alg.as_str(),
		&encrypted_sign_key,
		server_output.keypair_sign_alg.as_str(),
	)?;

	Ok(DeviceKeyDataInt {
		private_key: PrivateKeyFormatInt {
			key_id: server_output.device_id.clone(),
			key: out.private_key,
		},
		sign_key: SignKeyFormatInt {
			key_id: server_output.device_id.clone(),
			key: out.sign_key,
		},
		public_key: PublicKeyFormatInt {
			key_id: server_output.device_id.clone(),
			key: public_key,
		},
		verify_key: VerifyKeyFormatInt {
			key_id: server_output.device_id.clone(),
			key: verify_key,
		},
		exported_public_key,
		exported_verify_key,
	})
}

//__________________________________________________________________________________________________

fn prepare_user_identifier_update_internally(user_identifier: String) -> Result<String, SdkLightError>
{
	let input = UserUpdateServerInput {
		user_identifier,
	};

	input
		.to_string()
		.map_err(|_| SdkLightError::JsonToStringFailed)
}

fn prepare_refresh_jwt_internally(refresh_token: String) -> Result<String, SdkLightError>
{
	JwtRefreshInput {
		refresh_token,
	}
	.to_string()
	.map_err(|_| SdkLightError::JsonToStringFailed)
}

//__________________________________________________________________________________________________

fn change_password_internally(
	old_pw: &str,
	new_pw: &str,
	server_output_prep_login: &str,
	server_output_done_login: &str,
) -> Result<String, SdkLightError>
{
	let server_output_prep_login: PrepareLoginSaltServerOutput = handle_server_response(server_output_prep_login)?;
	let server_output_done_login: DoneLoginLightOutput = handle_server_response(server_output_done_login)?;

	let encrypted_master_key =
		Base64::decode_vec(server_output_done_login.encrypted_master_key.as_str()).map_err(|_| SdkUtilError::DerivedKeyWrongFormat)?;

	let old_salt = Base64::decode_vec(server_output_prep_login.salt_string.as_str()).map_err(|_| SdkUtilError::DecodeSaltFailed)?;

	let output = sentc_crypto_core::user::change_password(
		old_pw,
		new_pw,
		&old_salt,
		&encrypted_master_key,
		server_output_prep_login.derived_encryption_key_alg.as_str(),
	)?;

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

	pw_change_out
		.to_string()
		.map_err(|_| SdkLightError::JsonToStringFailed)
}

#[cfg(test)]
pub(crate) mod test_fn
{
	use alloc::vec::Vec;

	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_core::generate_salt;
	use sentc_crypto_utils::client_random_value_from_string;

	use super::*;

	fn generate_salt_from_base64(client_random_value: &str, alg: &str, add_str: &str) -> Vec<u8>
	{
		let client_random_value = client_random_value_from_string(client_random_value, alg).unwrap();

		generate_salt(client_random_value, add_str)
	}

	fn generate_salt_from_base64_to_string(client_random_value: &str, alg: &str, add_str: &str) -> String
	{
		let salt = generate_salt_from_base64(client_random_value, alg, add_str);

		Base64::encode_string(&salt)
	}

	pub(crate) fn simulate_server_prepare_login(derived: &KeyDerivedData) -> String
	{
		let salt_string = generate_salt_from_base64_to_string(derived.client_random_value.as_str(), derived.derived_alg.as_str(), "");

		ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(PrepareLoginSaltServerOutput {
				salt_string,
				derived_encryption_key_alg: derived.derived_alg.clone(),
			}),
		}
		.to_string()
		.unwrap()
	}

	pub(crate) fn simulate_server_done_login(device: UserDeviceRegisterInput) -> String
	{
		//get the server output back
		let device_keys = DoneLoginLightOutput {
			encrypted_master_key: device.master_key.encrypted_master_key,
			encrypted_private_key: device.derived.encrypted_private_key,
			encrypted_sign_key: device.derived.encrypted_sign_key,
			public_key_string: device.derived.public_key,
			verify_key_string: device.derived.verify_key,
			keypair_encrypt_alg: device.derived.keypair_encrypt_alg,
			keypair_sign_alg: device.derived.keypair_sign_alg,
			user_id: "abc".to_string(),
			jwt: "".to_string(),
			device_id: "abc".to_string(),
			refresh_token: "".to_string(),
		};

		ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(device_keys),
		}
		.to_string()
		.unwrap()
	}
}
