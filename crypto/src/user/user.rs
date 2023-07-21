use alloc::string::String;
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::user::{RegisterData, UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::UserId;
use sentc_crypto_core::DeriveMasterKeyForAuth;
use sentc_crypto_utils::keys::{SymKeyFormatExport, SymKeyFormatInt};
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::entities::user::{UserDataExport, UserKeyDataExport};
use crate::user::{
	change_password_internally,
	create_safety_number_internally,
	done_check_user_identifier_available_internally,
	done_key_fetch_internally,
	done_login_internally,
	done_register_device_start_internally,
	done_register_internally,
	generate_user_register_data_internally,
	prepare_check_user_identifier_available_internally,
	prepare_login_internally,
	prepare_login_start_internally,
	prepare_refresh_jwt_internally,
	prepare_register_device_internally,
	prepare_register_device_start_internally,
	prepare_user_identifier_update_internally,
	register_internally,
	register_typed_internally,
	reset_password_internally,
	verify_user_public_key_internally,
};
use crate::{group, SdkError};

#[derive(Serialize, Deserialize)]
pub enum MasterKeyFormat
{
	Argon2(String), //Base64 encoded string from prepare login, is used in done_login
}

impl MasterKeyFormat
{
	pub fn from_string(v: &str) -> serde_json::Result<Self>
	{
		from_str::<Self>(v)
	}

	pub fn to_string(&self) -> serde_json::Result<String>
	{
		to_string(self)
	}
}

pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, String>
{
	Ok(prepare_check_user_identifier_available_internally(user_identifier)?)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, String>
{
	Ok(done_check_user_identifier_available_internally(server_output)?)
}

pub fn generate_user_register_data() -> Result<(String, String), String>
{
	Ok(generate_user_register_data_internally()?)
}

pub fn register_typed(user_identifier: &str, password: &str) -> Result<RegisterData, String>
{
	Ok(register_typed_internally(user_identifier, password)?)
}

pub fn register(user_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(register_internally(user_identifier, password)?)
}

pub fn done_register(server_output: &str) -> Result<UserId, String>
{
	Ok(done_register_internally(server_output)?)
}

pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(prepare_register_device_start_internally(device_identifier, password)?)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), String>
{
	Ok(done_register_device_start_internally(server_output)?)
}

pub fn prepare_register_device(server_output: &str, user_keys: &str, key_session: bool) -> Result<(String, String), String>
{
	let user_keys: Vec<SymKeyFormatExport> = from_str(user_keys).map_err(SdkError::JsonParseFailed)?;

	let saved_keys = user_keys
		.iter()
		.map(|k| k.try_into())
		.collect::<Result<Vec<SymKeyFormatInt>, _>>()?;

	let split_group_keys = group::prepare_group_keys_for_new_member_with_ref(&saved_keys);

	let (input, exported_public_key) = prepare_register_device_internally(server_output, &split_group_keys, key_session)?;

	Ok((
		input,
		exported_public_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
	))
}

pub fn prepare_login_start(user_id: &str) -> Result<String, String>
{
	Ok(prepare_login_start_internally(user_id)?)
}

pub fn prepare_login(user_identifier: &str, password: &str, server_output: &str) -> Result<(String, String), String>
{
	//the auth key is already in the right json format for the server
	let (auth_key, master_key_encryption_key) = prepare_login_internally(user_identifier, password, server_output)?;

	//return the encryption key for the master key to the app and then use it for done login
	let master_key_encryption_key = match master_key_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => {
			let key = Base64::encode_string(&k);

			MasterKeyFormat::Argon2(key)
		},
	};

	Ok((
		auth_key,
		master_key_encryption_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
	))
}

pub fn done_login(
	master_key_encryption: &str, //from the prepare login as base64 for exporting
	server_output: &str,
) -> Result<UserDataExport, String>
{
	let master_key_encryption = MasterKeyFormat::from_string(master_key_encryption).map_err(SdkError::JsonParseFailed)?;

	let master_key_encryption = match master_key_encryption {
		MasterKeyFormat::Argon2(mk) => {
			let mk = Base64::decode_vec(mk.as_str()).map_err(|_e| SdkError::KeyDecryptFailed)?;

			//if it was encrypted by a key which was derived by argon
			let master_key_encryption_key: [u8; 32] = mk.try_into().map_err(|_e| SdkError::KeyDecryptFailed)?;

			DeriveMasterKeyForAuth::Argon2(master_key_encryption_key)
		},
	};

	let result = done_login_internally(&master_key_encryption, server_output)?;

	Ok(result.try_into()?)
}

pub fn done_key_fetch(private_key: &str, server_output: &str) -> Result<UserKeyDataExport, String>
{
	let key = done_key_fetch_internally(&private_key.parse()?, server_output)?;

	Ok(key.try_into()?)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, String>
{
	Ok(prepare_user_identifier_update_internally(user_identifier)?)
}

pub fn prepare_refresh_jwt(refresh_token: String) -> Result<String, String>
{
	Ok(prepare_refresh_jwt_internally(refresh_token)?)
}

pub fn change_password(old_pw: &str, new_pw: &str, server_output_prep_login: &str, server_output_done_login: &str) -> Result<String, String>
{
	Ok(change_password_internally(
		old_pw,
		new_pw,
		server_output_prep_login,
		server_output_done_login,
	)?)
}

pub fn reset_password(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	Ok(reset_password_internally(
		new_password,
		&decrypted_private_key.parse()?,
		&decrypted_sign_key.parse()?,
	)?)
}

pub fn create_safety_number(verify_key_1: &str, user_id_1: &str, verify_key_2: Option<&str>, user_id_2: Option<&str>) -> Result<String, String>
{
	let verify_key_1 = UserVerifyKeyData::from_string(verify_key_1).map_err(SdkError::JsonParseFailed)?;
	let verify_key_2 = match verify_key_2 {
		Some(k) => Some(UserVerifyKeyData::from_string(k).map_err(SdkError::JsonParseFailed)?),
		None => None,
	};

	Ok(create_safety_number_internally(
		&verify_key_1,
		user_id_1,
		verify_key_2.as_ref(),
		user_id_2,
	)?)
}

pub fn verify_user_public_key(verify_key: &str, public_key: &str) -> Result<bool, String>
{
	let verify_key = UserVerifyKeyData::from_string(verify_key).map_err(SdkError::JsonParseFailed)?;
	let public_key = UserPublicKeyData::from_string(public_key).map_err(SdkError::JsonParseFailed)?;

	Ok(verify_user_public_key_internally(&verify_key, &public_key)?)
}

#[cfg(test)]
mod test
{
	extern crate std;

	use alloc::string::ToString;
	use alloc::vec;

	use sentc_crypto_common::group::CreateData;
	use sentc_crypto_common::user::{
		ChangePasswordData,
		RegisterData,
		UserDeviceDoneRegisterInput,
		UserDeviceRegisterInput,
		UserDeviceRegisterOutput,
	};
	use sentc_crypto_common::ServerOutput;
	use sentc_crypto_utils::keys::PrivateKeyFormatExport;

	use super::*;
	use crate::user::test_fn::{create_user, simulate_server_done_login, simulate_server_prepare_login};

	#[test]
	fn test_register()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		std::println!("{}", out);
	}

	#[test]
	fn test_register_with_generated_data()
	{
		let (username, password) = generate_user_register_data().unwrap();

		register(&username, &password).unwrap();
	}

	#[test]
	fn test_register_and_login()
	{
		let username = "admin";
		let password = "abc*èéöäüê";

		let out = register(username, password).unwrap();

		let out = RegisterData::from_string(out.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_auth_key, master_key_encryption_key) = prepare_login(username, password, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let login_out = done_login(
			master_key_encryption_key.as_str(), //the value comes from prepare login
			server_output.as_str(),
		)
		.unwrap();

		let private_key = match from_str(&login_out.user_keys[0].private_key).unwrap() {
			PrivateKeyFormatExport::Ecies {
				key_id: _,
				key,
			} => key,
		};

		assert_ne!(private_key, "");
	}

	#[test]
	fn test_change_password()
	{
		let username = "admin";
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(username, password).unwrap();

		let out_new = RegisterData::from_string(out.as_str()).unwrap();
		let out_old = RegisterData::from_string(out.as_str()).unwrap();

		let prep_server_output = simulate_server_prepare_login(&out_new.device.derived);
		let done_server_output = simulate_server_done_login(out_new);

		let pw_change_out = change_password(
			password,
			new_password,
			prep_server_output.as_str(),
			done_server_output.as_str(),
		)
		.unwrap();

		let pw_change_out = ChangePasswordData::from_string(pw_change_out.as_str()).unwrap();

		assert_ne!(
			pw_change_out.new_client_random_value,
			out_old.device.derived.client_random_value
		);

		assert_ne!(
			pw_change_out.new_encrypted_master_key,
			out_old.device.master_key.encrypted_master_key
		);
	}

	#[test]
	fn test_new_device()
	{
		//1. register the main device
		let out_string = register("hello", "1234").unwrap();
		let out = RegisterData::from_string(out_string.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);
		let (_auth_key, master_key_encryption_key) = prepare_login("hello", "1234", server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let user = done_login(
			master_key_encryption_key.as_str(), //the value comes from prepare login
			server_output.as_str(),
		)
		.unwrap();

		//2. prepare the device register
		let device_id = "hello_device";
		let device_pw = "12345";

		let server_input = prepare_register_device_start(device_id, device_pw).unwrap();

		//3. simulate server
		let input: UserDeviceRegisterInput = from_str(&server_input).unwrap();

		//4. server output
		let server_output = UserDeviceRegisterOutput {
			device_id: "abc".to_string(),
			token: "1234567890".to_string(),
			device_identifier: device_id.to_string(),
			public_key_string: input.derived.public_key.to_string(),
			keypair_encrypt_alg: input.derived.keypair_encrypt_alg.to_string(),
		};

		let server_output = ServerOutput {
			status: true,
			err_msg: None,
			err_code: None,
			result: Some(server_output),
		};

		let server_output = to_string(&server_output).unwrap();

		//5. check the server output
		done_register_device_start(&server_output).unwrap();

		//6. register the device with the main device
		let g_k: SymKeyFormatExport = from_str(&user.user_keys[0].group_key).unwrap();
		let user_keys = to_string(&vec![g_k]).unwrap();

		let (out, _) = prepare_register_device(&server_output, &user_keys, false).unwrap();

		let out: UserDeviceDoneRegisterInput = from_str(&out).unwrap();
		let user_keys = &out.user_keys.keys[0];

		//7. check login with new device
		let out_new_device = RegisterData::from_string(out_string.as_str()).unwrap();

		let server_output = simulate_server_prepare_login(&input.derived);
		let (_auth_key, master_key_encryption_key) = prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(RegisterData {
			device: input,
			group: CreateData {
				encrypted_group_key: user_keys.encrypted_group_key.to_string(),
				group_key_alg: out_new_device.group.group_key_alg,
				encrypted_group_key_alg: user_keys.encrypted_alg.to_string(),

				//private and sign key are encrypted by group key and for all device the same
				encrypted_private_group_key: out_new_device.group.encrypted_private_group_key,
				public_group_key: out_new_device.group.public_group_key,
				keypair_encrypt_alg: out_new_device.group.keypair_encrypt_alg,
				creator_public_key_id: "abc".to_string(),
				encrypted_hmac_key: out_new_device.group.encrypted_hmac_key,
				encrypted_hmac_alg: out_new_device.group.encrypted_hmac_alg,
				encrypted_sortable_key: out_new_device.group.encrypted_sortable_key,
				encrypted_sortable_alg: out_new_device.group.encrypted_sortable_alg,
				encrypted_sign_key: out_new_device.group.encrypted_sign_key,
				verify_key: out_new_device.group.verify_key,
				keypair_sign_alg: out_new_device.group.keypair_sign_alg,
				public_key_sig: out_new_device.group.public_key_sig,
			},
		});

		let new_device_data = done_login(master_key_encryption_key.as_str(), server_output.as_str()).unwrap();

		assert_eq!(user.user_keys[0].group_key, new_device_data.user_keys[0].group_key);
		assert_ne!(user.device_keys.private_key, new_device_data.device_keys.private_key);
	}

	#[test]
	fn test_safety_number()
	{
		//use other ids to compare equal
		let user_1 = create_user();
		let user_1_id = "abc1";
		let user_2 = create_user();
		let user_2_id = "abc2";
		let user_3 = create_user();
		let user_3_id = "abc3";

		let _number_single = create_safety_number(&user_1.user_keys[0].exported_verify_key, &user_1.user_id, None, None).unwrap();

		let number = create_safety_number(
			&user_1.user_keys[0].exported_verify_key,
			user_1_id,
			Some(&user_2.user_keys[0].exported_verify_key),
			Some(user_2_id),
		)
		.unwrap();
		let number_2 = create_safety_number(
			&user_2.user_keys[0].exported_verify_key,
			user_2_id,
			Some(&user_1.user_keys[0].exported_verify_key),
			Some(user_1_id),
		)
		.unwrap();

		assert_eq!(number, number_2);

		let number_3 = create_safety_number(
			&user_3.user_keys[0].exported_verify_key,
			user_3_id,
			Some(&user_1.user_keys[0].exported_verify_key),
			Some(user_1_id),
		)
		.unwrap();

		assert_ne!(number, number_3);
	}

	#[test]
	fn test_verify_public_key()
	{
		let user_1 = create_user();

		let verify = verify_user_public_key(
			&user_1.user_keys[0].exported_verify_key,
			&user_1.user_keys[0].exported_public_key,
		)
		.unwrap();

		assert!(verify);
	}

	#[test]
	fn test_verify_public_key_with_wrong_key()
	{
		let user_1 = create_user();
		let user_2 = create_user();

		let verify = verify_user_public_key(
			&user_1.user_keys[0].exported_verify_key,
			&user_2.user_keys[0].exported_public_key,
		)
		.unwrap();
		assert!(!verify);

		let verify = verify_user_public_key(
			&user_2.user_keys[0].exported_verify_key,
			&user_1.user_keys[0].exported_public_key,
		)
		.unwrap();
		assert!(!verify);
	}
}
