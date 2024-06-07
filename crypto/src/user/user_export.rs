use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::user::{RegisterData, UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::{DeviceId, UserId};
use sentc_crypto_utils::keys::MasterKeyFormat;
use sentc_crypto_utils::user::{DeviceKeyDataInt, UserPreVerifyLogin};
use serde_json::from_str;

use crate::entities::keys::{SymKeyFormatExport, SymmetricKey};
use crate::entities::user::{UserDataExport, UserKeyDataExport};
use crate::{group, SdkError};

pub fn prepare_check_user_identifier_available(user_identifier: &str) -> Result<String, String>
{
	Ok(super::user::prepare_check_user_identifier_available(user_identifier)?)
}

pub fn done_check_user_identifier_available(server_output: &str) -> Result<bool, String>
{
	Ok(super::user::done_check_user_identifier_available(server_output)?)
}

pub fn generate_user_register_data() -> Result<(String, String), String>
{
	Ok(super::user::generate_user_register_data()?)
}

pub fn register_typed(user_identifier: &str, password: &str) -> Result<RegisterData, String>
{
	Ok(super::user::register_typed(user_identifier, password)?)
}

pub fn register(user_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(super::user::register(user_identifier, password)?)
}

pub fn done_register(server_output: &str) -> Result<UserId, String>
{
	Ok(super::user::done_register(server_output)?)
}

pub fn prepare_register_device_start(device_identifier: &str, password: &str) -> Result<String, String>
{
	Ok(super::user::prepare_register_device_start(
		device_identifier,
		password,
	)?)
}

pub fn done_register_device_start(server_output: &str) -> Result<(), String>
{
	Ok(super::user::done_register_device_start(server_output)?)
}

pub fn prepare_register_device(server_output: &str, user_keys: &str, key_session: bool) -> Result<(String, String), String>
{
	let user_keys: Vec<SymKeyFormatExport> = from_str(user_keys).map_err(SdkError::JsonParseFailed)?;

	let saved_keys = user_keys
		.iter()
		.map(|k| k.try_into())
		.collect::<Result<Vec<SymmetricKey>, _>>()?;

	let split_group_keys = group::prepare_group_keys_for_new_member_with_ref(&saved_keys);

	let (input, exported_public_key) = super::user::prepare_register_device(server_output, &split_group_keys, key_session)?;

	Ok((
		input,
		exported_public_key
			.to_string()
			.map_err(|_e| SdkError::JsonToStringFailed)?,
	))
}

pub fn prepare_login_start(user_id: &str) -> Result<String, String>
{
	Ok(super::user::prepare_login_start(user_id)?)
}

pub fn done_validate_mfa(
	master_key_encryption: &str,
	auth_key: String,
	device_identifier: String,
	server_output: &str,
) -> Result<UserPreVerifyLogin, SdkError>
{
	let master_key_encryption: MasterKeyFormat = master_key_encryption.parse()?;

	super::user::done_validate_mfa(
		&master_key_encryption.try_into()?,
		auth_key,
		device_identifier,
		server_output,
	)
}

pub fn verify_login(server_output: &str, user_id: UserId, device_id: DeviceId, device_keys: DeviceKeyDataInt) -> Result<UserDataExport, String>
{
	let out = super::user::verify_login(server_output, user_id, device_id, device_keys)?;

	Ok(out.try_into()?)
}

pub fn done_key_fetch(private_key: &str, server_output: &str) -> Result<UserKeyDataExport, String>
{
	let key = super::user::done_key_fetch(&private_key.parse()?, server_output)?;

	Ok(key.try_into()?)
}

pub fn prepare_user_identifier_update(user_identifier: String) -> Result<String, String>
{
	Ok(super::user::prepare_user_identifier_update(user_identifier)?)
}

pub fn prepare_refresh_jwt(refresh_token: String) -> Result<String, String>
{
	Ok(super::user::prepare_refresh_jwt(refresh_token)?)
}

pub fn reset_password(new_password: &str, decrypted_private_key: &str, decrypted_sign_key: &str) -> Result<String, String>
{
	Ok(super::user::reset_password(
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

	Ok(super::user::create_safety_number(
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

	Ok(super::user::verify_user_public_key(&verify_key, &public_key)?)
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
	use serde_json::to_string;

	use super::*;
	use crate::user::test_fn::{create_user_export, simulate_server_done_login, simulate_server_prepare_login, simulate_verify_login};
	use crate::user::{change_password, done_login, prepare_login};

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

		let out_string = register(username, password).unwrap();

		let out = RegisterData::from_string(&out_string).unwrap();

		let server_output = simulate_server_prepare_login(&out.device.derived);

		//back to the client, send prep login out string to the server if it is no err
		let (_input, auth_key, master_key_encryption_key) = prepare_login(username, password, server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let done_login = done_login(
			&master_key_encryption_key, //the value comes from prepare login
			auth_key,
			username.to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(RegisterData::from_string(&out_string).unwrap(), &done_login.challenge);
		let _out = verify_login(
			&server_output,
			done_login.user_id,
			done_login.device_id,
			done_login.device_keys,
		)
		.unwrap();
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

		let pw_change_out = change_password(password, new_password, &prep_server_output, done_server_output).unwrap();

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
		let (_input, auth_key, master_key_encryption_key) = prepare_login("hello", "1234", server_output.as_str()).unwrap();

		let server_output = simulate_server_done_login(out);

		//now save the values
		let done_login_out = done_login(
			&master_key_encryption_key, //the value comes from prepare login
			auth_key,
			"hello".to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(
			RegisterData::from_string(&out_string).unwrap(),
			&done_login_out.challenge,
		);
		let user = verify_login(
			&server_output,
			done_login_out.user_id,
			done_login_out.device_id,
			done_login_out.device_keys,
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
		let (_input, auth_key, master_key_encryption_key) = prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

		let new_device_register_data = to_string(&RegisterData {
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
		})
		.unwrap();

		let server_output = simulate_server_done_login(from_str(&new_device_register_data).unwrap());

		let new_device_data = done_login(
			&master_key_encryption_key,
			auth_key,
			device_id.to_string(),
			server_output,
		)
		.unwrap();

		let server_output = simulate_verify_login(
			from_str(&new_device_register_data).unwrap(),
			&new_device_data.challenge,
		);

		let new_device_data = verify_login(
			&server_output,
			new_device_data.user_id,
			new_device_data.device_id,
			new_device_data.device_keys,
		)
		.unwrap();

		assert_eq!(user.user_keys[0].group_key, new_device_data.user_keys[0].group_key);
		assert_ne!(user.device_keys.private_key, new_device_data.device_keys.private_key);
	}

	#[test]
	fn test_safety_number()
	{
		//use other ids to compare equal
		let user_1 = create_user_export();
		let user_1_id = "abc1";
		let user_2 = create_user_export();
		let user_2_id = "abc2";
		let user_3 = create_user_export();
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
		let user_1 = create_user_export();

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
		let user_1 = create_user_export();
		let user_2 = create_user_export();

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
