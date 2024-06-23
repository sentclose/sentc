use sentc_crypto::user::{done_register_device_start, generate_user_register_data};
use sentc_crypto_common::group::CreateData;
use sentc_crypto_common::user::{ChangePasswordData, RegisterData, UserDeviceDoneRegisterInput, UserDeviceRegisterInput, UserDeviceRegisterOutput};
use sentc_crypto_common::ServerOutput;
use sentc_crypto_fips_keys::sdk::FipsUser;
use serde_json::to_string;

use crate::sdk_test_fn::{create_user, simulate_server_done_login, simulate_server_prepare_login, simulate_verify_login};

mod sdk_test_fn;

#[test]
fn test_register()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let username = "admin";
	let password = "abc*èéöäüê";

	let out = FipsUser::register(username, password).unwrap();

	std::println!("rust: {}", out);
}

#[test]
fn test_register_with_generated_data()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let (username, password) = generate_user_register_data().unwrap();

	FipsUser::register(&username, &password).unwrap();
}

#[test]
fn test_register_and_login()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let username = "admin";
	let password = "abc*èéöäüê";

	let out_string = FipsUser::register(username, password).unwrap();

	let out = RegisterData::from_string(&out_string).unwrap();

	let server_output = simulate_server_prepare_login(&out.device.derived);

	//back to the client, send prep login out string to the server if it is no err
	let (_, auth_key, master_key_encryption_key) = FipsUser::prepare_login(username, password, &server_output).unwrap();

	let server_output = simulate_server_done_login(out);

	//now save the values
	let login_out = FipsUser::done_login(
		&master_key_encryption_key,
		auth_key,
		username.to_string(),
		server_output,
	)
	.unwrap();

	let server_output = simulate_verify_login(RegisterData::from_string(&out_string).unwrap(), &login_out.challenge);
	let _out = FipsUser::verify_login(
		&server_output,
		login_out.user_id,
		login_out.device_id,
		login_out.device_keys,
	)
	.unwrap();
}

#[test]
fn test_change_password()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let username = "admin";
	let password = "abc*èéöäüê";
	let new_password = "abcdfg";

	let out = FipsUser::register(username, password).unwrap();

	let out_new = RegisterData::from_string(out.as_str()).unwrap();
	let out_old = RegisterData::from_string(out.as_str()).unwrap();

	let prep_server_output = simulate_server_prepare_login(&out_new.device.derived);
	let done_server_output = simulate_server_done_login(out_new);

	let pw_change_out = FipsUser::change_password(password, new_password, &prep_server_output, done_server_output).unwrap();

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
	openssl::provider::Provider::load(None, "fips").unwrap();

	//1. register the main device
	let out_string = FipsUser::register("hello", "1234").unwrap();
	let out = RegisterData::from_string(out_string.as_str()).unwrap();

	let server_output = simulate_server_prepare_login(&out.device.derived);
	let (_, auth_key, master_key_encryption_key) = FipsUser::prepare_login("hello", "1234", server_output.as_str()).unwrap();

	let server_output = simulate_server_done_login(out);

	//now save the values
	let done_login_out = FipsUser::done_login(
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
	let user = FipsUser::verify_login(
		&server_output,
		done_login_out.user_id,
		done_login_out.device_id,
		done_login_out.device_keys,
	)
	.unwrap();

	//2. prepare the device register
	let device_id = "hello_device";
	let device_pw = "12345";

	let server_input = FipsUser::prepare_register_device_start(device_id, device_pw).unwrap();

	//3. simulate server
	let input: UserDeviceRegisterInput = serde_json::from_str(&server_input).unwrap();

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

	let (out, _) = FipsUser::prepare_register_device(&server_output, &[&user.user_keys[0].group_key], false).unwrap();

	let out: UserDeviceDoneRegisterInput = serde_json::from_str(&out).unwrap();
	let user_keys = &out.user_keys.keys[0];

	//7. check login with new device
	let out_new_device = RegisterData::from_string(out_string.as_str()).unwrap();

	let server_output = simulate_server_prepare_login(&input.derived);
	let (_, auth_key, master_key_encryption_key) = FipsUser::prepare_login(device_id, device_pw, server_output.as_str()).unwrap();

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

	let server_output = simulate_server_done_login(serde_json::from_str(&new_device_register_data).unwrap());

	let new_device_data = FipsUser::done_login(
		&master_key_encryption_key,
		auth_key,
		device_id.to_string(),
		server_output,
	)
	.unwrap();

	let server_output = simulate_verify_login(
		serde_json::from_str(&new_device_register_data).unwrap(),
		&new_device_data.challenge,
	);

	let new_device_data = FipsUser::verify_login(
		&server_output,
		new_device_data.user_id,
		new_device_data.device_id,
		new_device_data.device_keys,
	)
	.unwrap();

	assert_eq!(
		user.user_keys[0].group_key.key.as_ref(),
		new_device_data.user_keys[0].group_key.key.as_ref()
	);
}

#[test]
fn test_safety_number()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//use other ids to compare equal
	let user_1 = create_user();
	let user_1_id = "abc1";
	let user_2 = create_user();
	let user_2_id = "abc2";
	let user_3 = create_user();
	let user_3_id = "abc3";

	let _number_single = FipsUser::create_safety_number(&user_1.user_keys[0].exported_verify_key, &user_1.user_id, None, None).unwrap();

	let number = FipsUser::create_safety_number(
		&user_1.user_keys[0].exported_verify_key,
		user_1_id,
		Some(&user_2.user_keys[0].exported_verify_key),
		Some(user_2_id),
	)
	.unwrap();
	let number_2 = FipsUser::create_safety_number(
		&user_2.user_keys[0].exported_verify_key,
		user_2_id,
		Some(&user_1.user_keys[0].exported_verify_key),
		Some(user_1_id),
	)
	.unwrap();

	assert_eq!(number, number_2);

	let number_3 = FipsUser::create_safety_number(
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
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user_1 = create_user();

	let verify = FipsUser::verify_user_public_key(
		&user_1.user_keys[0].exported_verify_key,
		&user_1.user_keys[0].exported_public_key,
	)
	.unwrap();

	assert!(verify);
}
