use std::future::Future;

use anyhow::{anyhow, Result};
use sentc_crypto::user;
use tokio::runtime::Runtime;

//User
#[repr(C)]
pub struct GeneratedRegisterData
{
	pub identifier: String,
	pub password: String,
}

#[repr(C)]
pub struct PrepareLoginOutput
{
	pub auth_key: String,
	pub master_key_encryption_key: String,
}

#[repr(C)]
pub struct DeviceKeyData
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl From<sentc_crypto::util::DeviceKeyData> for DeviceKeyData
{
	fn from(keys: sentc_crypto::DeviceKeyData) -> Self
	{
		Self {
			private_key: keys.private_key,
			public_key: keys.public_key,
			sign_key: keys.sign_key,
			verify_key: keys.verify_key,
			exported_public_key: keys.exported_public_key,
			exported_verify_key: keys.exported_verify_key,
		}
	}
}

#[repr(C)]
pub struct UserKeyData
{
	pub private_key: String,
	pub public_key: String,
	pub group_key: String,
	pub time: String,
	pub group_key_id: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl From<sentc_crypto::util::UserKeyData> for UserKeyData
{
	fn from(data: sentc_crypto::UserKeyData) -> Self
	{
		Self {
			private_key: data.private_key,
			public_key: data.public_key,
			group_key: data.group_key,
			time: data.time.to_string(),
			group_key_id: data.group_key_id,
			sign_key: data.sign_key,
			verify_key: data.verify_key,
			exported_public_key: data.exported_public_key,
			exported_verify_key: data.exported_verify_key,
		}
	}
}

#[repr(C)]
pub struct UserData
{
	pub jwt: String,
	pub user_id: String,
	pub device_id: String,
	pub refresh_token: String,
	pub keys: DeviceKeyData,
	pub user_keys: Vec<UserKeyData>,
}

impl From<sentc_crypto::util::UserData> for UserData
{
	fn from(data: sentc_crypto::UserData) -> Self
	{
		let mut user_keys = Vec::with_capacity(data.user_keys.len());

		for user_key in data.user_keys {
			user_keys.push(user_key.into());
		}

		Self {
			jwt: data.jwt,
			user_id: data.user_id,
			device_id: data.device_id,
			refresh_token: data.refresh_token,
			keys: data.device_keys.into(),
			user_keys,
		}
	}
}

fn rt<T, Fut>(fun: Fut) -> Result<T>
where
	Fut: Future<Output = std::result::Result<T, String>>,
{
	let rt = Runtime::new().unwrap();

	let data = rt.block_on(fun).map_err(|err| anyhow!(err))?;

	Ok(data)
}

//__________________________________________________________________________________________________

/**
# Check if the identifier is available for this app
 */
pub fn check_user_identifier_available(base_url: String, auth_token: String, user_identifier: String) -> Result<bool>
{
	let out = rt(async {
		//
		sentc_crypto_full::user::check_user_identifier_available(
			//
			base_url,
			auth_token.as_str(),
			user_identifier.as_str(),
		)
		.await
	})?;

	Ok(out)
}

/**
# Check if the identifier is available

but without making a request
 */
pub fn prepare_check_user_identifier_available(user_identifier: String) -> Result<String>
{
	user::prepare_check_user_identifier_available(user_identifier.as_str()).map_err(|err| anyhow!(err))
}

/**
# Validates the response if the identifier is available

but without making a request
 */
pub fn done_check_user_identifier_available(server_output: String) -> Result<bool>
{
	user::done_check_user_identifier_available(server_output.as_str()).map_err(|err| anyhow!(err))
}

/**
Generates identifier and password for a user or device
*/
pub fn generate_user_register_data() -> Result<GeneratedRegisterData>
{
	let (identifier, password) = user::generate_user_register_data().map_err(|err| anyhow!(err))?;

	Ok(GeneratedRegisterData {
		identifier,
		password,
	})
}

/**
# Get the user input from the user client

This is used when the register endpoint should only be called from the backend and not the clients.

For full register see register()
 */
pub fn prepare_register(user_identifier: String, password: String) -> Result<String>
{
	user::register(user_identifier.as_str(), password.as_str()).map_err(|err| anyhow!(err))
}

/**
# Validates the response of register

Returns the new user id
 */
pub fn done_register(server_output: String) -> Result<String>
{
	user::done_register(server_output.as_str()).map_err(|err| anyhow!(err))
}

/**
# Register a new user for the app

Do the full req incl. req.
No checking about spamming and just return the user id.
 */
pub fn register(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<String>
{
	let data = rt(async {
		sentc_crypto_full::user::register(
			base_url,
			auth_token.as_str(),
			user_identifier.as_str(),
			password.as_str(),
		)
		.await
	})?;

	Ok(data)
}

pub fn prepare_register_device_start(device_identifier: String, password: String) -> Result<String>
{
	user::prepare_register_device_start(device_identifier.as_str(), password.as_str()).map_err(|err| anyhow!(err))
}

pub fn done_register_device_start(server_output: String) -> Result<()>
{
	user::done_register_device_start(server_output.as_str()).map_err(|err| anyhow!(err))
}

pub fn register_device_start(base_url: String, auth_token: String, device_identifier: String, password: String) -> Result<String>
{
	let out = rt(async {
		sentc_crypto_full::user::register_device_start(
			base_url,
			auth_token.as_str(),
			device_identifier.as_str(),
			password.as_str(),
		)
		.await
	})?;

	Ok(out)
}

#[repr(C)]
pub struct PreRegisterDeviceData
{
	pub input: String,
	pub exported_public_key: String,
}

#[repr(C)]
pub struct RegisterDeviceData
{
	pub session_id: String,
	pub exported_public_key: String,
}

pub fn prepare_register_device(server_output: String, user_keys: String, key_count: i32) -> Result<PreRegisterDeviceData>
{
	let key_session = if key_count > 50 { true } else { false };

	let (input, exported_public_key) = user::prepare_register_device(
		//
		server_output.as_str(),
		user_keys.as_str(),
		key_session,
	)
	.map_err(|err| anyhow!(err))?;

	Ok(PreRegisterDeviceData {
		input,
		exported_public_key,
	})
}

pub fn register_device(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	key_count: i32,
	user_keys: String,
) -> Result<RegisterDeviceData>
{
	let (out, exported_public_key) = rt(async {
		sentc_crypto_full::user::register_device(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			server_output.as_str(),
			key_count,
			user_keys.as_str(),
		)
		.await
	})?;

	let session_id = match out {
		Some(id) => id,
		None => String::from(""),
	};

	Ok(RegisterDeviceData {
		session_id,
		exported_public_key,
	})
}

pub fn user_device_key_session_upload(
	base_url: String,
	auth_token: String,
	jwt: String,
	session_id: String,
	user_public_key: String,
	group_keys: String,
) -> Result<()>
{
	rt(async {
		sentc_crypto_full::user::device_key_session(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			session_id.as_str(),
			user_public_key.as_str(),
			group_keys.as_str(),
		)
		.await
	})
}

//__________________________________________________________________________________________________

pub fn prepare_login_start(base_url: String, auth_token: String, user_identifier: String) -> Result<String>
{
	let out = rt(async {
		//
		sentc_crypto_full::user::prepare_login_start(
			//
			base_url,
			auth_token.as_str(),
			user_identifier.as_str(),
		)
		.await
	})?;

	Ok(out)
}

pub fn prepare_login(user_identifier: String, password: String, server_output: String) -> Result<PrepareLoginOutput>
{
	let (auth_key, master_key_encryption_key) = user::prepare_login(
		//
		user_identifier.as_str(),
		password.as_str(),
		server_output.as_str(),
	)
	.map_err(|err| anyhow!(err))?;

	Ok(PrepareLoginOutput {
		auth_key,
		master_key_encryption_key,
	})
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> Result<UserData>
{
	let data = user::done_login(master_key_encryption.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(data.into())
}

/**
# Login the user to this app

Does the login requests. 1. for auth, 2nd to get the keys.

If there are more data in the backend, then it is possible to call it via the jwt what is returned by the done login request.

The other backend can validate the jwt
 */
pub fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserData>
{
	let data = rt(async {
		sentc_crypto_full::user::login(
			base_url,
			auth_token.as_str(),
			user_identifier.as_str(),
			password.as_str(),
		)
		.await
	})?;

	Ok(data.into())
}

pub fn done_fetch_user_key(private_key: String, server_output: String) -> Result<UserKeyData>
{
	let data = user::done_key_fetch(private_key.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(data.into())
}

pub fn fetch_user_key(base_url: String, auth_token: String, jwt: String, key_id: String, private_key: String) -> Result<UserKeyData>
{
	let data = rt(async {
		sentc_crypto_full::user::fetch_user_key(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			key_id.as_str(),
			private_key.as_str(),
		)
		.await
	})?;

	Ok(data.into())
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct UserInitServerOutput
{
	pub jwt: String,
	pub invites: Vec<GroupInviteReqList>,
}

pub fn refresh_jwt(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<String>
{
	rt(async {
		//
		sentc_crypto_full::user::refresh_jwt(
			//
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			refresh_token.as_str(),
		)
		.await
	})
}

pub fn init_user(base_url: String, auth_token: String, jwt: String, refresh_token: String) -> Result<UserInitServerOutput>
{
	let out = rt(async {
		//
		sentc_crypto_full::user::init_user(
			//
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			refresh_token.as_str(),
		)
		.await
	})?;

	let mut invites = Vec::with_capacity(out.invites.len());

	for invite in out.invites {
		invites.push(invite.into());
	}

	Ok(UserInitServerOutput {
		jwt: out.jwt,
		invites,
	})
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct UserDeviceList
{
	pub device_id: String,
	pub time: String,
	pub device_identifier: String,
}

impl From<sentc_crypto_common::user::UserDeviceList> for UserDeviceList
{
	fn from(list: sentc_crypto_common::user::UserDeviceList) -> Self
	{
		Self {
			device_id: list.device_id,
			time: list.time.to_string(),
			device_identifier: list.device_identifier,
		}
	}
}

pub fn get_user_devices(
	base_url: String,
	auth_token: String,
	jwt: String,
	last_fetched_time: String,
	last_fetched_id: String,
) -> Result<Vec<UserDeviceList>>
{
	let out = rt(async {
		sentc_crypto_full::user::get_user_devices(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			last_fetched_time.as_str(),
			last_fetched_id.as_str(),
		)
		.await
	})?;

	let mut list = Vec::with_capacity(out.len());

	for device in out {
		list.push(device.into())
	}

	Ok(list)
}

pub fn reset_password(
	base_url: String,
	auth_token: String,
	jwt: String,
	new_password: String,
	decrypted_private_key: String,
	decrypted_sign_key: String,
) -> Result<()>
{
	rt(async {
		sentc_crypto_full::user::reset_password(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			new_password.as_str(),
			decrypted_private_key.as_str(),
			decrypted_sign_key.as_str(),
		)
		.await
	})
}

pub fn change_password(base_url: String, auth_token: String, user_identifier: String, old_password: String, new_password: String) -> Result<()>
{
	rt(async {
		sentc_crypto_full::user::change_password(
			base_url,
			auth_token.as_str(),
			user_identifier.as_str(),
			old_password.as_str(),
			new_password.as_str(),
		)
		.await
	})
}

pub fn delete_user(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<()>
{
	rt(async {
		sentc_crypto_full::user::delete(
			base_url,
			auth_token.as_str(),
			user_identifier.as_str(),
			password.as_str(),
		)
		.await
	})
}

pub fn delete_device(base_url: String, auth_token: String, device_identifier: String, password: String, device_id: String) -> Result<()>
{
	rt(async {
		sentc_crypto_full::user::delete_device(
			base_url,
			auth_token.as_str(),
			device_identifier.as_str(),
			password.as_str(),
			device_id.as_str(),
		)
		.await
	})
}

pub fn update_user(base_url: String, auth_token: String, jwt: String, user_identifier: String) -> Result<()>
{
	rt(async {
		//
		sentc_crypto_full::user::update(base_url, auth_token.as_str(), jwt.as_str(), user_identifier).await
	})
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct UserPublicKeyData
{
	pub public_key: String,
	pub public_key_id: String,
}

pub fn user_fetch_public_key(base_url: String, auth_token: String, user_id: String) -> Result<UserPublicKeyData>
{
	let (public_key, public_key_id) = rt(async {
		//
		sentc_crypto_full::user::fetch_user_public_key(base_url, auth_token.as_str(), user_id.as_str()).await
	})?;

	Ok(UserPublicKeyData {
		public_key,
		public_key_id,
	})
}

pub fn user_fetch_verify_key(base_url: String, auth_token: String, user_id: String, verify_key_id: String) -> Result<String>
{
	let key = rt(async {
		sentc_crypto_full::user::fetch_user_verify_key_by_id(
			base_url,
			auth_token.as_str(),
			user_id.as_str(),
			verify_key_id.as_str(),
		)
		.await
	})?;

	Ok(key)
}

//__________________________________________________________________________________________________

#[repr(C)]
pub struct KeyRotationGetOut
{
	pub pre_group_key_id: String,
	pub new_group_key_id: String,
	pub encrypted_eph_key_key_id: String,
	pub server_output: String,
}

pub fn user_key_rotation(base_url: String, auth_token: String, jwt: String, public_device_key: String, pre_user_key: String) -> Result<String>
{
	rt(async {
		sentc_crypto_full::user::key_rotation(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			public_device_key.as_str(),
			pre_user_key.as_str(),
		)
		.await
	})
}

pub fn user_pre_done_key_rotation(base_url: String, auth_token: String, jwt: String) -> Result<Vec<KeyRotationGetOut>>
{
	let out = rt(async { sentc_crypto_full::user::prepare_done_key_rotation(base_url, auth_token.as_str(), jwt.as_str()).await })?;

	let mut list = Vec::with_capacity(out.len());

	for item in out {
		list.push(KeyRotationGetOut {
			pre_group_key_id: item.pre_group_key_id,
			new_group_key_id: item.new_group_key_id,
			encrypted_eph_key_key_id: item.encrypted_eph_key_key_id,
			server_output: item.server_output,
		});
	}

	Ok(list)
}

pub fn user_get_done_key_rotation_server_input(server_output: String) -> Result<KeyRotationInput>
{
	let out = sentc_crypto::group::get_done_key_rotation_server_input(server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(out.into())
}

pub fn user_finish_key_rotation(
	base_url: String,
	auth_token: String,
	jwt: String,
	server_output: String,
	pre_group_key: String,
	public_key: String,
	private_key: String,
) -> Result<()>
{
	rt(async {
		sentc_crypto_full::user::done_key_rotation(
			base_url,
			auth_token.as_str(),
			jwt.as_str(),
			server_output.as_str(),
			pre_group_key.as_str(),
			public_key.as_str(),
			private_key.as_str(),
		)
		.await
	})
}

//==================================================================================================
//Group

#[repr(C)]
pub struct GroupInviteReqList
{
	pub group_id: String,
	pub time: String,
}

impl From<sentc_crypto_common::group::GroupInviteReqList> for GroupInviteReqList
{
	fn from(list: sentc_crypto_common::group::GroupInviteReqList) -> Self
	{
		Self {
			group_id: list.group_id,
			time: list.time.to_string(),
		}
	}
}

#[repr(C)]
pub struct KeyRotationInput
{
	pub encrypted_ephemeral_key_by_group_key_and_public_key: String,
	pub encrypted_group_key_by_ephemeral: String,
	pub ephemeral_alg: String,
	pub encrypted_eph_key_key_id: String, //the public key id which was used to encrypt the eph key on the server.
	pub previous_group_key_id: String,
	pub time: String,
	pub new_group_key_id: String,
}

impl From<sentc_crypto_common::group::KeyRotationInput> for KeyRotationInput
{
	fn from(out: sentc_crypto_common::group::KeyRotationInput) -> Self
	{
		Self {
			encrypted_ephemeral_key_by_group_key_and_public_key: out.encrypted_ephemeral_key_by_group_key_and_public_key,
			encrypted_group_key_by_ephemeral: out.encrypted_group_key_by_ephemeral,
			ephemeral_alg: out.ephemeral_alg,
			encrypted_eph_key_key_id: out.encrypted_eph_key_key_id,
			previous_group_key_id: out.previous_group_key_id,
			time: out.time.to_string(),
			new_group_key_id: out.new_group_key_id,
		}
	}
}
