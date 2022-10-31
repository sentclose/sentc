use std::future::Future;

use anyhow::{anyhow, Result};
use sentc_crypto::user;
use tokio::runtime::Runtime;

//User
pub struct GeneratedRegisterData
{
	pub identifier: String,
	pub password: String,
}

pub struct PrepareLoginOutput
{
	pub auth_key: String,
	pub master_key_encryption_key: String,
}

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

pub struct PreRegisterDeviceData
{
	pub input: String,
	pub exported_public_key: String,
}

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

//==================================================================================================
//Group

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
