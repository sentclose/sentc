use anyhow::{anyhow, Result};
use sentc_crypto::user;
use tokio::runtime::Runtime;

pub struct PrepareLoginOutput
{
	pub auth_key: String,
	pub master_key_encryption_key: String,
}

pub struct KeyData
{
	pub private_key: String, //Base64 exported keys
	pub public_key: String,
	pub sign_key: String,
	pub verify_key: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

impl From<sentc_crypto::util::DeviceKeyData> for KeyData
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

pub struct UserData
{
	pub jwt: String,
	pub user_id: String,
	pub refresh_token: String,
	pub keys: KeyData,
}

impl From<sentc_crypto::util::UserData> for UserData
{
	fn from(data: sentc_crypto::UserData) -> Self
	{
		Self {
			jwt: data.jwt,
			user_id: data.user_id,
			refresh_token: data.refresh_token,
			keys: data.device_keys.into(),
		}
	}
}

pub fn prepare_register(user_identifier: String, password: String) -> Result<String>
{
	user::register(user_identifier.as_str(), password.as_str()).map_err(|err| anyhow!(err))
}

pub fn done_register(server_output: String) -> Result<String>
{
	user::done_register(server_output.as_str()).map_err(|err| anyhow!(err))
}

pub fn register(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<String>
{
	let rt = Runtime::new().unwrap();

	let data = rt
		.block_on(async {
			sentc_crypto_full::user::register(
				base_url,
				auth_token.as_str(),
				user_identifier.as_str(),
				password.as_str(),
			)
			.await
		})
		.map_err(|err| anyhow!(err))?;

	Ok(data)
}

pub fn prepare_login(user_identifier: String, password: String, server_output: String) -> Result<PrepareLoginOutput>
{
	let (auth_key, master_key_encryption_key) =
		user::prepare_login(user_identifier.as_str(), password.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

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

pub fn login(base_url: String, auth_token: String, user_identifier: String, password: String) -> Result<UserData>
{
	let rt = Runtime::new().unwrap();

	let data = rt
		.block_on(async {
			sentc_crypto_full::user::login(
				base_url,
				auth_token.as_str(),
				user_identifier.as_str(),
				password.as_str(),
			)
			.await
		})
		.map_err(|err| anyhow!(err))?;

	Ok(data.into())
}
