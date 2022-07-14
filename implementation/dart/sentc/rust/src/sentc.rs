use anyhow::{anyhow, Result};
use sentc_crypto::{test_fn, user};

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
	pub jwt: String,
	pub exported_public_key: String,
	pub exported_verify_key: String,
}

pub fn register_test_full() -> String
{
	test_fn::register_test_full()
}

//real usage
pub fn register(user_identifier: String, password: String) -> Result<String>
{
	user::register(user_identifier.as_str(), password.as_str()).map_err(|err| anyhow!(err))
}

pub fn prepare_login(password: String, server_output: String) -> Result<PrepareLoginOutput>
{
	let (auth_key, master_key_encryption_key) = user::prepare_login(password.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(PrepareLoginOutput {
		auth_key,
		master_key_encryption_key,
	})
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> Result<KeyData>
{
	let data = user::done_login(master_key_encryption.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))?;

	Ok(KeyData {
		private_key: data.private_key,
		public_key: data.public_key,
		sign_key: data.sign_key,
		verify_key: data.verify_key,
		jwt: data.jwt,
		exported_public_key: data.exported_public_key,
		exported_verify_key: data.exported_verify_key,
	})
}
