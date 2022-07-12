use anyhow::{anyhow, Result};
use sentc_crypto::{test_fn, user};

pub struct PrepareLoginOutput
{
	pub auth_key: String,
	pub master_key_encryption_key: String,
}

pub fn register_test_full() -> String
{
	test_fn::register_test_full()
}

//real usage
pub fn register(username: String, password: String) -> Result<String>
{
	user::register(username.as_str(), password.as_str()).map_err(|err| anyhow!(err))
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
) -> Result<String>
{
	user::done_login(master_key_encryption.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))
}
