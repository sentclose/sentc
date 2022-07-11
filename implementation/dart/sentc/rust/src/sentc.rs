use anyhow::{anyhow, Result};
use sentc_crypto::test_fn;
use sentc_crypto::user::{done_login as done_login_core, prepare_login as prepare_login_core, register as register_core};

pub fn register_test_full() -> String
{
	test_fn::register_test_full()
}

//real usage
pub fn register(password: String) -> Result<String>
{
	register_core(password.as_str()).map_err(|err| anyhow!(err))
}

pub fn prepare_login(password: String, server_output: String) -> Result<String>
{
	prepare_login_core(password.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> Result<String>
{
	done_login_core(master_key_encryption.as_str(), server_output.as_str()).map_err(|err| anyhow!(err))
}
