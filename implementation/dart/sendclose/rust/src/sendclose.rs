use sendclose_crypto::register_test;
use sendclose_crypto::user::{done_login as done_login_core, prepare_login as prepare_login_core, register as register_core};

pub fn register_test_full() -> String
{
	register_test()
}

//real usage
pub fn register(password: String) -> String
{
	register_core(password.as_str())
}

pub fn prepare_login(password: String, server_output: String) -> String
{
	prepare_login_core(password.as_str(), server_output.as_str())
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> String
{
	done_login_core(master_key_encryption.as_str(), server_output.as_str())
}
