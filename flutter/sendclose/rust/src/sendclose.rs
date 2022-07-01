use sendclose_crypto::{done_login as done_login_core, prepare_login as prepare_login_core, register as register_core, register_test};

pub fn register_test_full() -> String
{
	register_test()
}

//real usage
pub fn register(password: String) -> String
{
	register_core(password)
}

pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> String
{
	prepare_login_core(password, salt_string, derived_encryption_key_alg)
}

pub fn done_login(
	master_key_encryption: String, //from the prepare login as base64 for exporting
	server_output: String,
) -> String
{
	done_login_core(master_key_encryption, server_output)
}
