use crate::user::{change_password_internally, done_login_internally, prepare_login_internally, register_internally};
use crate::{DeriveMasterKeyForAuth, DoneLoginOutput, Error};

pub fn register(password: String) -> Result<String, Error>
{
	register_internally(password)
}

pub fn prepare_login(password: String, salt_string: String, derived_encryption_key_alg: String) -> Result<(String, DeriveMasterKeyForAuth), Error>
{
	prepare_login_internally(password, salt_string, derived_encryption_key_alg)
}

pub fn done_login(master_key_encryption: &DeriveMasterKeyForAuth, server_output: String) -> Result<DoneLoginOutput, Error>
{
	done_login_internally(&master_key_encryption, server_output)
}

pub fn change_password(
	old_pw: String,
	new_pw: String,
	old_salt: String,
	encrypted_master_key: String,
	derived_encryption_key_alg: String,
) -> Result<String, Error>
{
	change_password_internally(old_pw, new_pw, old_salt, encrypted_master_key, derived_encryption_key_alg)
}

#[cfg(test)]
mod test
{
	use super::*;

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		let out = register(password.to_string()).unwrap();

		println!("rust: {}", out);
	}
}
