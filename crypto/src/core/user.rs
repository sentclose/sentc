use crate::alg::{asym, pw_hash, sign, sym};
use crate::error::Error;
use crate::{DeriveKeysForAuthOutput, DeriveMasterKeyForAuth, RegisterOutPut, SignK, Sk, SymKey};

pub(crate) fn register(password: String) -> Result<RegisterOutPut, Error>
{
	//1. create aes master key
	let master_key = sym::aes_gcm::generate_key()?;

	//2. create static pub/pri key pair for encrypt and decrypt
	let keypair = asym::ecies::generate_static_keypair();

	//3. create sign key pair for sign and verify
	let sign = sign::ed25519::generate_key_pair()?;

	//4. encrypt the private keys with the master key
	let raw_master_key = match &master_key.key {
		SymKey::Aes(k) => k,
	};

	let private_key = match &keypair.sk {
		Sk::Ecies(k) => k,
	};

	let sign_key = match &sign.sign_key {
		SignK::Ed25519(k) => k,
	};

	let encrypted_private_key = sym::aes_gcm::encrypt_with_generated_key(raw_master_key, private_key)?;
	let encrypted_sign_key = sym::aes_gcm::encrypt_with_generated_key(raw_master_key, sign_key)?;

	//5. derived keys from password
	let derived = pw_hash::argon2::derived_keys_from_password(password.as_bytes(), raw_master_key)?;

	Ok(RegisterOutPut {
		master_key_alg: master_key.alg,
		client_random_value: derived.client_random_value,
		hashed_authentication_key_bytes: derived.hashed_authentication_key_bytes,
		master_key_info: derived.master_key_info,
		derived_alg: derived.alg,
		encrypted_sign_key,
		verify_key: sign.verify_key,
		keypair_sign_alg: sign.alg,
		encrypted_private_key,
		public_key: keypair.pk,
		keypair_encrypt_alg: keypair.alg,
	})
}

pub(crate) fn prepare_login(password: String, salt_string: String, derived_encryption_key: &'static str) -> Result<DeriveKeysForAuthOutput, Error>
{
	//TODO decode the salt string from secure base64
	let salt = base64::decode(salt_string).map_err(|_| Error::DecodeSaltFailed)?;

	//expand the match arm when supporting more alg
	let out = match derived_encryption_key {
		pw_hash::argon2::ARGON_2_OUTPUT => pw_hash::argon2::derive_keys_for_auth(password.as_bytes(), &salt)?,
		_ => return Err(Error::AlgNotFound),
	};

	Ok(out)
}

pub(crate) fn done_login(
	derived_encryption_key: &DeriveMasterKeyForAuth, //the value from prepare_login
	encrypted_master_key: String,                    //as base64 encoded string from the server
	encrypted_private_key: String,
	keypair_encrypt_alg: &'static str,
	encrypted_sign_key: String,
	keypair_sign_alg: &'static str,
) -> Result<String, Error>
{
	//TODO decode the strings from secure base64
	let encrypted_master_key = base64::decode(encrypted_master_key).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_private_key = base64::decode(encrypted_private_key).map_err(|_| Error::DerivedKeyWrongFormat)?;
	let encrypted_sign_key = base64::decode(encrypted_sign_key).map_err(|_| Error::DerivedKeyWrongFormat)?;

	//decrypt the master key from the derived key from password
	let master_key = match derived_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => pw_hash::argon2::get_master_key(k, &encrypted_master_key)?,
	};

	//decrypt the private keys
	let (private, sign) = match master_key {
		SymKey::Aes(k) => {
			let decrypted_private_key = sym::aes_gcm::decrypt_with_generated_key(&k, &encrypted_private_key)?;
			let decrypted_sign_key = sym::aes_gcm::decrypt_with_generated_key(&k, &encrypted_sign_key)?;

			(decrypted_private_key, decrypted_sign_key)
		},
	};

	//decode the private keys to the enums to use them later
	let private_key = match keypair_encrypt_alg {
		asym::ecies::ECIES_OUTPUT => {
			let private = private
				.try_into()
				.map_err(|_| Error::DecodePrivateKeyFailed)?;
			Sk::Ecies(private)
		},
		_ => return Err(Error::AlgNotFound),
	};

	let sign_key = match keypair_sign_alg {
		sign::ed25519::ED25519_OUTPUT => {
			let sign = sign.try_into().map_err(|_| Error::DecodePrivateKeyFailed)?;
			SignK::Ed25519(sign)
		},
		_ => return Err(Error::AlgNotFound),
	};

	Ok(format!("done"))
}

#[cfg(test)]
mod test
{
	use super::*;
	use crate::ClientRandomValue;

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		//register should not panic because we only use internally values!
		let out = register(password.to_string()).unwrap();

		assert_eq!(out.master_key_alg, sym::aes_gcm::AES_GCM_OUTPUT);
		assert_eq!(out.keypair_encrypt_alg, asym::ecies::ECIES_OUTPUT);
		assert_eq!(out.keypair_sign_alg, sign::ed25519::ED25519_OUTPUT);
	}

	#[test]
	fn test_login()
	{
		//the normal register
		let password = "abc*èéöäüê";

		let out = register(password.to_string()).unwrap();

		//and now try to login
		//normally the salt gets calc by the api
		let client_random_value = match out.client_random_value {
			ClientRandomValue::Argon2(v) => v,
		};
		let salt_from_rand_value = pw_hash::argon2::generate_salt(client_random_value);
		let salt_string = base64::encode(salt_from_rand_value); //TODo test here with the secure base64

		let prep_login_out = prepare_login(password.to_string(), salt_string, out.derived_alg).unwrap();

		//try to decrypt the master key
		//prepare the encrypted values (from server in base64 encoded)
		let encrypted_master_key = base64::encode(&out.master_key_info.encrypted_master_key);
		let encrypted_private_key = base64::encode(&out.encrypted_private_key);
		let encrypted_sign_key = base64::encode(&out.encrypted_sign_key);

		let login_out = done_login(
			&prep_login_out.master_key_encryption_key, //the value comes from prepare login
			encrypted_master_key,
			encrypted_private_key,
			out.keypair_encrypt_alg,
			encrypted_sign_key,
			out.keypair_sign_alg,
		)
		.unwrap();

		assert_eq!(login_out, "done");
	}
}
