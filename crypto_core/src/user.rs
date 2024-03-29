use alloc::vec::Vec;

use crate::alg::{asym, pw_hash, sign, sym};
use crate::error::Error;
use crate::{
	decrypt_private_key,
	decrypt_sign_key,
	ClientRandomValue,
	DeriveAuthKeyForAuth,
	DeriveKeysForAuthOutput,
	DeriveMasterKeyForAuth,
	HashedAuthenticationKey,
	MasterKeyInfo,
	Pk,
	SafetyNumber,
	Sig,
	SignK,
	Sk,
	SymKey,
	VerifyK,
};

pub struct RegisterOutPut
{
	//info about the raw master key (not the encrypted by the password!)
	pub master_key_alg: &'static str,

	//from key derived
	pub client_random_value: ClientRandomValue,
	pub hashed_authentication_key_bytes: HashedAuthenticationKey,
	pub master_key_info: MasterKeyInfo,
	pub derived_alg: &'static str,

	//the key pairs incl. the encrypted secret keys
	pub public_key: Pk,
	pub encrypted_private_key: Vec<u8>,
	pub keypair_encrypt_alg: &'static str,
	pub verify_key: VerifyK,
	pub encrypted_sign_key: Vec<u8>,
	pub keypair_sign_alg: &'static str,
}

pub struct LoginDoneOutput
{
	pub private_key: Sk,
	pub sign_key: SignK,
}

pub struct ChangePasswordOutput
{
	pub client_random_value: ClientRandomValue,
	pub hashed_authentication_key_bytes: HashedAuthenticationKey,
	pub master_key_info: MasterKeyInfo,
	pub derived_alg: &'static str,
	pub old_auth_key: DeriveAuthKeyForAuth,
}

pub struct ResetPasswordOutput
{
	pub master_key_alg: &'static str,
	pub client_random_value: ClientRandomValue,
	pub hashed_authentication_key_bytes: HashedAuthenticationKey,
	pub master_key_info: MasterKeyInfo,
	pub derived_alg: &'static str,
	pub encrypted_private_key: Vec<u8>,
	pub encrypted_sign_key: Vec<u8>,
}

#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
fn register_argon2_aes_ecies_ed25519(password: &str) -> Result<RegisterOutPut, Error>
{
	//1. create aes master key
	let master_key = sym::aes_gcm::generate_key()?;

	//2. create static pub/pri key pair for encrypt and decrypt
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	let keypair = asym::ecies::generate_static_keypair();

	#[cfg(feature = "argon2_aes_ecies_ed25519_kyber_hybrid")]
	let keypair = asym::ecies_kyber_hybrid::generate_static_keypair()?;

	//3. create sign key pair for sign and verify
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	let sign = sign::ed25519::generate_key_pair()?;

	#[cfg(feature = "argon2_aes_ecies_ed25519_kyber_hybrid")]
	let sign = sign::ed25519_dilithium_hybrid::generate_key_pair()?;

	//4. encrypt the private keys with the master key
	let raw_master_key = match &master_key.key {
		SymKey::Aes(k) => k,
	};

	let encrypted_private_key = match &keypair.sk {
		Sk::Ecies(k) => sym::aes_gcm::encrypt_with_generated_key(raw_master_key, k)?,
		Sk::Kyber(k) => sym::aes_gcm::encrypt_with_generated_key(raw_master_key, k)?,
		Sk::EciesKyberHybrid {
			x,
			k,
		} => {
			let private_key = [&x[..], k].concat();

			sym::aes_gcm::encrypt_with_generated_key(raw_master_key, &private_key)?
		},
	};

	let encrypted_sign_key = match &sign.sign_key {
		SignK::Ed25519(k) => sym::aes_gcm::encrypt_with_generated_key(raw_master_key, k)?,
		SignK::Dilithium(k) => sym::aes_gcm::encrypt_with_generated_key(raw_master_key, k)?,
		SignK::Ed25519DilithiumHybrid {
			x,
			k,
		} => {
			let private_key = [&x[..], k].concat();

			sym::aes_gcm::encrypt_with_generated_key(raw_master_key, &private_key)?
		},
	};

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

/**
# register a new user

Every user got a master key, every other user key is encrypted by this master key.

The master key is encrypted by a derived key from password. The password turned into two different keys via a password hash.
The first key is the derived key and encrypts the master key. The second key is the authentication for the server.
Only this key gets send to the server not the password.

A public / private encryption key pair and a sign / verify key pair get created too.

Both private and sign key gets encrypted by the master key.

<br>

## For key update:
Just register the user again with a password, it should be the same password for usability but it can a different password too.
Then login again and encrypt everything what was encrypt by the old keys with the new keys
(e.g. group keys (encrypted by public key), or direct encrypted data).
*/
pub fn register(password: &str) -> Result<RegisterOutPut, Error>
{
	//define at register which alg should be used, but support all other alg in the other functions

	#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
	register_argon2_aes_ecies_ed25519(password)
}

/**
# Start the login process

The salt was generated by the server when the user first interact with the server.
*/
pub fn prepare_login(password: &str, salt: &[u8], derived_encryption_key_alg: &str) -> Result<DeriveKeysForAuthOutput, Error>
{
	//expand the match arm when supporting more alg
	let out = match derived_encryption_key_alg {
		pw_hash::argon2::ARGON_2_OUTPUT => pw_hash::argon2::derive_keys_for_auth(password.as_bytes(), salt)?,
		_ => return Err(Error::AlgNotFound),
	};

	Ok(out)
}

/**
# End the login process

Get all information about the current used login keys
*/
pub fn done_login(
	derived_encryption_key: &DeriveMasterKeyForAuth, //the value from prepare_login
	encrypted_master_key: &[u8],                     //as base64 encoded string from the server
	encrypted_private_key: &[u8],
	keypair_encrypt_alg: &str,
	encrypted_sign_key: &[u8],
	keypair_sign_alg: &str,
) -> Result<LoginDoneOutput, Error>
{
	//decrypt the master key from the derived key from password
	let master_key = match derived_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => pw_hash::argon2::get_master_key(k, encrypted_master_key)?,
	};

	//decode the private keys to the enums to use them later
	let private_key = decrypt_private_key(encrypted_private_key, &master_key, keypair_encrypt_alg)?;
	let sign_key = decrypt_sign_key(encrypted_sign_key, &master_key, keypair_sign_alg)?;

	Ok(LoginDoneOutput {
		private_key,
		sign_key,
	})
}

/**
# Prepare Password change

before calling this function make a request to the login api endpoint with the username
to get the salt from the api
if the old pw was wrong this will checked in the api later after this function function

get the old auth key from @see prepare_login()
with the old pw and the old salt

decrypt the master key with the old pw (because it is stored in the client but encrypted)

use the function @see derivedKeysFromPassword with the new pw and the decrypted master key
to create the new client random value, the new encrypted master key and the new hashed authkey

send the return data back to the server
*/
pub fn change_password(
	old_pw: &str,
	new_pw: &str,
	old_salt: &[u8],
	encrypted_master_key: &[u8],
	derived_encryption_key_alg: &str,
) -> Result<ChangePasswordOutput, Error>
{
	//first make a request to login endpoint -> prepareLogin() with the username to get the salt
	//get the old auth key
	let prepare_login_output = prepare_login(old_pw, old_salt, derived_encryption_key_alg)?;

	//decrypt the master key with the old pw.
	let master_key = match &prepare_login_output.master_key_encryption_key {
		DeriveMasterKeyForAuth::Argon2(k) => pw_hash::argon2::get_master_key(k, encrypted_master_key)?,
	};

	//encrypt the master key with the new pw and create a new salt with a new random value
	//the 2nd check is necessary because master key from different alg can have different length
	let derived = match master_key {
		SymKey::Aes(raw_master_key) => pw_hash::argon2::derived_keys_from_password(new_pw.as_bytes(), &raw_master_key)?,
	};

	Ok(ChangePasswordOutput {
		derived_alg: derived.alg,
		client_random_value: derived.client_random_value,
		hashed_authentication_key_bytes: derived.hashed_authentication_key_bytes,
		master_key_info: derived.master_key_info,
		old_auth_key: prepare_login_output.auth_key,
	})
}

#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
fn password_reset_argon2_aes_ecies_ed25519(new_pw: &str, decrypted_private_key: &Sk, decrypted_sign_key: &SignK)
	-> Result<ResetPasswordOutput, Error>
{
	//1. create a new master key (because the old key was encrypted by the forgotten password and can't be restored)
	let master_key = sym::aes_gcm::generate_key()?;

	//2. encrypt the private and the sign key with the new master key
	let encrypted_private_key = match decrypted_private_key {
		Sk::Ecies(k) => sym::aes_gcm::encrypt(&master_key.key, k)?,
		Sk::Kyber(k) => sym::aes_gcm::encrypt(&master_key.key, k)?,
		Sk::EciesKyberHybrid {
			x,
			k,
		} => {
			let private_key = [&x[..], k].concat();

			sym::aes_gcm::encrypt(&master_key.key, &private_key)?
		},
	};

	let encrypted_sign_key = match decrypted_sign_key {
		SignK::Ed25519(k) => sym::aes_gcm::encrypt(&master_key.key, k)?,
		SignK::Dilithium(k) => sym::aes_gcm::encrypt(&master_key.key, k)?,
		SignK::Ed25519DilithiumHybrid {
			x,
			k,
		} => {
			let private_key = [&x[..], k].concat();

			sym::aes_gcm::encrypt(&master_key.key, &private_key)?
		},
	};

	//3. encrypt the new master key with the new password
	let raw_master_key = match &master_key.key {
		SymKey::Aes(k) => k,
	};

	let derived = pw_hash::argon2::derived_keys_from_password(new_pw.as_bytes(), raw_master_key)?;

	Ok(ResetPasswordOutput {
		master_key_alg: master_key.alg,
		client_random_value: derived.client_random_value,
		hashed_authentication_key_bytes: derived.hashed_authentication_key_bytes,
		master_key_info: derived.master_key_info,
		derived_alg: derived.alg,
		encrypted_private_key,
		encrypted_sign_key,
	})
}

/**
# Reset the users password

Only works if the user has still access to the decrypted private key and the decrypted sign key (which are encrypted by the old password).

1. create a new master key like register()
2. encrypt the private and sign keys with the new master key. Use here the alg from the actual selected feature
3. finally encrypt the new master key by the new password

## Security hint:
- the server still awaits a valid auth token when sending the reset password request
- an attacker needs access to the decrypted private key, decrypted sign key and the auth token
*/
pub fn password_reset(new_pw: &str, decrypted_private_key: &Sk, decrypted_sign_key: &SignK) -> Result<ResetPasswordOutput, Error>
{
	#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
	password_reset_argon2_aes_ecies_ed25519(new_pw, decrypted_private_key, decrypted_sign_key)
}

/**
Creates a safety number in byte of a given verify key and additional user information like the user id or user name.

## combined number

To create a combination of two identities set for user_2 another SafetyNumberUser struct.
Make sure to keep the order of user_1 and user_2 on the other user too, otherwise the number will not be the same.
*/
pub fn safety_number(user_1: SafetyNumber, user_2: Option<SafetyNumber>) -> Vec<u8>
{
	sign::safety_number(user_1, user_2)
}

/**
Verify a user public key, which was signed by the user group.

The verify key must be from the user group
*/
pub fn verify_user_public_key(verify_key: &VerifyK, sig: &Sig, public_key: &Pk) -> Result<bool, Error>
{
	match public_key {
		Pk::Ecies(pk) => crate::crypto::verify_only(verify_key, sig, pk),
		Pk::Kyber(pk) => crate::crypto::verify_only(verify_key, sig, pk),
		Pk::EciesKyberHybrid {
			x,
			k,
		} => crate::crypto::verify_only(verify_key, sig, &[&x[..], &k[..]].concat()),
	}
}

#[cfg(test)]
mod test
{
	use core::str::from_utf8;

	use super::*;
	use crate::crypto::{decrypt_asymmetric, encrypt_asymmetric, sign, verify};
	use crate::{generate_salt, ClientRandomValue};

	#[test]
	fn test_register()
	{
		let password = "abc*èéöäüê";

		//register should not panic because we only use internally values!
		let out = register(password).unwrap();

		#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
		assert_eq!(out.master_key_alg, sym::aes_gcm::AES_GCM_OUTPUT);
		#[cfg(feature = "argon2_aes_ecies_ed25519")]
		assert_eq!(out.keypair_encrypt_alg, asym::ecies::ECIES_OUTPUT);
		#[cfg(feature = "argon2_aes_ecies_ed25519")]
		assert_eq!(out.keypair_sign_alg, sign::ed25519::ED25519_OUTPUT);

		#[cfg(feature = "argon2_aes_ecies_ed25519_kyber_hybrid")]
		assert_eq!(
			out.keypair_encrypt_alg,
			asym::ecies_kyber_hybrid::ECIES_KYBER_HYBRID_OUTPUT
		);

		#[cfg(feature = "argon2_aes_ecies_ed25519_kyber_hybrid")]
		assert_eq!(
			out.keypair_sign_alg,
			sign::ed25519_dilithium_hybrid::ED25519_DILITHIUM_HYBRID_OUTPUT
		);
	}

	#[test]
	fn test_login()
	{
		//the normal register
		let password = "abc*èéöäüê";

		let out = register(password).unwrap();

		//and now try to login
		//normally the salt gets calc by the api
		let salt_from_rand_value = generate_salt(out.client_random_value, "");

		let prep_login_out = prepare_login(password, &salt_from_rand_value, out.derived_alg).unwrap();

		//try to decrypt the master key
		let login_out = done_login(
			&prep_login_out.master_key_encryption_key, //the value comes from prepare login
			&out.master_key_info.encrypted_master_key,
			&out.encrypted_private_key,
			out.keypair_encrypt_alg,
			&out.encrypted_sign_key,
			out.keypair_sign_alg,
		)
		.unwrap();

		//try encrypt / decrypt with the keypair
		let public_key = out.public_key;

		let text = "Hello world üöäéèßê°";
		let encrypted = encrypt_asymmetric(&public_key, text.as_bytes()).unwrap();
		let decrypted = decrypt_asymmetric(&login_out.private_key, &encrypted).unwrap();
		let decrypted_text = from_utf8(&decrypted).unwrap();

		assert_eq!(decrypted_text, text);

		//try sign and verify
		let verify_key = out.verify_key;

		let data_with_sign = sign(&login_out.sign_key, &encrypted).unwrap();
		let (_data, verify_res) = verify(&verify_key, &data_with_sign).unwrap();

		assert!(verify_res);
	}

	#[test]
	fn test_pw_change()
	{
		//the normal register
		let password = "abc*èéöäüê";
		let new_password = "abcdfg";

		let out = register(password).unwrap();

		//normally the salt gets calc by the api
		let salt_from_rand_value = match out.client_random_value {
			//for all different random value alg
			//classic way here because when generating salt we will move the value, but we need the old salt for pw change and after for comparing the output
			ClientRandomValue::Argon2(v) => pw_hash::argon2::generate_salt(v, ""),
		};

		let pw_change_out = change_password(
			password,
			new_password,
			&salt_from_rand_value,
			&out.master_key_info.encrypted_master_key,
			out.derived_alg,
		)
		.unwrap();

		match (&out.client_random_value, &pw_change_out.client_random_value) {
			(ClientRandomValue::Argon2(client_random_value), ClientRandomValue::Argon2(new_rand)) => {
				assert_ne!(*client_random_value, *new_rand);
			},
		}

		//must be different because it is encrypted by a new password
		assert_ne!(
			out.master_key_info.encrypted_master_key,
			pw_change_out.master_key_info.encrypted_master_key
		);

		//the decrypted master key must be the same
		//first get the master key which was encrypted by the old password
		let prep_login_old = prepare_login(password, &salt_from_rand_value, out.derived_alg).unwrap();

		//2nd get the master key which was encrypted by the new password
		let new_salt = generate_salt(pw_change_out.client_random_value, "");
		let prep_login_new = prepare_login(new_password, &new_salt, pw_change_out.derived_alg).unwrap();

		match (
			&prep_login_old.master_key_encryption_key,
			&prep_login_new.master_key_encryption_key,
		) {
			(DeriveMasterKeyForAuth::Argon2(k1), DeriveMasterKeyForAuth::Argon2(k2)) => {
				let old_master_key = pw_hash::argon2::get_master_key(k1, &out.master_key_info.encrypted_master_key).unwrap();
				let new_master_key = pw_hash::argon2::get_master_key(k2, &pw_change_out.master_key_info.encrypted_master_key).unwrap();

				match (old_master_key, new_master_key) {
					(SymKey::Aes(km1), SymKey::Aes(km2)) => {
						assert_eq!(km1, km2);
					},
				}
			},
		}
	}

	#[test]
	fn test_password_reset()
	{
		let password = "abc*èéöäüê";
		let out = register(password).unwrap();

		let salt_from_rand_value = generate_salt(out.client_random_value, "");

		let prep_login_out = prepare_login(password, &salt_from_rand_value, out.derived_alg).unwrap();

		//try to decrypt the master key
		let login_out = done_login(
			&prep_login_out.master_key_encryption_key, //the value comes from prepare login
			&out.master_key_info.encrypted_master_key,
			&out.encrypted_private_key,
			out.keypair_encrypt_alg,
			&out.encrypted_sign_key,
			out.keypair_sign_alg,
		)
		.unwrap();

		//reset the password
		let new_password = "123";

		let password_reset_out = password_reset(new_password, &login_out.private_key, &login_out.sign_key).unwrap();

		//test if we can login with the new password
		let salt_from_rand_value = generate_salt(password_reset_out.client_random_value, "");

		let prep_login_out_pw_reset = prepare_login(new_password, &salt_from_rand_value, password_reset_out.derived_alg).unwrap();

		//try to decrypt the master key
		let login_out_pw_reset = done_login(
			&prep_login_out_pw_reset.master_key_encryption_key, //the value comes from prepare login
			&password_reset_out.master_key_info.encrypted_master_key,
			&password_reset_out.encrypted_private_key,
			out.keypair_encrypt_alg,
			&password_reset_out.encrypted_sign_key,
			out.keypair_sign_alg,
		)
		.unwrap();

		assert_ne!(
			out.master_key_info.encrypted_master_key,
			password_reset_out.master_key_info.encrypted_master_key
		);

		match (login_out.private_key, login_out_pw_reset.private_key) {
			(Sk::Ecies(pk), Sk::Ecies(pk2)) => {
				assert_eq!(pk, pk2);
			},
			(Sk::Kyber(pk), Sk::Kyber(pk2)) => {
				assert_eq!(pk, pk2);
			},
			(
				Sk::EciesKyberHybrid {
					x,
					k,
				},
				Sk::EciesKyberHybrid {
					x: x1,
					k: k1,
				},
			) => {
				assert_eq!(x, x1);
				assert_eq!(k, k1);
			},
			_ => panic!("Keys not the same format"),
		}
	}

	fn create_dummy_user_for_safety_number() -> (VerifyK, LoginDoneOutput)
	{
		let password = "abc*èéöäüê";
		let out = register(password).unwrap();

		let salt_from_rand_value = generate_salt(out.client_random_value, "");

		let prep_login_out = prepare_login(password, &salt_from_rand_value, out.derived_alg).unwrap();

		//try to decrypt the master key
		let login_out = done_login(
			&prep_login_out.master_key_encryption_key, //the value comes from prepare login
			&out.master_key_info.encrypted_master_key,
			&out.encrypted_private_key,
			out.keypair_encrypt_alg,
			&out.encrypted_sign_key,
			out.keypair_sign_alg,
		)
		.unwrap();

		(out.verify_key, login_out)
	}

	#[test]
	fn test_safety_number()
	{
		let (user_1_key, _user_1) = create_dummy_user_for_safety_number();
		let (user_2_key, _user_2) = create_dummy_user_for_safety_number();

		let number = safety_number(
			SafetyNumber {
				verify_key: &user_1_key,
				user_info: "abc",
			},
			None,
		);

		let number_1 = safety_number(
			SafetyNumber {
				verify_key: &user_1_key,
				user_info: "abc",
			},
			Some(SafetyNumber {
				verify_key: &user_2_key,
				user_info: "abc",
			}),
		);

		let number_2 = safety_number(
			SafetyNumber {
				verify_key: &user_2_key,
				user_info: "abc",
			},
			Some(SafetyNumber {
				verify_key: &user_1_key,
				user_info: "abc",
			}),
		);

		assert_eq!(number.len(), 32);
		assert_eq!(number_1.len(), 32);
		assert_eq!(number_2.len(), 32);

		assert_ne!(number_1, number_2);
	}
}
