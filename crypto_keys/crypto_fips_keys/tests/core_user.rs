use std::str::from_utf8;

use sentc_crypto_core::cryptomat::{ClientRandomValue, DeriveMasterKeyForAuth, Pk, SignK, Sk, VerifyK};
use sentc_crypto_core::user::{change_password, done_login, password_reset, prepare_login, register, safety_number, LoginDoneOutput};
use sentc_crypto_fips_keys::core::asym::RsaSk;
use sentc_crypto_fips_keys::core::pw_hash::PwHasherGetter;
use sentc_crypto_fips_keys::core::sign::{Ed25519FIPSSignK, Ed25519FIPSVerifyK};
use sentc_crypto_fips_keys::core::sym::Aes256GcmKey;

#[test]
fn test_register()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let password = "abc*èéöäüê";

	//register should not panic because we only use internally values!
	let _ = register::<Aes256GcmKey, RsaSk, Ed25519FIPSSignK, PwHasherGetter>(password).unwrap();
}

#[test]
fn test_login()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//the normal register
	let password = "abc*èéöäüê";

	let out = register::<Aes256GcmKey, RsaSk, Ed25519FIPSSignK, PwHasherGetter>(password).unwrap();

	//and now try to log in
	//normally the salt gets calc by the api
	let salt_from_rand_value = out.client_random_value.generate_salt("");

	let prep_login_out = prepare_login::<PwHasherGetter>(password, &salt_from_rand_value, out.derived_alg).unwrap();

	//try to decrypt the master key
	let login_out = done_login::<RsaSk, Ed25519FIPSSignK>(
		&prep_login_out.master_key_encryption_key, //the value comes from prepare login
		&out.encrypted_master_key,
		&out.encrypted_private_key,
		out.keypair_encrypt_alg,
		&out.encrypted_sign_key,
		out.keypair_sign_alg,
	)
	.unwrap();

	//try to encrypt / decrypt with the keypair
	let public_key = out.public_key;

	let text = "Hello world üöäéèßê°";
	let encrypted = public_key.encrypt(text.as_bytes()).unwrap();
	let decrypted = login_out.private_key.decrypt(&encrypted).unwrap();
	let decrypted_text = from_utf8(&decrypted).unwrap();

	assert_eq!(decrypted_text, text);

	//try sign and verify
	let verify_key = out.verify_key;

	let data_with_sign = login_out.sign_key.sign(&encrypted).unwrap();
	let (_data, verify_res) = verify_key.verify(&data_with_sign).unwrap();

	assert!(verify_res);
}

#[test]
fn test_pw_change()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//the normal register
	let password = "abc*èéöäüê";
	let new_password = "abcdfg";

	let out = register::<Aes256GcmKey, RsaSk, Ed25519FIPSSignK, PwHasherGetter>(password).unwrap();

	//normally the salt gets calc by the api
	//for all different random value alg
	//classic way here because when generating salt we will move the value, but we need the old salt for pw change and after for comparing the output
	let salt_from_rand_value = out.client_random_value.generate_salt("");

	let pw_change_out = change_password::<PwHasherGetter>(
		password,
		new_password,
		&salt_from_rand_value,
		&out.encrypted_master_key,
		out.derived_alg,
	)
	.unwrap();

	//must be different because it is encrypted by a new password
	assert_ne!(out.encrypted_master_key, pw_change_out.encrypted_master_key);

	//the decrypted master key must be the same
	//first get the master key which was encrypted by the old password
	let prep_login_old = prepare_login::<PwHasherGetter>(password, &salt_from_rand_value, out.derived_alg).unwrap();

	//2nd get the master key which was encrypted by the new password
	let new_salt = pw_change_out.client_random_value.generate_salt("");
	let prep_login_new = prepare_login::<PwHasherGetter>(new_password, &new_salt, pw_change_out.derived_alg).unwrap();

	let key_old = prep_login_old
		.master_key_encryption_key
		.get_master_key(&out.encrypted_master_key)
		.unwrap();
	let key_new = prep_login_new
		.master_key_encryption_key
		.get_master_key(&pw_change_out.encrypted_master_key)
		.unwrap();

	assert_eq!(key_old.as_ref(), key_new.as_ref());
}

#[test]
fn test_password_reset()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let password = "abc*èéöäüê";
	let out = register::<Aes256GcmKey, RsaSk, Ed25519FIPSSignK, PwHasherGetter>(password).unwrap();

	let salt_from_rand_value = out.client_random_value.generate_salt("");

	let prep_login_out = prepare_login::<PwHasherGetter>(password, &salt_from_rand_value, out.derived_alg).unwrap();

	//try to decrypt the master key
	let login_out = done_login::<RsaSk, Ed25519FIPSSignK>(
		&prep_login_out.master_key_encryption_key, //the value comes from prepare login
		&out.encrypted_master_key,
		&out.encrypted_private_key,
		out.keypair_encrypt_alg,
		&out.encrypted_sign_key,
		out.keypair_sign_alg,
	)
	.unwrap();

	//reset the password
	let new_password = "123";

	let password_reset_out = password_reset::<Aes256GcmKey, PwHasherGetter>(new_password, &login_out.private_key, &login_out.sign_key).unwrap();

	//test if we can log in with the new password
	let salt_from_rand_value = password_reset_out.client_random_value.generate_salt("");

	let prep_login_out_pw_reset = prepare_login::<PwHasherGetter>(new_password, &salt_from_rand_value, password_reset_out.derived_alg).unwrap();

	//try to decrypt the master key
	let login_out_pw_reset = done_login::<RsaSk, Ed25519FIPSSignK>(
		&prep_login_out_pw_reset.master_key_encryption_key, //the value comes from prepare login
		&password_reset_out.encrypted_master_key,
		&password_reset_out.encrypted_private_key,
		out.keypair_encrypt_alg,
		&password_reset_out.encrypted_sign_key,
		out.keypair_sign_alg,
	)
	.unwrap();

	assert_ne!(out.encrypted_master_key, password_reset_out.encrypted_master_key);

	assert_eq!(
		login_out.private_key.export().unwrap(),
		login_out_pw_reset.private_key.export().unwrap()
	);
}

fn create_dummy_user_for_safety_number() -> (Ed25519FIPSVerifyK, LoginDoneOutput<RsaSk, Ed25519FIPSSignK>)
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let password = "abc*èéöäüê";
	let out = register::<Aes256GcmKey, RsaSk, Ed25519FIPSSignK, PwHasherGetter>(password).unwrap();

	let salt_from_rand_value = out.client_random_value.generate_salt("");

	let prep_login_out = prepare_login::<PwHasherGetter>(password, &salt_from_rand_value, out.derived_alg).unwrap();

	//try to decrypt the master key
	let login_out = done_login::<RsaSk, Ed25519FIPSSignK>(
		&prep_login_out.master_key_encryption_key, //the value comes from prepare login
		&out.encrypted_master_key,
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
	openssl::provider::Provider::load(None, "fips").unwrap();

	let (user_1_key, _user_1) = create_dummy_user_for_safety_number();
	let (user_2_key, _user_2) = create_dummy_user_for_safety_number();

	let number = safety_number(&user_1_key, "abc", None, None);

	let number_1 = safety_number(&user_1_key, "abc", Some(&user_2_key), Some("abc"));

	let number_2 = safety_number(&user_2_key, "abc", Some(&user_1_key), Some("abc"));

	assert_eq!(number.len(), 32);
	assert_eq!(number_1.len(), 32);
	assert_eq!(number_2.len(), 32);

	assert_ne!(number_1, number_2);
}
