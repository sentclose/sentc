use sentc_crypto::crypto::KeyGenerator;
use sentc_crypto_fips_keys::util::{PublicKey, SignKey, SymmetricKey};
use sentc_crypto_utils::cryptomat::{PkFromUserKeyWrapper, SkCryptoWrapper, SymKeyCrypto};

use crate::sdk_test_fn::{create_group, create_user};

mod sdk_test_fn;

#[test]
fn test_encrypt_decrypt_sym_raw()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let (head, encrypted) = group_key
		.encrypt_raw(text.as_bytes(), None::<&SignKey>)
		.unwrap();

	let decrypted = group_key.decrypt_raw(&encrypted, &head, None).unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_sym_raw_with_sig()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//create a rust dummy user
	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let (head, encrypted) = group_key
		.encrypt_raw(text.as_bytes(), Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = group_key
		.decrypt_raw(&encrypted, &head, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_sym_raw_with_aad()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";
	let payload = b"payload1234567891011121314151617";

	let (head, encrypted) = group_key
		.encrypt_raw_with_aad(text.as_bytes(), payload, None::<&SignKey>)
		.unwrap();

	let decrypted = group_key
		.decrypt_raw_with_aad(&encrypted, payload, &head, None)
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_sym_raw_with_sig_with_aad()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	//create a rust dummy user
	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";
	let payload = b"payload1234567891011121314151617";

	let (head, encrypted) = group_key
		.encrypt_raw_with_aad(text.as_bytes(), payload, Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = group_key
		.decrypt_raw_with_aad(
			&encrypted,
			payload,
			&head,
			Some(&user.user_keys[0].exported_verify_key),
		)
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_asym_raw()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let text = "123*+^êéèüöß@€&$";
	let user = create_user();

	let (head, encrypted) = PublicKey::encrypt_raw_with_user_key(
		&user.user_keys[0].exported_public_key,
		text.as_bytes(),
		None::<&SignKey>,
	)
	.unwrap();

	let decrypted = user.user_keys[0]
		.private_key
		.decrypt_raw(&encrypted, &head, None)
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_asym_raw_with_sig()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let text = "123*+^êéèüöß@€&$";
	let user = create_user();

	let (head, encrypted) = PublicKey::encrypt_raw_with_user_key(
		&user.user_keys[0].exported_public_key,
		text.as_bytes(),
		Some(&user.user_keys[0].sign_key),
	)
	.unwrap();

	let decrypted = &user.user_keys[0]
		.private_key
		.decrypt_raw(&encrypted, &head, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_sym()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = group_key
		.encrypt(text.as_bytes(), None::<&SignKey>)
		.unwrap();

	let decrypted = group_key.decrypt(&encrypted, None).unwrap();

	assert_eq!(text.as_bytes(), decrypted)
}

#[test]
fn test_encrypt_decrypt_sym_with_aad()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	let text = "123*+^êéèüöß@€&$ 👍 🚀";
	let payload = b"payload1234567891011121314151617";

	let encrypted = group_key
		.encrypt_with_aad(text.as_bytes(), payload, None::<&SignKey>)
		.unwrap();

	let decrypted = group_key
		.decrypt_with_aad(&encrypted, payload, None)
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted);
}

#[test]
fn test_encrypt_decrypt_sym_with_wrong_aad()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	let text = "123*+^êéèüöß@€&$ 👍 🚀";
	let payload = b"payload1234567891011121314151617";
	let payload2 = b"payload1234567891011121314151618";

	let encrypted = group_key
		.encrypt_with_aad(text.as_bytes(), payload, None::<&SignKey>)
		.unwrap();

	let decrypted = group_key.decrypt_with_aad(&encrypted, payload2, None);

	match decrypted {
		Err(_e) => {},
		_ => panic!("should be error"),
	}
}

#[test]
fn test_encrypt_decrypt_sym_with_sign()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = group_key
		.encrypt(text.as_bytes(), Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = group_key
		.decrypt(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted)
}

#[test]
fn test_encrypt_decrypt_asym()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = PublicKey::encrypt_with_user_key(
		&user.user_keys[0].exported_public_key,
		text.as_bytes(),
		None::<&SignKey>,
	)
	.unwrap();

	let decrypted = user.user_keys[0]
		.private_key
		.decrypt(&encrypted, None)
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted)
}

#[test]
fn test_encrypt_decrypt_asym_with_sign()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = PublicKey::encrypt_with_user_key(
		&user.user_keys[0].exported_public_key,
		text.as_bytes(),
		Some(&user.user_keys[0].sign_key),
	)
	.unwrap();

	let decrypted = user.user_keys[0]
		.private_key
		.decrypt(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(text.as_bytes(), decrypted)
}

#[test]
fn test_encrypt_decrypt_string_sym()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = group_key.encrypt_string(text, None::<&SignKey>).unwrap();

	let decrypted = group_key.decrypt_string(&encrypted, None).unwrap();

	assert_eq!(text, decrypted)
}

#[test]
fn test_encrypt_decrypt_string_sym_wit_aad()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();
	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	let text = "123*+^êéèüöß@€&$ 👍 🚀";
	let payload = "payload1234567891011121314151617";

	let encrypted = group_key
		.encrypt_string_with_aad(text, payload, None::<&SignKey>)
		.unwrap();

	let decrypted = group_key
		.decrypt_string_with_aad(&encrypted, payload, None)
		.unwrap();

	assert_eq!(text, decrypted);
}

#[test]
fn test_encrypt_decrypt_string_sym_with_sign()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let group_key = &key_data[0].group_key;

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = group_key
		.encrypt_string(text, Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = group_key
		.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(text, decrypted)
}

#[test]
fn test_encrypt_decrypt_string_asym()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = PublicKey::encrypt_string_with_user_key(&user.user_keys[0].exported_public_key, text, None::<&SignKey>).unwrap();

	let decrypted = user.user_keys[0]
		.private_key
		.decrypt_string(&encrypted, None)
		.unwrap();

	assert_eq!(text, decrypted)
}

#[test]
fn test_encrypt_decrypt_string_asym_with_sign()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	//now start encrypt and decrypt with the group master key
	let text = "123*+^êéèüöß@€&$";

	let encrypted = PublicKey::encrypt_string_with_user_key(
		&user.user_keys[0].exported_public_key,
		text,
		Some(&user.user_keys[0].sign_key),
	)
	.unwrap();

	let decrypted = user.user_keys[0]
		.private_key
		.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(text, decrypted)
}

#[test]
fn test_generate_non_register_sym_key()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();
	let (_, key_data, _, _, _) = create_group(&user.user_keys[0]);
	let master_key = &key_data[0].group_key;

	let (key, encrypted_key) = KeyGenerator::<SymmetricKey, SymmetricKey, PublicKey>::generate_non_register_sym_key(master_key).unwrap();

	//test the encrypt / decrypt
	let text = "123*+^êéèüöß@€&$";

	let encrypted = key
		.encrypt_string(text, Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = key
		.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(decrypted, text);

	//check if we can decrypt the key with the master key

	let decrypted_key = KeyGenerator::<SymmetricKey, SymmetricKey, PublicKey>::decrypt_sym_key(master_key, &encrypted_key).unwrap();

	assert_eq!(key.key.as_ref(), decrypted_key.key.as_ref());
}

#[test]
fn test_generate_non_register_sym_key_by_public_key()
{
	openssl::provider::Provider::load(None, "fips").unwrap();

	let user = create_user();

	let (key, encrypted_key) =
		KeyGenerator::<SymmetricKey, SymmetricKey, PublicKey>::generate_non_register_sym_key_by_public_key(&user.user_keys[0].exported_public_key)
			.unwrap();

	//test the encrypt / decrypt
	let text = "123*+^êéèüöß@€&$";

	let encrypted = key
		.encrypt_string(text, Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = key
		.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(decrypted, text);

	//check if we can decrypt the key with the master key

	let decrypted_key =
		KeyGenerator::<SymmetricKey, SymmetricKey, PublicKey>::decrypt_sym_key_by_private_key(&user.user_keys[0].private_key, &encrypted_key)
			.unwrap();

	let text = "123*+^êéèüöß@€&$";

	let encrypted = decrypted_key
		.encrypt_string(text, Some(&user.user_keys[0].sign_key))
		.unwrap();

	let decrypted = decrypted_key
		.decrypt_string(&encrypted, Some(&user.user_keys[0].exported_verify_key))
		.unwrap();

	assert_eq!(decrypted, text);

	assert_eq!(key.key.as_ref(), decrypted_key.key.as_ref());
}
