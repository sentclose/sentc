#![no_std]

extern crate alloc;

use alloc::vec;
use core::str::from_utf8;

use sentc_crypto_core::cryptomat::{ClientRandomValue, Pk, Sk, SymKey};
use sentc_crypto_core::group::{done_key_rotation, get_group, key_rotation, prepare_create, prepare_group_keys_for_new_member};
use sentc_crypto_core::user::{done_login, prepare_login, register, LoginDoneOutput};
use sentc_crypto_std_keys::core::{HmacKey, PwHasherGetter, SecretKey, SignKey, SortKeys, SymmetricKey};

fn create_dummy_user() -> (impl Pk, LoginDoneOutput<SecretKey, SignKey>)
{
	let password = "12345";

	//create a test user
	let register_out = register::<SymmetricKey, SecretKey, SignKey, PwHasherGetter>(password).unwrap();

	//and now try to log in
	//normally the salt gets calc by the api
	let salt_from_rand_value = register_out.client_random_value.generate_salt("");

	let prep_login_out = prepare_login::<PwHasherGetter>(password, &salt_from_rand_value, register_out.derived_alg).unwrap();

	//try to decrypt the master key
	let login_out = done_login::<SecretKey, SignKey>(
		&prep_login_out.master_key_encryption_key, //the value comes from prepare login
		&register_out.encrypted_master_key,
		&register_out.encrypted_private_key,
		register_out.keypair_encrypt_alg,
		&register_out.encrypted_sign_key,
		register_out.keypair_sign_alg,
	)
	.unwrap();

	(register_out.public_key, login_out)
}

#[test]
fn test_group_creation()
{
	let (pk, login_out) = create_dummy_user();

	let group_out = prepare_create::<SymmetricKey, SecretKey, SignKey, HmacKey, SortKeys>(&pk, false).unwrap();
	let created_key = group_out.1;
	let group_out = group_out.0;

	//decrypt the group key
	let (group_key, group_pri_key) = get_group::<SymmetricKey, SecretKey>(
		&login_out.private_key,
		&group_out.encrypted_group_key,
		&group_out.encrypted_private_group_key,
		group_out.group_key_alg,
		group_out.keypair_encrypt_alg,
	)
	.unwrap();

	//test encrypt / decrypt
	let text = "abc 12345 üöä*#+^°êéè";

	let encrypted = group_key.encrypt(text.as_bytes()).unwrap();
	let decrypted = group_key.decrypt(&encrypted).unwrap();

	assert_eq!(decrypted, text.as_bytes());

	//test decrypt with group returned group key after create
	let encrypted = created_key.encrypt(text.as_bytes()).unwrap();
	let decrypted = created_key.decrypt(&encrypted).unwrap();

	assert_eq!(decrypted, text.as_bytes());

	let decrypted_text = from_utf8(&decrypted).unwrap();
	assert_eq!(decrypted_text, text);

	let encrypted_pri = group_out.public_group_key.encrypt(text.as_bytes()).unwrap();
	let decrypted_pri = group_pri_key.decrypt(&encrypted_pri).unwrap();

	assert_eq!(decrypted_pri, text.as_bytes());

	let decrypted_text = from_utf8(&decrypted_pri).unwrap();
	assert_eq!(decrypted_text, text);
}

#[test]
fn test_key_rotation()
{
	let (pk, login_out) = create_dummy_user();

	let group_out = prepare_create::<SymmetricKey, SecretKey, SignKey, HmacKey, SortKeys>(&pk, false)
		.unwrap()
		.0;

	//decrypt the group key
	let (group_key, _group_pri_key) = get_group::<SymmetricKey, SecretKey>(
		&login_out.private_key,
		&group_out.encrypted_group_key,
		&group_out.encrypted_private_group_key,
		group_out.group_key_alg,
		group_out.keypair_encrypt_alg,
	)
	.unwrap();

	let rotation_out = key_rotation::<SymmetricKey, SecretKey, SignKey>(&group_key, &pk, false).unwrap();

	//it should get the values from own encrypted group key
	let (new_group_key, _new_group_pri_key) = get_group::<SymmetricKey, SecretKey>(
		&login_out.private_key,
		&rotation_out.encrypted_group_key_by_user,
		&rotation_out.encrypted_private_group_key,
		rotation_out.group_key_alg,
		rotation_out.keypair_encrypt_alg,
	)
	.unwrap();

	assert_ne!(group_key.as_ref(), new_group_key.as_ref());

	//do the server key rotation
	//executed on the server not the client. the client invokes done_key_rotation after
	//1. encrypt the encrypted ephemeral key with the public key
	//2. save this key in the db
	let encrypted_ephemeral_key_by_group_key_and_public_key = pk.encrypt(&rotation_out.encrypted_ephemeral_key).unwrap();

	//the encrypted_group_key_by_ephemeral is for everyone the same because this is encrypted by the previous group key

	//done key rotation to get the new group key
	let out = done_key_rotation::<SymmetricKey>(
		&login_out.private_key,
		&pk,
		&group_key,
		&encrypted_ephemeral_key_by_group_key_and_public_key,
		&rotation_out.encrypted_group_key_by_ephemeral,
		rotation_out.ephemeral_alg,
	)
	.unwrap();

	//get the new group by get_group
	let (new_group_key2, _new_group_pri_key2) = get_group::<SymmetricKey, SecretKey>(
		&login_out.private_key,
		&out,
		&rotation_out.encrypted_private_group_key,
		rotation_out.group_key_alg,
		rotation_out.keypair_encrypt_alg,
	)
	.unwrap();

	assert_eq!(new_group_key.as_ref(), new_group_key2.as_ref());
	assert_ne!(group_key.as_ref(), new_group_key2.as_ref());
}

#[test]
fn test_accept_join_req()
{
	let (user_1_pk, user_1_out) = create_dummy_user();
	let (user_2_pk, user_2_out) = create_dummy_user();

	let group_out = prepare_create::<SymmetricKey, SecretKey, SignKey, HmacKey, SortKeys>(&user_1_pk, false)
		.unwrap()
		.0;
	let (group_key, _group_pri_key) = get_group::<SymmetricKey, SecretKey>(
		&user_1_out.private_key,
		&group_out.encrypted_group_key,
		&group_out.encrypted_private_group_key,
		group_out.group_key_alg,
		group_out.keypair_encrypt_alg,
	)
	.unwrap();

	//create multiple group keys
	let rotation_out = key_rotation::<SymmetricKey, SecretKey, SignKey>(&group_key, &user_1_pk, false).unwrap();
	let (new_group_key, _new_group_pri_key) = get_group::<SymmetricKey, SecretKey>(
		&user_1_out.private_key,
		&rotation_out.encrypted_group_key_by_user,
		&rotation_out.encrypted_private_group_key,
		rotation_out.group_key_alg,
		rotation_out.keypair_encrypt_alg,
	)
	.unwrap();

	let rotation_out_1 = key_rotation::<SymmetricKey, SecretKey, SignKey>(&new_group_key, &user_1_pk, false).unwrap();
	let (new_group_key_1, _new_group_pri_key_1) = get_group::<SymmetricKey, SecretKey>(
		&user_1_out.private_key,
		&rotation_out_1.encrypted_group_key_by_user,
		&rotation_out_1.encrypted_private_group_key,
		rotation_out_1.group_key_alg,
		rotation_out_1.keypair_encrypt_alg,
	)
	.unwrap();

	let rotation_out_2 = key_rotation::<SymmetricKey, SecretKey, SignKey>(&new_group_key_1, &user_1_pk, false).unwrap();
	let (new_group_key_2, _new_group_pri_key_2) = get_group::<SymmetricKey, SecretKey>(
		&user_1_out.private_key,
		&rotation_out_2.encrypted_group_key_by_user,
		&rotation_out_2.encrypted_private_group_key,
		rotation_out_2.group_key_alg,
		rotation_out_2.keypair_encrypt_alg,
	)
	.unwrap();

	//now do the accept join req
	//put all group keys into a vec
	let group_keys = vec![&group_key, &new_group_key, &new_group_key_1, &new_group_key_2];

	let new_user_out = prepare_group_keys_for_new_member(&user_2_pk, &group_keys).unwrap();

	//try to get group from the 2nd user
	//can't use loop here because we need to know which group key we are actual processing
	let group_key_2 = &new_user_out[1];

	let (new_user_group_key_2, _new_user_group_pri_key_2) = get_group::<SymmetricKey, SecretKey>(
		&user_2_out.private_key,
		&group_key_2.encrypted_group_key,
		&rotation_out.encrypted_private_group_key, //normally get from the server
		rotation_out.group_key_alg,
		rotation_out.keypair_encrypt_alg,
	)
	.unwrap();

	assert_eq!(new_group_key.as_ref(), new_user_group_key_2.as_ref());

	let group_key_3 = &new_user_out[2];

	let (new_user_group_key_3, _new_user_group_pri_key_3) = get_group::<SymmetricKey, SecretKey>(
		&user_2_out.private_key,
		&group_key_3.encrypted_group_key,
		&rotation_out_1.encrypted_private_group_key, //normally get from the server
		rotation_out_1.group_key_alg,
		rotation_out_1.keypair_encrypt_alg,
	)
	.unwrap();

	assert_eq!(new_group_key_1.as_ref(), new_user_group_key_3.as_ref());
}
