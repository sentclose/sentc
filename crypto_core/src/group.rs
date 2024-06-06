use alloc::vec::Vec;

use crate::alg::{asym, hmac, sign, sortable, sym};
use crate::cryptomat::{CryptoAlg, Pk, SearchableKey, SignK, Sk, SortableKey, SymKey};
use crate::{Error, PublicKey, SecretKey, Signature, SymmetricKey, VerifyKey};

pub struct CreateGroupOutput
{
	pub encrypted_group_key: Vec<u8>,          //encrypted by creators public key
	pub group_key_alg: &'static str,           //info about the raw master key (not the encrypted by the pk!)
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: PublicKey,
	pub keypair_encrypt_alg: &'static str,
	pub encrypted_hmac_key: Vec<u8>,
	pub encrypted_hmac_alg: &'static str,
	pub encrypted_sortable_key: Vec<u8>,
	pub encrypted_sortable_key_alg: &'static str,

	//for user group
	pub verify_key: Option<VerifyKey>,
	pub encrypted_sign_key: Option<Vec<u8>>,
	pub keypair_sign_alg: Option<&'static str>,
	pub public_key_sig: Option<Signature>,
}

pub struct KeyRotationOutput
{
	pub encrypted_group_key_by_user: Vec<u8>, //encrypted by invoker public key
	pub group_key_alg: &'static str,
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk from the invoker (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: PublicKey,
	pub keypair_encrypt_alg: &'static str,
	pub encrypted_group_key_by_ephemeral: Vec<u8>,
	pub ephemeral_alg: &'static str,
	pub encrypted_ephemeral_key: Vec<u8>, //encrypted by the previous_group_key group key. encrypt this key with every other member public key on the server

	//for user group
	pub verify_key: Option<VerifyKey>,
	pub encrypted_sign_key: Option<Vec<u8>>,
	pub keypair_sign_alg: Option<&'static str>,
	pub public_key_sig: Option<Signature>,
}

pub struct PrepareGroupKeysForNewMemberOutput
{
	pub alg: &'static str,
	pub encrypted_group_key: Vec<u8>,
	pub encrypted_group_key_alg: &'static str,
}

#[allow(clippy::type_complexity)]
fn prepare_keys<P: Pk, S: SymKey, Gsk: Sk, Gpk: Pk>(
	creators_public_key: &P,
	user_group: bool,
	group_key: &S,
	group_sk: &Gsk,
	group_pk: &Gpk,
) -> Result<
	(
		Vec<u8>,
		Vec<u8>,
		&'static str,
		Option<VerifyKey>,
		Option<Vec<u8>>,
		Option<Signature>,
		Option<&'static str>,
	),
	Error,
>
{
	let encrypted_private_group_key = group_sk.encrypt_by_master_key(group_key)?;

	let encrypted_group_key = group_key.encrypt_key_with_master_key(creators_public_key)?;

	let (verify_key, encrypted_sign_key, public_key_sig, keypair_sign_alg) = if !user_group {
		(None, None, None, None)
	} else {
		let (sign_key, verify_key) = sign::generate_keys()?;

		let encrypted_sign_key = sign_key.encrypt_by_master_key(group_key)?;

		let public_key_sig = group_pk.sign_public_key(&sign_key)?.into();

		(
			Some(verify_key.into()),
			Some(encrypted_sign_key),
			Some(public_key_sig),
			Some(sign_key.get_alg_str()),
		)
	};

	Ok((
		encrypted_private_group_key,
		encrypted_group_key,
		creators_public_key.get_alg_str(),
		verify_key,
		encrypted_sign_key,
		public_key_sig,
		keypair_sign_alg,
	))
}

pub fn prepare_create<P: Pk>(creators_public_key: &P, user_group: bool) -> Result<(CreateGroupOutput, impl SymKey), Error>
{
	//1. create the keys:
	//	1. master symmetric key
	//	2. pub / pri keys

	let group_key = sym::generate_key()?;

	let (sk, pk) = asym::generate_keys()?;

	let (encrypted_private_group_key, encrypted_group_key, encrypted_group_key_alg, verify_key, encrypted_sign_key, public_key_sig, keypair_sign_alg) =
		prepare_keys(creators_public_key, user_group, &group_key, &sk, &pk)?;

	/*
	create the searchable encryption hmac key and encrypt it with the group key

	create it only for create group not key rotation
	 because when searching an item we don't know what key was used for the item
	 */

	//3. get the hmac key
	let searchable_encryption = hmac::generate_key()?;
	let encrypted_hmac_key = searchable_encryption.encrypt_key_with_master_key(&group_key)?;

	let sortable_encryption = sortable::generate_key()?;
	let encrypted_sortable_key = sortable_encryption.encrypt_key_with_master_key(&group_key)?;

	Ok((
		CreateGroupOutput {
			encrypted_group_key,
			encrypted_private_group_key,
			public_group_key: pk.into(),
			group_key_alg: group_key.get_alg_str(),
			keypair_encrypt_alg: sk.get_alg_str(),
			encrypted_hmac_key,
			encrypted_hmac_alg: searchable_encryption.get_alg_str(),
			encrypted_sortable_key,
			encrypted_sortable_key_alg: sortable_encryption.get_alg_str(),
			encrypted_group_key_alg,
			verify_key,
			encrypted_sign_key,
			keypair_sign_alg,
			public_key_sig,
		},
		group_key, //return the group key extra because it is not encrypted and should not leave the device
	))
}

pub fn key_rotation<S: SymKey, P: Pk>(previous_group_key: &S, invoker_public_key: &P, user_group: bool) -> Result<KeyRotationOutput, Error>
{
	//1. create new group keys
	let group_key = sym::generate_key()?;

	let (sk, pk) = asym::generate_keys()?;

	//2. encrypt the private key with the group key
	let (
		encrypted_private_group_key,
		encrypted_group_key_by_user,
		encrypted_group_key_alg,
		verify_key,
		encrypted_sign_key,
		public_key_sig,
		keypair_sign_alg,
	) = prepare_keys(invoker_public_key, user_group, &group_key, &sk, &pk)?;

	//3. create an ephemeral key to encrypt the new group key
	let ephemeral_key = sym::generate_key()?;

	//4. encrypt the new group with the ephemeral_key.
	let encrypted_group_key_by_ephemeral = group_key.encrypt_with_sym_key(&ephemeral_key)?;

	//5. encrypt the ephemeral key with the previous_group_key group key,
	// so all group member can get the new key.
	// this encrypted ephemeral key will get encrypted by every group uses public key
	let encrypted_ephemeral_key = ephemeral_key.encrypt_with_sym_key(previous_group_key)?;

	Ok(KeyRotationOutput {
		encrypted_group_key_by_user,
		encrypted_group_key_alg,
		encrypted_private_group_key,
		group_key_alg: group_key.get_alg_str(),
		keypair_encrypt_alg: sk.get_alg_str(),
		encrypted_group_key_by_ephemeral,
		public_group_key: pk.into(),
		encrypted_ephemeral_key,
		verify_key,
		encrypted_sign_key,
		keypair_sign_alg,
		public_key_sig,
		ephemeral_alg: ephemeral_key.get_alg_str(),
	})
}

pub fn done_key_rotation<S: SymKey, Sek: Sk, P: Pk>(
	private_key: &Sek,
	public_key: &P,
	previous_group_key: &S,
	encrypted_ephemeral_key_by_group_key_and_public_key: &[u8],
	encrypted_group_key_by_ephemeral: &[u8],
	ephemeral_alg: &str,
) -> Result<Vec<u8>, Error>
{
	//1. decrypt the encrypted ephemeral key with the private key
	let decrypted_encrypted_ephemeral_key = private_key.decrypt(encrypted_ephemeral_key_by_group_key_and_public_key)?;

	//2. decrypt the encrypted ephemeral key then with the previous_group_key group key (the previous group key)
	let ephemeral_key = SymmetricKey::decrypt_key_by_sym_key(previous_group_key, &decrypted_encrypted_ephemeral_key, ephemeral_alg)?;

	//3.decrypt the new group key with the decrypted ephemeral key
	let new_group_key = ephemeral_key.decrypt(encrypted_group_key_by_ephemeral)?;

	//4. encrypt the new group key with the public key
	let encrypted_new_group_key = public_key.encrypt(&new_group_key)?;

	//the user can call ger group to get the new pri key too
	Ok(encrypted_new_group_key)
}

pub fn get_group<Sek: Sk>(
	private_key: &Sek,
	encrypted_group_key: &[u8],
	encrypted_private_group_key: &[u8],
	group_key_alg: &str,
	key_pair_alg: &str,
) -> Result<(SymmetricKey, SecretKey), Error>
{
	//call this for every group key with the private key, because every group key can be created and encrypted by different alg.

	//1. decrypt the group key
	let decrypted_group_key = SymmetricKey::decrypt_key_by_master_key(private_key, encrypted_group_key, group_key_alg)?;

	let decrypted_private_group_key = SecretKey::decrypt_by_maser_key(&decrypted_group_key, encrypted_private_group_key, key_pair_alg)?;

	Ok((decrypted_group_key, decrypted_private_group_key))
}

/**
# Prepare all group keys for a new added or invited member

Use this function to accept a new group join request or prepare an invitation request.

In both cases, all created group keys are needed for the new user to access.

```ignore
//get your group keys
use sentc_crypto_core::group::prepare_group_keys_for_new_member;
use sentc_crypto_core::Pk;

let group_keys = vec![&group_key, &new_group_key, &new_group_key_1, &new_group_key_2];

//get the new users public key
let user_pk = Pk::Ecies([0u8; 32]); //get it from the server

let new_user_out = prepare_group_keys_for_new_member(&user_pk, &group_keys);
```
*/
pub fn prepare_group_keys_for_new_member<P: Pk>(
	requester_public_key: &P,
	group_keys: &[&impl SymKey],
) -> Result<Vec<PrepareGroupKeysForNewMemberOutput>, Error>
{
	//encrypt all group keys with the requester public key, so he / she can access the data
	/*
		can't use the method from key rotation, where only the first key needs to pass to the other user and the rest gets encrypted by the server,
		because after all member got their new room key the rotation keys gets deleted
		 so every group key needs to encrypt for the new user
	*/

	let encrypted_group_key_alg = requester_public_key.get_alg_str();

	let encrypted_group_keys = group_keys
		.iter()
		.map(|group_key| {
			let encrypted_group_key = group_key.encrypt_key_with_master_key(requester_public_key)?;

			Ok(PrepareGroupKeysForNewMemberOutput {
				encrypted_group_key,
				alg: group_key.get_alg_str(),
				encrypted_group_key_alg,
			})
		})
		.collect::<Result<Vec<PrepareGroupKeysForNewMemberOutput>, Error>>()?;

	Ok(encrypted_group_keys)
}

#[cfg(test)]
mod test
{
	use alloc::vec;
	use core::str::from_utf8;

	use super::*;
	use crate::generate_salt;
	use crate::user::{done_login, prepare_login, register, LoginDoneOutput};

	fn create_dummy_user() -> (impl Pk, LoginDoneOutput)
	{
		let password = "12345";

		//create a test user
		let register_out = register(password).unwrap();

		//and now try to log in
		//normally the salt gets calc by the api
		let salt_from_rand_value = generate_salt(register_out.client_random_value, "");

		let prep_login_out = prepare_login(password, &salt_from_rand_value, register_out.derived_alg).unwrap();

		//try to decrypt the master key
		let login_out = done_login(
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

		let group_out = prepare_create(&pk, false).unwrap();
		let created_key = group_out.1;
		let group_out = group_out.0;

		#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
		assert_eq!(group_out.group_key_alg, AES_GCM_OUTPUT);

		//decrypt the group key
		let (group_key, group_pri_key) = get_group(
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

		let group_out = prepare_create(&pk, false).unwrap().0;

		#[cfg(any(feature = "argon2_aes_ecies_ed25519", feature = "argon2_aes_ecies_ed25519_kyber_hybrid"))]
		assert_eq!(group_out.group_key_alg, AES_GCM_OUTPUT);

		//decrypt the group key
		let (group_key, _group_pri_key) = get_group(
			&login_out.private_key,
			&group_out.encrypted_group_key,
			&group_out.encrypted_private_group_key,
			group_out.group_key_alg,
			group_out.keypair_encrypt_alg,
		)
		.unwrap();

		let rotation_out = key_rotation(&group_key, &pk, false).unwrap();

		//it should get the values from own encrypted group key
		let (_, _new_group_pri_key) = get_group(
			&login_out.private_key,
			&rotation_out.encrypted_group_key_by_user,
			&rotation_out.encrypted_private_group_key,
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();

		//do the server key rotation
		//executed on the server not the client. the client invokes done_key_rotation after
		//1. encrypt the encrypted ephemeral key with the public key
		//2. save this key in the db
		let encrypted_ephemeral_key_by_group_key_and_public_key = pk.encrypt(&rotation_out.encrypted_ephemeral_key).unwrap();

		//the encrypted_group_key_by_ephemeral is for everyone the same because this is encrypted by the previous group key

		//done key rotation to get the new group key
		let out = done_key_rotation(
			&login_out.private_key,
			&pk,
			&group_key,
			&encrypted_ephemeral_key_by_group_key_and_public_key,
			&rotation_out.encrypted_group_key_by_ephemeral,
			rotation_out.ephemeral_alg,
		)
		.unwrap();

		//get the new group by get_group
		let (_, _new_group_pri_key2) = get_group(
			&login_out.private_key,
			&out,
			&rotation_out.encrypted_private_group_key,
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();
	}

	#[test]
	fn test_accept_join_req()
	{
		let (user_1_pk, user_1_out) = create_dummy_user();
		let (user_2_pk, user_2_out) = create_dummy_user();

		let group_out = prepare_create(&user_1_pk, false).unwrap().0;
		let (group_key, _group_pri_key) = get_group(
			&user_1_out.private_key,
			&group_out.encrypted_group_key,
			&group_out.encrypted_private_group_key,
			group_out.group_key_alg,
			group_out.keypair_encrypt_alg,
		)
		.unwrap();

		//create multiple group keys
		let rotation_out = key_rotation(&group_key, &user_1_pk, false).unwrap();
		let (new_group_key, _new_group_pri_key) = get_group(
			&user_1_out.private_key,
			&rotation_out.encrypted_group_key_by_user,
			&rotation_out.encrypted_private_group_key,
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();

		let rotation_out_1 = key_rotation(&new_group_key, &user_1_pk, false).unwrap();
		let (new_group_key_1, _new_group_pri_key_1) = get_group(
			&user_1_out.private_key,
			&rotation_out_1.encrypted_group_key_by_user,
			&rotation_out_1.encrypted_private_group_key,
			rotation_out_1.group_key_alg,
			rotation_out_1.keypair_encrypt_alg,
		)
		.unwrap();

		let rotation_out_2 = key_rotation(&new_group_key_1, &user_1_pk, false).unwrap();
		let (new_group_key_2, _new_group_pri_key_2) = get_group(
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

		let (_, _new_user_group_pri_key_2) = get_group(
			&user_2_out.private_key,
			&group_key_2.encrypted_group_key,
			&rotation_out.encrypted_private_group_key, //normally get from the server
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();

		let group_key_3 = &new_user_out[2];

		let (_, _new_user_group_pri_key_3) = get_group(
			&user_2_out.private_key,
			&group_key_3.encrypted_group_key,
			&rotation_out_1.encrypted_private_group_key, //normally get from the server
			rotation_out_1.group_key_alg,
			rotation_out_1.keypair_encrypt_alg,
		)
		.unwrap();
	}
}
