use alloc::vec::Vec;

use crate::alg::sym::aes_gcm::AesKey;
use crate::alg::{asym, hmac, sign, sym};
use crate::crypto::{decrypt_asymmetric, decrypt_symmetric, encrypt_asymmetric};
use crate::{AsymKeyOutput, Error, HmacKey, Pk, Sig, SignK, Sk, SymKey, VerifyK};

pub struct CreateGroupOutput
{
	pub encrypted_group_key: Vec<u8>,          //encrypted by creators public key
	pub group_key_alg: &'static str,           //info about the raw master key (not the encrypted by the pk!)
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: Pk,
	pub keypair_encrypt_alg: &'static str,
	pub encrypted_hmac_key: Vec<u8>,
	pub encrypted_hmac_alg: &'static str,

	//for user group
	pub verify_key: Option<VerifyK>,
	pub encrypted_sign_key: Option<Vec<u8>>,
	pub keypair_sign_alg: Option<&'static str>,
	pub public_key_sig: Option<Sig>,
}

pub struct KeyRotationOutput
{
	pub encrypted_group_key_by_user: Vec<u8>, //encrypted by invoker public key
	pub group_key_alg: &'static str,
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk from the invoker (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: Pk,
	pub keypair_encrypt_alg: &'static str,
	pub encrypted_group_key_by_ephemeral: Vec<u8>,
	pub ephemeral_alg: &'static str,
	pub encrypted_ephemeral_key: Vec<u8>, //encrypted by the previous_group_key group key. encrypt this key with every other member public key on the server

	//for user group
	pub verify_key: Option<VerifyK>,
	pub encrypted_sign_key: Option<Vec<u8>>,
	pub keypair_sign_alg: Option<&'static str>,
	pub public_key_sig: Option<Sig>,
}

pub struct PrepareGroupKeysForNewMemberOutput
{
	pub alg: &'static str,
	pub encrypted_group_key: Vec<u8>,
	pub encrypted_group_key_alg: &'static str,
}

#[cfg(feature = "argon2_aes_ecies_ed25519")]
fn prepare_create_aes_ecies_ed25519(creators_public_key: &Pk, user_group: bool) -> Result<(CreateGroupOutput, SymKey), Error>
{
	//1. create the keys:
	//	1. master symmetric key
	//	2. pub / pri keys

	let group_key = sym::aes_gcm::generate_key()?;
	let keypair = asym::ecies::generate_static_keypair();

	//2. encrypt the private key with the group key
	let raw_group_key = match &group_key.key {
		SymKey::Aes(k) => k,
	};

	let (encrypted_private_group_key, encrypted_group_key, encrypted_group_key_alg, verify_key, encrypted_sign_key, keypair_sign_alg, public_key_sig) =
		prepare_keys_aes_ecies_ed25519(creators_public_key, user_group, raw_group_key, &keypair)?;

	//3. get the hmac key

	/*
	create the searchable encryption hmac key and encrypt it with the group key

	create it only for create group not key rotation
	 because when searching an item we don't know what key was used for the item
	 */
	let searchable_encryption = hmac::hmac_sha256::generate_key()?;

	let encrypted_hmac_key = match &searchable_encryption.key {
		HmacKey::HmacSha256(k) => sym::aes_gcm::encrypt_with_generated_key(raw_group_key, k)?,
	};

	Ok((
		CreateGroupOutput {
			encrypted_group_key,
			encrypted_private_group_key,
			public_group_key: keypair.pk,
			group_key_alg: group_key.alg,
			keypair_encrypt_alg: keypair.alg,
			encrypted_hmac_key,
			encrypted_hmac_alg: searchable_encryption.alg,
			encrypted_group_key_alg,
			verify_key,
			encrypted_sign_key,
			keypair_sign_alg,
			public_key_sig,
		},
		group_key.key, //return the group key extra because it is not encrypted and should not leave the device
	))
}

pub fn prepare_create(creators_public_key: &Pk, user_group: bool) -> Result<(CreateGroupOutput, SymKey), Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	prepare_create_aes_ecies_ed25519(creators_public_key, user_group)
}

#[cfg(feature = "argon2_aes_ecies_ed25519")]
fn key_rotation_aes_ecies_ed25519(previous_group_key: &SymKey, invoker_public_key: &Pk, user_group: bool) -> Result<KeyRotationOutput, Error>
{
	//1. create new group keys
	let group_key = sym::aes_gcm::generate_key()?;
	let keypair = asym::ecies::generate_static_keypair();

	//2. encrypt the private key with the group key
	let raw_group_key = match &group_key.key {
		SymKey::Aes(k) => k,
	};

	let (
		encrypted_private_group_key,
		encrypted_group_key_by_user,
		encrypted_group_key_alg,
		verify_key,
		encrypted_sign_key,
		keypair_sign_alg,
		public_key_sig,
	) = prepare_keys_aes_ecies_ed25519(invoker_public_key, user_group, raw_group_key, &keypair)?;

	//3. create an ephemeral key to encrypt the new group key
	let ephemeral_key = sym::aes_gcm::generate_key()?;
	let raw_ephemeral_key = match &ephemeral_key.key {
		SymKey::Aes(k) => k,
	};

	//4. encrypt the new group with the ephemeral_key.
	let encrypted_group_key_by_ephemeral = sym::aes_gcm::encrypt_with_generated_key(raw_ephemeral_key, raw_group_key)?;

	//5. encrypt the ephemeral key with the previous_group_key group key, so all group member can get the new key. this encrypted ephemeral key will get encrypted by every group uses public key
	let encrypted_ephemeral_key = match previous_group_key {
		SymKey::Aes(k) => sym::aes_gcm::encrypt_with_generated_key(k, raw_ephemeral_key)?,
	};

	Ok(KeyRotationOutput {
		encrypted_group_key_by_user,
		encrypted_group_key_alg,
		encrypted_private_group_key,
		group_key_alg: group_key.alg,
		keypair_encrypt_alg: keypair.alg,
		encrypted_group_key_by_ephemeral,
		public_group_key: keypair.pk,
		encrypted_ephemeral_key,
		verify_key,
		encrypted_sign_key,
		keypair_sign_alg,
		public_key_sig,
		ephemeral_alg: sym::aes_gcm::AES_GCM_OUTPUT,
	})
}

pub fn key_rotation(previous_group_key: &SymKey, invoker_public_key: &Pk, user_group: bool) -> Result<KeyRotationOutput, Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	key_rotation_aes_ecies_ed25519(previous_group_key, invoker_public_key, user_group)
}

type PrepareKeysAesEciesEd25519Tuple = (
	Vec<u8>,
	Vec<u8>,
	&'static str,
	Option<VerifyK>,
	Option<Vec<u8>>,
	Option<&'static str>,
	Option<Sig>,
);

#[cfg(feature = "argon2_aes_ecies_ed25519")]
fn prepare_keys_aes_ecies_ed25519(
	public_key: &Pk,
	user_group: bool,
	raw_group_key: &AesKey,
	key_pair: &AsymKeyOutput,
) -> Result<PrepareKeysAesEciesEd25519Tuple, Error>
{
	//encrypt the private group key
	let private_key = match &key_pair.sk {
		Sk::Ecies(k) => k,
	};

	let encrypted_private_group_key = sym::aes_gcm::encrypt_with_generated_key(raw_group_key, private_key)?;

	let (encrypted_group_key, encrypted_group_key_alg) = match public_key {
		Pk::Ecies(_) => {
			let en = asym::ecies::encrypt(public_key, raw_group_key)?;

			(en, asym::ecies::ECIES_OUTPUT)
		},
	};

	//create the sign keys if user group and after encrypt the sign key with group key
	let (verify_key, encrypted_sign_key, keypair_sign_alg, public_key_sig) = if !user_group {
		(None, None, None, None)
	} else {
		let sign = sign::ed25519::generate_key_pair()?;

		let raw_sign_key = match &sign.sign_key {
			SignK::Ed25519(k) => k,
		};

		let encrypted_sign_key = sym::aes_gcm::encrypt_with_generated_key(raw_group_key, raw_sign_key)?;

		//sign the public key
		let raw_public_key = match public_key {
			Pk::Ecies(k) => k,
		};

		let public_key_sig = sign::ed25519::sign_only(&sign.sign_key, raw_public_key)?;

		(
			Some(sign.verify_key),
			Some(encrypted_sign_key),
			Some(sign.alg),
			Some(public_key_sig),
		)
	};

	Ok((
		encrypted_private_group_key,
		encrypted_group_key,
		encrypted_group_key_alg,
		verify_key,
		encrypted_sign_key,
		keypair_sign_alg,
		public_key_sig,
	))
}

pub fn done_key_rotation(
	private_key: &Sk,
	public_key: &Pk,
	previous_group_key: &SymKey,
	encrypted_ephemeral_key_by_group_key_and_public_key: &[u8],
	encrypted_group_key_by_ephemeral: &[u8],
	ephemeral_alg: &str,
) -> Result<Vec<u8>, Error>
{
	//1. decrypt the encrypted ephemeral key with the private key
	let decrypted_encrypted_ephemeral_key = decrypt_asymmetric(private_key, encrypted_ephemeral_key_by_group_key_and_public_key)?;

	//2. decrypt the encrypted ephemeral key then with the previous_group_key group key (the previous group key)
	let decrypted_ephemeral_key = decrypt_symmetric(previous_group_key, &decrypted_encrypted_ephemeral_key)?;

	//3.decrypt the new group key with the decrypted ephemeral key
	let new_group_key = match ephemeral_alg {
		sym::aes_gcm::AES_GCM_OUTPUT => {
			//decrypt directly here with the key because we know which key was used thanks to the ephemeral_alg
			let key = &decrypted_ephemeral_key
				.try_into()
				.map_err(|_| Error::KeyDecryptFailed)?;

			sym::aes_gcm::decrypt_with_generated_key(key, encrypted_group_key_by_ephemeral)?
		},
		_ => return Err(Error::AlgNotFound),
	};

	//4. encrypt the new group key with the public key
	let encrypted_new_group_key = encrypt_asymmetric(public_key, &new_group_key)?;

	//the user can call ger group to get the new pri key too
	Ok(encrypted_new_group_key)
}

pub fn get_group_hmac_key(group_key: &SymKey, encrypted_hmac_key: &[u8], encrypted_hmac_alg: &str) -> Result<HmacKey, Error>
{
	let hmac_key = decrypt_symmetric(group_key, encrypted_hmac_key)?;

	let key = match encrypted_hmac_alg {
		hmac::hmac_sha256::HMAC_SHA256_OUTPUT => HmacKey::HmacSha256(hmac_key.try_into().map_err(|_| Error::KeyDecryptFailed)?),
		_ => return Err(Error::AlgNotFound),
	};

	Ok(key)
}

pub fn get_group(
	private_key: &Sk,
	encrypted_group_key: &[u8],
	encrypted_private_group_key: &[u8],
	group_key_alg: &str,
	key_pair_alg: &str,
) -> Result<(SymKey, Sk), Error>
{
	//call this for every group key with the private key, because every group key can be created and encrypted by different alg.

	//1. decrypt the group key
	let decrypted_group_key = decrypt_asymmetric(private_key, encrypted_group_key)?;

	//turn the decrypted group key into a Sym key
	let (decrypted_group_key, decrypted_private_group_key) = match group_key_alg {
		sym::aes_gcm::AES_GCM_OUTPUT => {
			let key = SymKey::Aes(
				decrypted_group_key
					.try_into()
					.map_err(|_| Error::KeyDecryptFailed)?,
			);

			//2. decrypt the private group key with the group key
			let decrypted_private_group_key = sym::aes_gcm::decrypt(&key, encrypted_private_group_key)?;

			(key, decrypted_private_group_key)
		},
		_ => return Err(Error::AlgNotFound),
	};

	//turn this private key into a Sk
	let decrypted_private_group_key = match key_pair_alg {
		asym::ecies::ECIES_OUTPUT => {
			Sk::Ecies(
				decrypted_private_group_key
					.try_into()
					.map_err(|_| Error::KeyDecryptFailed)?,
			)
		},
		_ => return Err(Error::AlgNotFound),
	};

	Ok((decrypted_group_key, decrypted_private_group_key))
}

/**
# Prepare all group keys for a new added or invited member

Use this function to accept a new group join request or prepare an invite request.

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
pub fn prepare_group_keys_for_new_member(requester_public_key: &Pk, group_keys: &[&SymKey])
	-> Result<Vec<PrepareGroupKeysForNewMemberOutput>, Error>
{
	//encrypt all group keys with the requester public key, so he / she can access the data
	/*
		can't use the method from key rotation, where only the first key needs to pass to the other user and the rest gets encrypted by the server,
		because after all member got their new room key the rotation keys gets deleted
		 so every group key needs to encrypt for the new user
	*/

	let mut encrypted_group_keys: Vec<PrepareGroupKeysForNewMemberOutput> = Vec::with_capacity(group_keys.len());

	let encrypted_group_key_alg = match requester_public_key {
		Pk::Ecies(_) => asym::ecies::ECIES_OUTPUT,
	};

	for group_key in group_keys {
		let (encrypted_group_key, group_key_alg) = match group_key {
			SymKey::Aes(k) => {
				//encrypt everytime single because we don't know what format the sym key has and we only know it by checking the enum,
				//so we can't save it in a variable
				let encrypted_group_key = encrypt_asymmetric(requester_public_key, k)?;

				(encrypted_group_key, sym::aes_gcm::AES_GCM_OUTPUT)
			},
		};

		encrypted_group_keys.push(PrepareGroupKeysForNewMemberOutput {
			encrypted_group_key,
			alg: group_key_alg,
			encrypted_group_key_alg,
		});
	}

	Ok(encrypted_group_keys)
}

#[cfg(test)]
mod test
{
	use alloc::vec;
	use core::str::from_utf8;

	use super::*;
	use crate::alg::sym::aes_gcm::AES_GCM_OUTPUT;
	use crate::crypto::{decrypt_asymmetric, decrypt_symmetric, encrypt_asymmetric, encrypt_symmetric};
	use crate::generate_salt;
	use crate::user::{done_login, prepare_login, register, LoginDoneOutput};

	fn create_dummy_user() -> (Pk, LoginDoneOutput)
	{
		let password = "12345";

		//create a test user
		let register_out = register(password).unwrap();

		//and now try to login
		//normally the salt gets calc by the api
		let salt_from_rand_value = generate_salt(register_out.client_random_value, "");

		let prep_login_out = prepare_login(password, &salt_from_rand_value, register_out.derived_alg).unwrap();

		//try to decrypt the master key
		let login_out = done_login(
			&prep_login_out.master_key_encryption_key, //the value comes from prepare login
			&register_out.master_key_info.encrypted_master_key,
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

		#[cfg(feature = "argon2_aes_ecies_ed25519")]
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

		let encrypted = encrypt_symmetric(&group_key, text.as_bytes()).unwrap();
		let decrypted = decrypt_symmetric(&group_key, &encrypted).unwrap();

		assert_eq!(decrypted, text.as_bytes());

		//test decrypt with group returned group key after create
		let encrypted = encrypt_symmetric(&created_key, text.as_bytes()).unwrap();
		let decrypted = decrypt_symmetric(&created_key, &encrypted).unwrap();

		assert_eq!(decrypted, text.as_bytes());

		let decrypted_text = from_utf8(&decrypted).unwrap();
		assert_eq!(decrypted_text, text);

		let encrypted_pri = encrypt_asymmetric(&group_out.public_group_key, text.as_bytes()).unwrap();
		let decrypted_pri = decrypt_asymmetric(&group_pri_key, &encrypted_pri).unwrap();

		assert_eq!(decrypted_pri, text.as_bytes());

		let decrypted_text = from_utf8(&decrypted_pri).unwrap();
		assert_eq!(decrypted_text, text);
	}

	#[test]
	fn test_key_rotation()
	{
		let (pk, login_out) = create_dummy_user();

		let group_out = prepare_create(&pk, false).unwrap().0;

		#[cfg(feature = "argon2_aes_ecies_ed25519")]
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
		let (new_group_key, _new_group_pri_key) = get_group(
			&login_out.private_key,
			&rotation_out.encrypted_group_key_by_user,
			&rotation_out.encrypted_private_group_key,
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();

		match (&group_key, &new_group_key) {
			(SymKey::Aes(previous_group_key), SymKey::Aes(new_key)) => {
				assert_ne!(*previous_group_key, *new_key);
			},
		}

		//do the server key rotation
		//executed on the server not the client. the client invokes done_key_rotation after
		//1. encrypt the encrypted ephemeral key with the public key
		//2. save this key in the db
		let encrypted_ephemeral_key_by_group_key_and_public_key = encrypt_asymmetric(&pk, &rotation_out.encrypted_ephemeral_key).unwrap();

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
		let (new_group_key2, _new_group_pri_key2) = get_group(
			&login_out.private_key,
			&out,
			&rotation_out.encrypted_private_group_key,
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();

		match (&group_key, &new_group_key, &new_group_key2) {
			(SymKey::Aes(previous_group_key), SymKey::Aes(new_key), SymKey::Aes(new_key2)) => {
				assert_eq!(*new_key, *new_key2); //should be the same
				assert_ne!(*previous_group_key, *new_key2); //should not the same because this is a new group key
			},
		}
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

		let (new_user_group_key_2, _new_user_group_pri_key_2) = get_group(
			&user_2_out.private_key,
			&group_key_2.encrypted_group_key,
			&rotation_out.encrypted_private_group_key, //normally get from the server
			rotation_out.group_key_alg,
			rotation_out.keypair_encrypt_alg,
		)
		.unwrap();

		match (&new_group_key, &new_user_group_key_2) {
			(SymKey::Aes(user_1_key_2), SymKey::Aes(user_2_key_2)) => {
				assert_eq!(*user_1_key_2, *user_2_key_2);
			},
		}

		let group_key_3 = &new_user_out[2];

		let (new_user_group_key_3, _new_user_group_pri_key_3) = get_group(
			&user_2_out.private_key,
			&group_key_3.encrypted_group_key,
			&rotation_out_1.encrypted_private_group_key, //normally get from the server
			rotation_out_1.group_key_alg,
			rotation_out_1.keypair_encrypt_alg,
		)
		.unwrap();

		match (&new_group_key_1, &new_user_group_key_3) {
			(SymKey::Aes(user_1_key_3), SymKey::Aes(user_2_key_3)) => {
				assert_eq!(*user_1_key_3, *user_2_key_3);
			},
		}
	}
}
