use alloc::vec::Vec;

use crate::cryptomat::{
	CryptoAlg,
	Pk,
	SearchableKey,
	SearchableKeyGen,
	Sig,
	SignK,
	SignKeyPair,
	Sk,
	SkComposer,
	SortableKey,
	SortableKeyGen,
	StaticKeyPair,
	SymKey,
	SymKeyComposer,
	SymKeyGen,
	VerifyK,
};
use crate::Error;

pub struct CreateGroupOutput<P: Pk, V: VerifyK, S: Sig>
{
	pub encrypted_group_key: Vec<u8>,          //encrypted by creators public key
	pub group_key_alg: &'static str,           //info about the raw master key (not the encrypted by the pk!)
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: P,
	pub keypair_encrypt_alg: &'static str,
	pub encrypted_hmac_key: Vec<u8>,
	pub encrypted_hmac_alg: &'static str,
	pub encrypted_sortable_key: Vec<u8>,
	pub encrypted_sortable_key_alg: &'static str,

	//for user group
	pub verify_key: Option<V>,
	pub encrypted_sign_key: Option<Vec<u8>>,
	pub keypair_sign_alg: Option<&'static str>,
	pub public_key_sig: Option<S>,
}

pub struct KeyRotationOutput<P: Pk, V: VerifyK, S: Sig>
{
	pub encrypted_group_key_by_user: Vec<u8>, //encrypted by invoker public key
	pub group_key_alg: &'static str,
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk from the invoker (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: P,
	pub keypair_encrypt_alg: &'static str,
	pub encrypted_group_key_by_ephemeral: Vec<u8>,
	pub ephemeral_alg: &'static str,
	pub encrypted_ephemeral_key: Vec<u8>, //encrypted by the previous_group_key group key. encrypt this key with every other member public key on the server

	//for user group
	pub verify_key: Option<V>,
	pub encrypted_sign_key: Option<Vec<u8>>,
	pub keypair_sign_alg: Option<&'static str>,
	pub public_key_sig: Option<S>,
}

pub struct PrepareGroupKeysForNewMemberOutput
{
	pub alg: &'static str,
	pub encrypted_group_key: Vec<u8>,
	pub encrypted_group_key_alg: &'static str,
}

#[allow(clippy::type_complexity)]
fn prepare_keys<Sign: SignKeyPair>(
	creators_public_key: &impl Pk,
	user_group: bool,
	group_key: &impl SymKey,
	group_sk: &impl Sk,
	group_pk: &impl Pk,
) -> Result<
	(
		Vec<u8>,
		Vec<u8>,
		&'static str,
		Option<Sign::VerifyKey>,
		Option<Vec<u8>>,
		Option<<<Sign>::SignKey as SignK>::Signature>,
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
		let (sign_key, verify_key) = Sign::generate_key_pair()?;

		let encrypted_sign_key = sign_key.encrypt_by_master_key(group_key)?;

		let public_key_sig = group_pk.sign_public_key(&sign_key)?;

		(
			Some(verify_key),
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

#[allow(clippy::type_complexity)]
pub fn prepare_create<S, St, Sign, Search, Sort>(
	creators_public_key: &impl Pk,
	user_group: bool,
) -> Result<
	(
		CreateGroupOutput<St::PublicKey, Sign::VerifyKey, <<Sign>::SignKey as SignK>::Signature>,
		S::SymmetricKey,
	),
	Error,
>
where
	S: SymKeyGen,
	St: StaticKeyPair,
	Sign: SignKeyPair,
	Search: SearchableKeyGen,
	Sort: SortableKeyGen,
{
	//1. create the keys:
	//	1. master symmetric key
	//	2. pub / pri keys

	let group_key = S::generate()?;

	let (sk, public_group_key) = St::generate_static_keypair()?;

	let (encrypted_private_group_key, encrypted_group_key, encrypted_group_key_alg, verify_key, encrypted_sign_key, public_key_sig, keypair_sign_alg) =
		prepare_keys::<Sign>(creators_public_key, user_group, &group_key, &sk, &public_group_key)?;

	/*
	create the searchable encryption hmac key and encrypt it with the group key

	create it only for create group not key rotation
	 because when searching an item we don't know what key was used for the item
	 */

	//3. get the hmac key
	let searchable_encryption = Search::generate()?;
	let encrypted_hmac_key = searchable_encryption.encrypt_key_with_master_key(&group_key)?;

	let sortable_encryption = Sort::generate()?;
	let encrypted_sortable_key = sortable_encryption.encrypt_key_with_master_key(&group_key)?;

	Ok((
		CreateGroupOutput {
			encrypted_group_key,
			encrypted_private_group_key,
			public_group_key,
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

#[allow(clippy::type_complexity)]
pub fn key_rotation<S: SymKeyGen, St: StaticKeyPair, Sign: SignKeyPair>(
	previous_group_key: &impl SymKey,
	invoker_public_key: &impl Pk,
	user_group: bool,
) -> Result<KeyRotationOutput<St::PublicKey, Sign::VerifyKey, <<Sign as SignKeyPair>::SignKey as SignK>::Signature>, Error>
{
	//1. create new group keys
	let group_key = S::generate()?;

	let (sk, public_group_key) = St::generate_static_keypair()?;

	//2. encrypt the private key with the group key
	let (
		encrypted_private_group_key,
		encrypted_group_key_by_user,
		encrypted_group_key_alg,
		verify_key,
		encrypted_sign_key,
		public_key_sig,
		keypair_sign_alg,
	) = prepare_keys::<Sign>(invoker_public_key, user_group, &group_key, &sk, &public_group_key)?;

	//3. create an ephemeral key to encrypt the new group key
	let ephemeral_key = S::generate()?;

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
		public_group_key,
		encrypted_ephemeral_key,
		verify_key,
		encrypted_sign_key,
		keypair_sign_alg,
		public_key_sig,
		ephemeral_alg: ephemeral_key.get_alg_str(),
	})
}

pub fn done_key_rotation<SymC: SymKeyComposer>(
	private_key: &impl Sk,
	public_key: &impl Pk,
	previous_group_key: &impl SymKey,
	encrypted_ephemeral_key_by_group_key_and_public_key: &[u8],
	encrypted_group_key_by_ephemeral: &[u8],
	ephemeral_alg: &str,
) -> Result<Vec<u8>, Error>
{
	//1. decrypt the encrypted ephemeral key with the private key
	let decrypted_encrypted_ephemeral_key = private_key.decrypt(encrypted_ephemeral_key_by_group_key_and_public_key)?;

	//2. decrypt the encrypted ephemeral key then with the previous_group_key group key (the previous group key)
	let ephemeral_key = SymC::decrypt_key_by_sym_key(previous_group_key, &decrypted_encrypted_ephemeral_key, ephemeral_alg)?;

	//3.decrypt the new group key with the decrypted ephemeral key
	let new_group_key = ephemeral_key.decrypt(encrypted_group_key_by_ephemeral)?;

	//4. encrypt the new group key with the public key
	let encrypted_new_group_key = public_key.encrypt(&new_group_key)?;

	//the user can call ger group to get the new pri key too
	Ok(encrypted_new_group_key)
}

pub fn get_group<SymC: SymKeyComposer, SkC: SkComposer>(
	private_key: &impl Sk,
	encrypted_group_key: &[u8],
	encrypted_private_group_key: &[u8],
	group_key_alg: &str,
	key_pair_alg: &str,
) -> Result<(SymC::SymmetricKey, SkC::SecretKey), Error>
{
	//call this for every group key with the private key, because every group key can be created and encrypted by different alg.

	//1. decrypt the group key
	let decrypted_group_key = SymC::decrypt_key_by_master_key(private_key, encrypted_group_key, group_key_alg)?;

	let decrypted_private_group_key = SkC::decrypt_by_master_key(&decrypted_group_key, encrypted_private_group_key, key_pair_alg)?;

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
