use alloc::vec::Vec;

use crate::alg::{asym, sym};
use crate::{Error, Pk, Sk, SymKey};

pub struct CreateGroupOutput
{
	pub encrypted_group_key: Vec<u8>,          //encrypted by creators public key
	pub group_key_alg: &'static str,           //info about the raw master key (not the encrypted by the pk!)
	pub encrypted_group_key_alg: &'static str, //info about how the encrypted group key was encrypted by the pk (important for the server)
	pub encrypted_private_group_key: Vec<u8>,
	pub public_group_key: Pk,
	pub keypair_encrypt_alg: &'static str,
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
	pub encrypted_ephemeral_key: Vec<u8>, //encrypted by the old group key. encrypt this key with every other member public key on the server
}

#[cfg(feature = "argon2_aes_ecies_ed25519")]
fn prepare_create_aes_ecies_ed25519(creators_public_key: &Pk) -> Result<CreateGroupOutput, Error>
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

	let private_key = match &keypair.sk {
		Sk::Ecies(k) => k,
	};

	let encrypted_private_group_key = sym::aes_gcm::encrypt_with_generated_key(raw_group_key, private_key)?;

	//3. encrypt the group key with the creators public key. every other member will get this key encrypted by his/hers public key
	let (encrypted_group_key, encrypted_group_key_alg) = match creators_public_key {
		Pk::Ecies(_) => {
			let en = asym::ecies::encrypt(creators_public_key, raw_group_key)?;

			(en, asym::ecies::ECIES_OUTPUT)
		},
	};

	Ok(CreateGroupOutput {
		encrypted_group_key,
		encrypted_private_group_key,
		public_group_key: keypair.pk,
		group_key_alg: group_key.alg,
		keypair_encrypt_alg: keypair.alg,
		encrypted_group_key_alg,
	})
}

pub fn prepare_create(creators_public_key: &Pk) -> Result<CreateGroupOutput, Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	prepare_create_aes_ecies_ed25519(creators_public_key)
}

#[cfg(feature = "argon2_aes_ecies_ed25519")]
fn key_rotation_aes_ecies_ed25519(old_group_key: &SymKey, invoker_public_key: &Pk) -> Result<KeyRotationOutput, Error>
{
	//1. create new group keys
	let group_key = sym::aes_gcm::generate_key()?;
	let keypair = asym::ecies::generate_static_keypair();

	//2. encrypt the private key with the group key
	let raw_group_key = match &group_key.key {
		SymKey::Aes(k) => k,
	};

	let private_key = match &keypair.sk {
		Sk::Ecies(k) => k,
	};

	let encrypted_private_group_key = sym::aes_gcm::encrypt_with_generated_key(raw_group_key, private_key)?;

	//3. create an ephemeral key to encrypt the new group key
	let ephemeral_key = sym::aes_gcm::generate_key()?;
	let raw_ephemeral_key = match &ephemeral_key.key {
		SymKey::Aes(k) => k,
	};

	//4. encrypt the new group with the ephemeral_key.
	let encrypted_group_key_by_ephemeral = sym::aes_gcm::encrypt_with_generated_key(raw_ephemeral_key, raw_group_key)?;

	//5. encrypt the ephemeral key with the old group key, so all group member can get the new key
	let encrypted_ephemeral_key = match old_group_key {
		SymKey::Aes(k) => sym::aes_gcm::encrypt_with_generated_key(k, raw_ephemeral_key)?,
	};

	//6. encrypt the new group key with the public key of the invoker, so we save one encryption on the server
	let (encrypted_group_key_by_user, encrypted_group_key_alg) = match invoker_public_key {
		Pk::Ecies(_) => {
			let en = asym::ecies::encrypt(invoker_public_key, raw_group_key)?;

			(en, asym::ecies::ECIES_OUTPUT)
		},
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
	})
}

pub fn key_rotation(old_group_key: &SymKey, invoker_public_key: &Pk) -> Result<KeyRotationOutput, Error>
{
	#[cfg(feature = "argon2_aes_ecies_ed25519")]
	key_rotation_aes_ecies_ed25519(old_group_key, invoker_public_key)
}

pub fn get_group(
	private_key: &Sk,
	encrypted_group_key: &[u8],
	encrypted_private_group_key: &[u8],
	group_key_alg: &str,
	key_pair_alg: &str,
) -> Result<(SymKey, Sk), Error>
{
	//1. decrypt the group key
	let decrypted_group_key = match private_key {
		Sk::Ecies(_) => asym::ecies::decrypt(private_key, encrypted_group_key)?,
	};

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

#[cfg(test)]
mod test
{
	//use std here to check if the bytes output are correct to the input string
	extern crate std;

	use super::*;
	use crate::alg::sym::aes_gcm::AES_GCM_OUTPUT;
	use crate::generate_salt;
	use crate::user::{done_login, prepare_login, register, LoginDoneOutput};

	fn create_dummy_user() -> (Pk, LoginDoneOutput)
	{
		let password = "12345";

		//create a test user
		let register_out = register(password).unwrap();

		//and now try to login
		//normally the salt gets calc by the api
		let salt_from_rand_value = generate_salt(register_out.client_random_value);

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

		let group_out = prepare_create(&pk).unwrap();

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
		#[cfg(feature = "argon2_aes_ecies_ed25519")]
		{
			let text = "abc 12345 üöä*#+^°êéè";

			let encrypted = sym::aes_gcm::encrypt(&group_key, text.as_bytes()).unwrap();

			let decrypted = sym::aes_gcm::decrypt(&group_key, &encrypted).unwrap();

			assert_eq!(decrypted, text.as_bytes());

			let decrypted_text = std::str::from_utf8(&decrypted).unwrap();
			assert_eq!(decrypted_text, text);

			let encrypted_pri = asym::ecies::encrypt(&group_out.public_group_key, text.as_bytes()).unwrap();

			let decrypted_pri = asym::ecies::decrypt(&group_pri_key, &encrypted_pri).unwrap();

			assert_eq!(decrypted_pri, text.as_bytes());

			let decrypted_text = std::str::from_utf8(&decrypted_pri).unwrap();
			assert_eq!(decrypted_text, text);
		}
	}
}
