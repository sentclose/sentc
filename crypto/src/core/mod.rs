use crate::{ClientRandomValue, HashedAuthenticationKey, MasterKeyInfo, Pk, VerifyK};

pub(crate) mod user;

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
