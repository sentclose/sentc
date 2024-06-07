use alloc::vec::Vec;

use hmac::digest::Digest;

use crate::{ClientRandomValue, DeriveAuthKeyForAuth, DeriveMasterKeyForAuth, Error, HashedAuthenticationKey, PasswordEncryptSalt};

pub trait CryptoAlg
{
	fn get_alg_str(&self) -> &'static str;
}

//__________________________________________________________________________________________________
//symmetric

pub trait SymKey: CryptoAlg + AsRef<[u8]>
{
	fn encrypt_key_with_master_key<M: Pk>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt_with_sym_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;

	fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait SymKeyGen
{
	type SymmetricKey: SymKey;

	fn generate() -> Result<Self::SymmetricKey, Error>;
}

pub trait SymKeyComposer
{
	type SymmetricKey: SymKey;

	fn decrypt_key_by_master_key<M: Sk>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>;

	fn decrypt_key_by_sym_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>;
}

//__________________________________________________________________________________________________
//asymmetric

pub trait Pk: CryptoAlg + Clone
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>;

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &[u8]) -> Result<bool, Error>;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Sk: CryptoAlg
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait StaticKeyPair
{
	type SecretKey: Sk;
	type PublicKey: Pk;

	fn generate_static_keypair() -> Result<(Self::SecretKey, Self::PublicKey), Error>;
}

pub trait SkComposer
{
	type SecretKey: Sk;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SecretKey, Error>;
}

//__________________________________________________________________________________________________
//sign

pub trait SignK: CryptoAlg
{
	type Signature: Sig;

	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

	fn sign_only<D: AsRef<[u8]>>(&self, data: D) -> Result<Self::Signature, Error>;
}

pub trait VerifyK: CryptoAlg
{
	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>;

	fn verify_only(&self, sig: &[u8], data: &[u8]) -> Result<bool, Error>;

	fn create_hash<D: Digest>(&self, hasher: &mut D);
}

pub trait SignKeyPair
{
	type SignKey: SignK;
	type VerifyKey: VerifyK;

	fn generate_key_pair() -> Result<(Self::SignKey, Self::VerifyKey), Error>;
}

pub trait SignKeyComposer
{
	type Key: SignK;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>;
}

pub trait Sig: CryptoAlg + Into<Vec<u8>>
{
	// fn split_sig_and_data<'a>(&self) -> Result<(&'a [u8], &'a [u8]), Error>;
	//
	// fn get_raw(&self) -> &[u8];
}

//__________________________________________________________________________________________________
//searchable

pub trait SearchableKey: CryptoAlg + AsRef<[u8]>
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt_searchable(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

	fn verify_encrypted_searchable(&self, data: &[u8], check: &[u8]) -> Result<bool, Error>;
}

pub trait SearchableKeyGen
{
	type SearchableKey: SearchableKey;

	fn generate() -> Result<Self::SearchableKey, Error>;
}

//__________________________________________________________________________________________________
//sortable

pub trait SortableKey: CryptoAlg + AsRef<[u8]>
{
	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt_sortable(&self, data: u64) -> Result<u64, Error>;
}

pub trait SortableKeyGen
{
	type SortableKey: SortableKey;

	fn generate() -> Result<Self::SortableKey, Error>;
}

//__________________________________________________________________________________________________
//pw hash

pub trait PwHash
{
	/**
	# Prepare registration

	 */
	fn derived_keys_from_password<M: SymKey>(
		&self,
		password: &[u8],
		master_key: &M,
	) -> Result<
		(
			ClientRandomValue,
			HashedAuthenticationKey,
			Vec<u8>,      //encrypted master key
			&'static str, //describe how the master key is encrypted
		),
		Error,
	>;

	/**
	# Prepare the login

	1. Takes the salt from the api (after sending the username)
	2. derived the encryption key (for the master key) and the auth key from the password and the salt
	3. return the encryption key and
		return the auth key to send it to the server so the server can check the hashed auth key

	@return: first is the master key, 2nd the auth key
	 */
	fn derive_keys_for_auth(&self, password: &[u8], salt_bytes: &[u8]) -> Result<(DeriveMasterKeyForAuth, DeriveAuthKeyForAuth), Error>;

	fn password_to_encrypt(&self, password: &[u8]) -> Result<(PasswordEncryptSalt, impl SymKey), Error>;

	fn password_to_decrypt(&self, password: &[u8], salt: &[u8]) -> Result<impl SymKey, Error>;
}
