use alloc::vec::Vec;

use hmac::digest::Digest;

use crate::{Error, HmacKey, PublicKey, SecretKey, SignKey, Signature, SymmetricKey, VerifyKey};

pub trait CryptoAlg
{
	fn get_alg_str(&self) -> &'static str;
}

pub trait SymKey: CryptoAlg + Into<SymmetricKey>
{
	fn generate() -> Result<impl SymKey, Error>;

	fn encrypt_key_with_master_key<M: Pk>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt_with_sym_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;

	fn encrypt_with_aad(&self, data: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;

	fn decrypt_with_aad(&self, ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Pk: CryptoAlg + Into<PublicKey>
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<impl Sig, Error>;

	fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait Sk: CryptoAlg + Into<SecretKey>
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, Error>;
}

pub trait StaticKeyPair
{
	fn generate_static_keypair() -> Result<(impl Sk, impl Pk), Error>;
}

pub trait SignK: CryptoAlg + Into<SignKey>
{
	fn encrypt_by_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

	fn sign_only(&self, data: &[u8]) -> Result<impl Sig, Error>;
}

pub trait VerifyK: CryptoAlg + Into<VerifyKey>
{
	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>;

	fn verify_only(&self, sig: &[u8], data: &[u8]) -> Result<bool, Error>;

	fn create_hash<D: Digest>(&self, hasher: &mut D);
}

pub trait SignKeyPair
{
	fn generate_key_pair() -> Result<(impl SignK, impl VerifyK), Error>;
}

pub trait Sig: CryptoAlg + Into<Signature>
{
	fn split_sig_and_data<'a>(&self) -> Result<(&'a [u8], &'a [u8]), Error>;

	fn get_raw(&self) -> &[u8];
}

pub trait SearchableKey: CryptoAlg + Into<HmacKey>
{
	fn generate() -> Result<impl SearchableKey, Error>;

	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt_searchable(&self, data: &[u8]) -> Result<Vec<u8>, Error>;

	fn verify_encrypted_searchable(&self, data: &[u8], check: &[u8]) -> Result<bool, Error>;
}

pub trait SortableKey: CryptoAlg
{
	fn generate() -> Result<impl SortableKey, Error>;

	fn encrypt_key_with_master_key<M: SymKey>(&self, master_key: &M) -> Result<Vec<u8>, Error>;

	fn encrypt_sortable(&self, data: u64) -> Result<u64, Error>;
}
