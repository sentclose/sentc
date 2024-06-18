use alloc::vec::Vec;

use sha2::digest::Digest;

use crate::Error;

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

	fn generate_symmetric_with_sym_key<M: SymKey>(master_key: &M) -> Result<(Vec<u8>, Self::SymmetricKey), Error>
	{
		let out = Self::generate()?;

		let encrypted_sym_key = out.encrypt_with_sym_key(master_key)?;

		Ok((encrypted_sym_key, out))
	}

	fn generate_symmetric_with_public_key<M: Pk>(master_key: &M) -> Result<(Vec<u8>, Self::SymmetricKey), Error>
	{
		let out = Self::generate()?;

		let encrypted_sym_key = out.encrypt_key_with_master_key(master_key)?;

		Ok((encrypted_sym_key, out))
	}
}

pub trait SymKeyComposer
{
	type SymmetricKey: SymKey;

	fn from_bytes(bytes: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>;

	fn decrypt_key_by_master_key<M: Sk>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}

	fn decrypt_key_by_sym_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::SymmetricKey, Error>
	{
		let decrypted_bytes = master_key.decrypt(encrypted_key)?;

		Self::from_bytes(&decrypted_bytes, alg_str)
	}
}

//__________________________________________________________________________________________________
//asymmetric

pub trait Pk: CryptoAlg + Clone
{
	fn sign_public_key<S: SignK>(&self, sign_key: &S) -> Result<S::Signature, Error>;

	fn verify_public_key<V: VerifyK>(&self, verify_key: &V, sig: &V::Signature) -> Result<bool, Error>;

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
	type Signature: Sig;

	fn verify<'a>(&self, data_with_sig: &'a [u8]) -> Result<(&'a [u8], bool), Error>;

	fn verify_only(&self, sig: &Self::Signature, data: &[u8]) -> Result<bool, Error>;

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

pub trait SearchableKeyComposer
{
	type Key: SearchableKey;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>;
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

pub trait SortableKeyComposer
{
	type Key: SortableKey;

	fn decrypt_by_master_key<M: SymKey>(master_key: &M, encrypted_key: &[u8], alg_str: &str) -> Result<Self::Key, Error>;
}

//__________________________________________________________________________________________________
//pw hash

pub trait PwHash
{
	type CRV: ClientRandomValue;
	type HAK: HashedAuthenticationKey;
	type DMK: DeriveMasterKeyForAuth;
	type DAK: DeriveAuthKeyForAuth;
	type PWS: PasswordEncryptSalt;

	/**
	# Prepare registration

	 */
	#[allow(clippy::type_complexity)]
	fn derived_keys_from_password<M: SymKey>(
		password: &[u8],
		master_key: &M,
		alg: Option<&str>, //when None then use default hasher. when set try to get the hasher that created the alg
	) -> Result<
		(
			Self::CRV,
			Self::HAK,
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
	fn derive_keys_for_auth(password: &[u8], salt_bytes: &[u8], alg: &str) -> Result<(Self::DMK, Self::DAK), Error>;

	fn password_to_encrypt(password: &[u8]) -> Result<(Self::PWS, impl SymKey), Error>;

	fn password_to_decrypt(password: &[u8], salt: &[u8]) -> Result<impl SymKey, Error>;
}

pub trait PwPrepareExport
{
	fn prepare_export(&self) -> &[u8];
}

pub trait ClientRandomValue: CryptoAlg + PwPrepareExport
{
	fn generate_salt(self, add_str: &str) -> Vec<u8>;
}

pub trait ClientRandomValueComposer
{
	type Value: ClientRandomValue;

	fn from_bytes(vec: Vec<u8>, alg: &str) -> Result<Self::Value, Error>;
}

pub trait HashedAuthenticationKey: PwPrepareExport {}

pub trait DeriveMasterKeyForAuth: PwPrepareExport
{
	fn get_master_key(&self, encrypted_master_key: &[u8]) -> Result<impl SymKey, Error>;
}

pub trait DeriveAuthKeyForAuth: PwPrepareExport
{
	fn hash_auth_key(&self) -> Result<Vec<u8>, Error>;
}

pub trait DeriveAuthKeyForAuthComposer
{
	type Value: DeriveAuthKeyForAuth;

	fn from_bytes(vec: Vec<u8>, alg: &str) -> Result<Self::Value, Error>;
}

pub trait PasswordEncryptSalt: PwPrepareExport {}
