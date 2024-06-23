#[cfg(feature = "encryption")]
mod crypto;

use alloc::string::String;
use core::str::FromStr;

#[cfg(feature = "encryption")]
pub use crypto::*;
use sentc_crypto_core::cryptomat::{
	Pk,
	SignK,
	SignKeyComposer,
	SignKeyPair,
	Sk,
	SkComposer,
	StaticKeyPair,
	SymKey,
	SymKeyComposer,
	SymKeyGen,
	VerifyK,
};

use crate::error::SdkUtilError;

#[macro_export]
macro_rules! wrapper_impl {
	($trait_impl:ident, $name:ident, $inner:ident) => {
		impl $trait_impl for $name
		{
			type Inner = $inner;

			fn get_id(&self) -> &str
			{
				&self.key_id
			}

			fn get_key(&self) -> &Self::Inner
			{
				&self.key
			}
		}
	};
}

#[macro_export]
macro_rules! to_string_impl {
	($st:ty,$t:ty) => {
		impl $crate::cryptomat::KeyToString for $st
		{
			fn to_string(self) -> Result<String, $crate::error::SdkUtilError>
			{
				serde_json::to_string(&Into::<$t>::into(self)).map_err(|_e| $crate::error::SdkUtilError::JsonToStringFailed)
			}
		}
	};
}

#[macro_export]
macro_rules! to_string_try_impl {
	($st:ty,$t:ty) => {
		impl $crate::cryptomat::KeyToString for $st
		{
			fn to_string(self) -> Result<String, $crate::error::SdkUtilError>
			{
				serde_json::to_string(&TryInto::<$t>::try_into(self)?).map_err(|_e| $crate::error::SdkUtilError::JsonToStringFailed)
			}
		}
	};
}

#[macro_export]
macro_rules! from_string_impl {
	($st:ty,$t:ty) => {
		impl FromStr for $st
		{
			type Err = $crate::error::SdkUtilError;

			fn from_str(s: &str) -> Result<Self, Self::Err>
			{
				let key: $t = serde_json::from_str(s).map_err(|_| $crate::error::SdkUtilError::ImportKeyFailed)?;

				key.try_into()
			}
		}
	};
}

//__________________________________________________________________________________________________

macro_rules! wrapper_trait {
	($name:ident, $inner:ident) => {
		pub trait $name: FromStr + KeyToString
		{
			type Inner: $inner;

			fn get_id(&self) -> &str;

			fn get_key(&self) -> &Self::Inner;
		}
	};
	($name:ident, $inner:ident, $crypto:ident) => {
		pub trait $name: FromStr + KeyToString + $crypto
		{
			type Inner: $inner;

			fn get_id(&self) -> &str;

			fn get_key(&self) -> &Self::Inner;
		}
	};
}

pub trait KeyToString
{
	fn to_string(self) -> Result<String, SdkUtilError>;
}

//__________________________________________________________________________________________________
//symmetric

#[cfg(not(feature = "encryption"))]
wrapper_trait!(SymKeyWrapper, SymKey);

#[cfg(feature = "encryption")]
wrapper_trait!(SymKeyWrapper, SymKey, SymKeyCrypto);

pub trait SymKeyGenWrapper
{
	type SymmetricKeyWrapper: SymKeyWrapper;
	type KeyGen: SymKeyGen;

	fn from_inner(inner: <<Self as SymKeyGenWrapper>::KeyGen as SymKeyGen>::SymmetricKey, id: String) -> Self::SymmetricKeyWrapper;
}

pub trait SymKeyComposerWrapper
{
	type SymmetricKeyWrapper: SymKeyWrapper;
	type Composer: SymKeyComposer;

	fn from_inner(inner: <<Self as SymKeyComposerWrapper>::Composer as SymKeyComposer>::SymmetricKey, id: String) -> Self::SymmetricKeyWrapper;
}

//__________________________________________________________________________________________________
//asymmetric

#[cfg(not(feature = "encryption"))]
wrapper_trait!(SkWrapper, Sk);

#[cfg(feature = "encryption")]
wrapper_trait!(SkWrapper, Sk, SkCryptoWrapper);

wrapper_trait!(PkWrapper, Pk, Clone);

pub trait StaticKeyPairWrapper
{
	// type SkWrapper: SkWrapper;
	type PkWrapper: PkWrapper;
	type KeyGen: StaticKeyPair;

	// fn sk_from_inner(inner: <<Self as StaticKeyPairWrapper>::KeyGen as StaticKeyPair>::SecretKey, id: String) -> Self::SkWrapper;

	fn pk_from_inner(inner: <<Self as StaticKeyPairWrapper>::KeyGen as StaticKeyPair>::PublicKey, id: String) -> Self::PkWrapper;

	fn pk_inner_to_pem(inner: &<<Self as StaticKeyPairWrapper>::KeyGen as StaticKeyPair>::PublicKey) -> Result<String, SdkUtilError>;
}

pub trait StaticKeyComposerWrapper
{
	type SkWrapper: SkWrapper;
	type PkWrapper: PkWrapper;
	type InnerPk: Pk;
	type Composer: SkComposer;

	fn sk_from_inner(inner: <<Self as StaticKeyComposerWrapper>::Composer as SkComposer>::SecretKey, id: String) -> Self::SkWrapper;

	fn pk_from_pem(public_key: &str, alg: &str, id: String) -> Result<Self::PkWrapper, SdkUtilError>;

	fn pk_inner_from_pem(public_key: &str, alg: &str) -> Result<Self::InnerPk, SdkUtilError>;
}

//__________________________________________________________________________________________________
//sign

#[cfg(not(feature = "encryption"))]
wrapper_trait!(SignKWrapper, SignK);

#[cfg(feature = "encryption")]
wrapper_trait!(SignKWrapper, SignK, SignKCryptoWrapper);

wrapper_trait!(VerifyKWrapper, VerifyK);

pub trait SignKeyPairWrapper
{
	type KeyGen: SignKeyPair;

	fn vk_inner_to_pem(inner: &<<Self as SignKeyPairWrapper>::KeyGen as SignKeyPair>::VerifyKey) -> Result<String, SdkUtilError>;

	fn sig_to_string(sig: <<<Self as SignKeyPairWrapper>::KeyGen as SignKeyPair>::SignKey as SignK>::Signature) -> String;
}

pub trait SignComposerWrapper
{
	type SignKWrapper: SignKWrapper;
	type VerifyKWrapper: VerifyKWrapper;
	type InnerVk: VerifyK;
	type Composer: SignKeyComposer;

	fn sk_from_inner(inner: <<Self as SignComposerWrapper>::Composer as SignKeyComposer>::Key, id: String) -> Self::SignKWrapper;

	fn vk_from_pem(public_key: &str, alg: &str, id: String) -> Result<Self::VerifyKWrapper, SdkUtilError>;

	fn vk_inner_from_pem(public_key: &str, alg: &str) -> Result<Self::InnerVk, SdkUtilError>;

	fn sig_from_string(sig: &str, alg: &str) -> Result<<<Self as SignComposerWrapper>::InnerVk as VerifyK>::Signature, SdkUtilError>;
}
