use alloc::string::String;
use alloc::vec::Vec;
use core::str::FromStr;

use sentc_crypto_common::crypto::SignHead;
use sentc_crypto_core::cryptomat::{CryptoAlg, Sig, SignK, SymKey};
use sentc_crypto_core::Error;
use sentc_crypto_utils::cryptomat::{KeyToString, SignKCryptoWrapper, SignKWrapper};
use sentc_crypto_utils::error::SdkUtilError;

use crate::SdkError;

pub(crate) struct FakeSig;

impl CryptoAlg for FakeSig
{
	fn get_alg_str(&self) -> &'static str
	{
		"fake"
	}
}

#[allow(clippy::from_over_into)]
impl Into<Vec<u8>> for FakeSig
{
	fn into(self) -> Vec<u8>
	{
		Default::default()
	}
}

impl Sig for FakeSig {}

pub(crate) struct FakeSignKey;

impl CryptoAlg for FakeSignKey
{
	fn get_alg_str(&self) -> &'static str
	{
		"fake"
	}
}

impl SignK for FakeSignKey
{
	type Signature = FakeSig;

	fn encrypt_by_master_key<M: SymKey>(&self, _master_key: &M) -> Result<Vec<u8>, Error>
	{
		unimplemented!("Fake sign key for internal encryption")
	}

	fn sign(&self, _data: &[u8]) -> Result<Vec<u8>, Error>
	{
		unimplemented!("Fake sign key for internal encryption")
	}

	fn sign_only<D: AsRef<[u8]>>(&self, _data: D) -> Result<Self::Signature, Error>
	{
		unimplemented!("Fake sign key for internal encryption")
	}
}

pub(crate) struct FakeSignKeyWrapper;

impl FromStr for FakeSignKeyWrapper
{
	type Err = SdkError;

	fn from_str(_s: &str) -> Result<Self, Self::Err>
	{
		Err(SdkError::JsonParse)
	}
}

impl KeyToString for FakeSignKeyWrapper
{
	fn to_string(self) -> Result<String, SdkUtilError>
	{
		Err(SdkUtilError::JsonToStringFailed)
	}
}

impl SignKCryptoWrapper for FakeSignKeyWrapper
{
	fn sign_with_head(&self, _data: &[u8]) -> Result<(SignHead, Vec<u8>), SdkUtilError>
	{
		unimplemented!("Fake sign key for internal encryption")
	}
}

impl SignKWrapper for FakeSignKeyWrapper
{
	type Inner = FakeSignKey;

	fn get_id(&self) -> &str
	{
		unimplemented!("Fake sign key for internal encryption")
	}

	fn get_key(&self) -> &Self::Inner
	{
		unimplemented!("Fake sign key for internal encryption")
	}
}
