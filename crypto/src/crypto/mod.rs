#[cfg(not(feature = "rust"))]
mod crypto;
#[cfg(feature = "rust")]
mod crypto_rust;

use alloc::string::ToString;
use alloc::vec::Vec;

use sendclose_crypto_common::crypto::{EncryptedHead, SignHead};
use sendclose_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sendclose_crypto_core::crypto::{decrypt_asymmetric, decrypt_symmetric, encrypt_asymmetric, encrypt_symmetric, sign, split_sig_and_data, verify};
use sendclose_crypto_core::{Error, SignK, ED25519_OUTPUT};

#[cfg(not(feature = "rust"))]
pub use self::crypto::{decrypt_raw_asymmetric, decrypt_raw_symmetric, encrypt_raw_asymmetric, encrypt_raw_symmetric};
#[cfg(feature = "rust")]
pub use self::crypto_rust::{decrypt_raw_asymmetric, decrypt_raw_symmetric, encrypt_raw_asymmetric, encrypt_raw_symmetric};
use crate::util::{import_public_key_from_pem_with_alg, import_verify_key_from_pem_with_alg, PrivateKeyFormatInt, SignKeyFormatInt, SymKeyFormatInt};

fn sign_internally(key: &SignKeyFormatInt, data: &[u8]) -> Result<(Option<SignHead>, Vec<u8>), Error>
{
	let signed_data = sign(&key.key, data)?;

	let alg = match &key.key {
		SignK::Ed25519(_) => ED25519_OUTPUT.to_string(),
	};

	let head = Some(SignHead {
		id: key.key_id.to_string(),
		alg,
	});

	Ok((head, signed_data))
}

fn verify_internally<'a>(verify_key: &UserVerifyKeyData, data_with_sig: &'a [u8], sign_head: &SignHead) -> Result<&'a [u8], Error>
{
	let verify_k = import_verify_key_from_pem_with_alg(verify_key.verify_key_pem.as_str(), verify_key.verify_key_alg.as_str())?;

	//check if the verify key is the right key id
	if verify_key.verify_key_id != sign_head.id {
		return Err(Error::SigFoundNotKey);
	}

	//verify the data with the right key
	let (encrypted_data_without_sig, check) = verify(&verify_k, data_with_sig)?;

	if check == false {
		return Err(Error::VerifyFailed);
	}

	Ok(encrypted_data_without_sig)
}

fn encrypt_raw_symmetric_internally(
	key: &SymKeyFormatInt,
	data: &[u8],
	sign_key: Option<&SignKeyFormatInt>,
) -> Result<(EncryptedHead, Vec<u8>), Error>
{
	let mut encrypt_head = EncryptedHead {
		id: key.key_id.to_string(),
		sign: None,
	};

	let mut encrypted = encrypt_symmetric(&key.key, data)?;

	//sign the data
	match sign_key {
		None => {},
		Some(sk) => {
			let (sign_head, data_with_sign) = sign_internally(sk, &encrypted)?;
			encrypted = data_with_sign;
			encrypt_head.sign = sign_head;
		},
	}

	Ok((encrypt_head, encrypted))
}

fn decrypt_raw_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	//the head needs to be checked before to know which key should be used here and if there is a sig and what verify key should be used

	//check if sig was set
	match &head.sign {
		None => decrypt_symmetric(&key.key, encrypted_data), //no sig used, go ahead
		Some(h) => {
			match verify_key {
				None => {
					//just split the data, use the alg here
					let (_, encrypted_data_without_sig) = split_sig_and_data(h.alg.as_str(), encrypted_data)?;
					decrypt_symmetric(&key.key, encrypted_data_without_sig)
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(&vk, encrypted_data, h)?;
					decrypt_symmetric(&key.key, encrypted_data_without_sig)
				},
			}
		},
	}
}

fn encrypt_raw_asymmetric_internally(
	reply_public_key: &UserPublicKeyData,
	data: &[u8],
	sign_key: Option<&SignKeyFormatInt>,
) -> Result<(EncryptedHead, Vec<u8>), Error>
{
	let public_key = import_public_key_from_pem_with_alg(reply_public_key.public_key_pem.as_str(), reply_public_key.public_key_alg.as_str())?;

	let mut encrypt_head = EncryptedHead {
		id: reply_public_key.public_key_id.to_string(),
		sign: None,
	};

	let mut encrypted = encrypt_asymmetric(&public_key, data)?;

	//sign the data
	match sign_key {
		None => {},
		Some(sk) => {
			let (sign_head, data_with_sign) = sign_internally(sk, &encrypted)?;
			encrypted = data_with_sign;
			encrypt_head.sign = sign_head;
		},
	}

	Ok((encrypt_head, encrypted))
}

fn decrypt_raw_asymmetric_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	match &head.sign {
		None => decrypt_asymmetric(&private_key.key, encrypted_data),
		Some(h) => {
			match verify_key {
				None => {
					let (_, encrypted_data_without_sig) = split_sig_and_data(h.alg.as_str(), encrypted_data)?;
					decrypt_asymmetric(&private_key.key, encrypted_data_without_sig)
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(&vk, encrypted_data, h)?;
					decrypt_asymmetric(&private_key.key, encrypted_data_without_sig)
				},
			}
		},
	}
}
