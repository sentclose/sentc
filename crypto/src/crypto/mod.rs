#[cfg(feature = "rust")]
mod crypto_rust;

use alloc::string::ToString;
use alloc::vec::Vec;

use sendclose_crypto_common::crypto::{EncryptedHead, SignHead};
use sendclose_crypto_core::crypto::{decrypt_symmetric, encrypt_symmetric, sign, split_sig_and_data, verify};
use sendclose_crypto_core::{Error, SignK, ED25519_OUTPUT};

#[cfg(feature = "rust")]
pub use self::crypto_rust::{decrypt_raw_symmetric, encrypt_raw_symmetric};
use crate::util::{SignKeyFormatInt, SymKeyFormatInt, VerifyKeyFormatInt};

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
			encrypted = sign(&sk.key, &encrypted)?;

			let alg = match sk.key {
				SignK::Ed25519(_) => ED25519_OUTPUT.to_string(),
			};

			encrypt_head.sign = Some(SignHead {
				id: sk.key_id.to_string(),
				alg,
			});
		},
	}

	Ok((encrypt_head, encrypted))
}

fn decrypt_raw_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&VerifyKeyFormatInt>,
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
					//check if the verify key is the right key id
					if vk.key_id != h.id {
						return Err(Error::SigFoundNotKey);
					}

					//verify the data with the right key
					let (encrypted_data_without_sig, check) = verify(&vk.key, encrypted_data)?;

					if check == false {
						return Err(Error::VerifyFailed);
					}

					decrypt_symmetric(&key.key, encrypted_data_without_sig)
				},
			}
		},
	}
}
