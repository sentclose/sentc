#[cfg(not(feature = "rust"))]
mod crypto;
#[cfg(feature = "rust")]
mod crypto_rust;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerInput, GeneratedSymKeyHeadServerOutput, SignHead};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_core::{crypto as crypto_core, Error, SignK, ED25519_OUTPUT};

#[cfg(not(feature = "rust"))]
pub use self::crypto::{
	decrypt_asymmetric,
	decrypt_raw_asymmetric,
	decrypt_raw_symmetric,
	decrypt_string_asymmetric,
	decrypt_string_symmetric,
	decrypt_sym_key,
	decrypt_symmetric,
	encrypt_asymmetric,
	encrypt_raw_asymmetric,
	encrypt_raw_symmetric,
	encrypt_string_asymmetric,
	encrypt_string_symmetric,
	encrypt_symmetric,
	prepare_register_sym_key,
};
#[cfg(feature = "rust")]
pub use self::crypto_rust::{
	decrypt_asymmetric,
	decrypt_raw_asymmetric,
	decrypt_raw_symmetric,
	decrypt_string_asymmetric,
	decrypt_string_symmetric,
	decrypt_sym_key,
	decrypt_symmetric,
	encrypt_asymmetric,
	encrypt_raw_asymmetric,
	encrypt_raw_symmetric,
	encrypt_string_asymmetric,
	encrypt_string_symmetric,
	encrypt_symmetric,
	prepare_register_sym_key,
};
use crate::util::{import_public_key_from_pem_with_alg, import_verify_key_from_pem_with_alg, PrivateKeyFormatInt, SignKeyFormatInt, SymKeyFormatInt};

fn sign_internally(key: &SignKeyFormatInt, data: &[u8]) -> Result<(Option<SignHead>, Vec<u8>), Error>
{
	let signed_data = crypto_core::sign(&key.key, data)?;

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
	let (encrypted_data_without_sig, check) = crypto_core::verify(&verify_k, data_with_sig)?;

	if check == false {
		return Err(Error::VerifyFailed);
	}

	Ok(encrypted_data_without_sig)
}

fn split_head_and_encrypted_data_internally(data_with_head: &[u8]) -> Result<(EncryptedHead, &[u8]), Error>
{
	let mut i = 0usize;
	for data_itr in data_with_head {
		if *data_itr == 0u8 {
			//the mark to split the head from the data
			//found the i where to split head from data
			break;
		}

		i += 1;
	}

	let head = EncryptedHead::from_slice(&data_with_head[..i]).map_err(|_| Error::JsonParseFailed)?;

	//ignore the zero byte
	Ok((head, &data_with_head[i + 1..]))
}

fn put_head_and_encrypted_data_internally(head: &EncryptedHead, encrypted: &[u8]) -> Result<Vec<u8>, Error>
{
	let head = head.to_string().map_err(|_| Error::JsonToStringFailed)?;

	let mut out = Vec::with_capacity(head.len() + 1 + encrypted.len());

	out.extend(head.as_bytes());
	out.extend([0u8]);
	out.extend(encrypted);

	Ok(out)
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

	let mut encrypted = crypto_core::encrypt_symmetric(&key.key, data)?;

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
		None => crypto_core::decrypt_symmetric(&key.key, encrypted_data), //no sig used, go ahead
		Some(h) => {
			match verify_key {
				None => {
					//just split the data, use the alg here
					let (_, encrypted_data_without_sig) = crypto_core::split_sig_and_data(h.alg.as_str(), encrypted_data)?;
					crypto_core::decrypt_symmetric(&key.key, encrypted_data_without_sig)
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(&vk, encrypted_data, h)?;
					crypto_core::decrypt_symmetric(&key.key, encrypted_data_without_sig)
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

	let mut encrypted = crypto_core::encrypt_asymmetric(&public_key, data)?;

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
		None => crypto_core::decrypt_asymmetric(&private_key.key, encrypted_data),
		Some(h) => {
			match verify_key {
				None => {
					let (_, encrypted_data_without_sig) = crypto_core::split_sig_and_data(h.alg.as_str(), encrypted_data)?;
					crypto_core::decrypt_asymmetric(&private_key.key, encrypted_data_without_sig)
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(&vk, encrypted_data, h)?;
					crypto_core::decrypt_asymmetric(&private_key.key, encrypted_data_without_sig)
				},
			}
		},
	}
}

fn encrypt_symmetric_internally(key: &SymKeyFormatInt, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<Vec<u8>, Error>
{
	let (head, encrypted) = encrypt_raw_symmetric_internally(key, data, sign_key)?;

	Ok(put_head_and_encrypted_data_internally(&head, &encrypted)?)
}

fn decrypt_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data_with_head: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	let (head, encrypted_data) = split_head_and_encrypted_data_internally(encrypted_data_with_head)?;

	Ok(decrypt_raw_symmetric_internally(key, encrypted_data, &head, verify_key)?)
}

fn encrypt_asymmetric_internally(reply_public_key: &UserPublicKeyData, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<Vec<u8>, Error>
{
	let (head, encrypted_data) = encrypt_raw_asymmetric_internally(reply_public_key, data, sign_key)?;

	Ok(put_head_and_encrypted_data_internally(&head, &encrypted_data)?)
}

fn decrypt_asymmetric_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_data_with_head: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	let (head, encrypted_data) = split_head_and_encrypted_data_internally(encrypted_data_with_head)?;

	Ok(decrypt_raw_asymmetric_internally(private_key, &encrypted_data, &head, verify_key)?)
}

fn encrypt_string_symmetric_internally(key: &SymKeyFormatInt, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<String, Error>
{
	let encrypted = encrypt_symmetric_internally(key, data, sign_key)?;

	Ok(Base64::encode_string(&encrypted))
}

fn decrypt_string_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	let encrypted = Base64::decode_vec(encrypted_data_with_head).map_err(|_| Error::DecodeEncryptedDataFailed)?;

	decrypt_symmetric_internally(key, &encrypted, verify_key)
}

fn encrypt_string_asymmetric_internally(
	reply_public_key: &UserPublicKeyData,
	data: &[u8],
	sign_key: Option<&SignKeyFormatInt>,
) -> Result<String, Error>
{
	let encrypted = encrypt_asymmetric_internally(reply_public_key, data, sign_key)?;

	Ok(Base64::encode_string(&encrypted))
}

fn decrypt_string_asymmetric_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, Error>
{
	let encrypted = Base64::decode_vec(encrypted_data_with_head).map_err(|_| Error::DecodeEncryptedDataFailed)?;

	decrypt_asymmetric_internally(private_key, &encrypted, verify_key)
}

/**
# Prepare key registration on the server

1. create a new symmetric key
2. export the symmetric key in base64
3. encrypt the symmetric key with the master key
4. return the server input
*/
fn prepare_register_sym_key_internally(master_key: &SymKeyFormatInt) -> Result<String, Error>
{
	let (encrypted_key, sym_key_alg) = crypto_core::generate_symmetric_with_master_key(&master_key.key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	Ok(GeneratedSymKeyHeadServerInput {
		encrypted_key_string,
		alg: sym_key_alg.to_string(),
		master_key_id: master_key.key_id.to_string(),
	}
	.to_string()
	.map_err(|_| Error::JsonToStringFailed)?)
}

/**
# Get a symmetric key which was encrypted by a master key

Backwards the process in prepare_register_sym_key.

1. get the bytes of the encrypted symmetric key
2. get the sym internal format by decrypting it with the master key
4. return the key incl. key id in the right format
*/
fn decrypt_sym_key_internally(
	master_key: &SymKeyFormatInt,
	encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput,
) -> Result<SymKeyFormatInt, Error>
{
	let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| Error::KeyDecryptFailed)?;

	let key = crypto_core::get_symmetric_key_from_master_key(&master_key.key, &encrypted_sym_key, encrypted_symmetric_key_info.alg.as_str())?;

	Ok(SymKeyFormatInt {
		key,
		key_id: encrypted_symmetric_key_info.key_id.to_string(),
	})
}
