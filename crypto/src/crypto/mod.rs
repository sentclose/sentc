#[cfg(not(feature = "rust"))]
mod crypto;
#[cfg(feature = "rust")]
mod crypto_rust;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

use base64ct::{Base64, Encoding};
use sentc_crypto_common::crypto::{EncryptedHead, GeneratedSymKeyHeadServerInput, GeneratedSymKeyHeadServerOutput, SignHead};
use sentc_crypto_common::user::{UserPublicKeyData, UserVerifyKeyData};
use sentc_crypto_common::SymKeyId;
use sentc_crypto_core::{crypto as crypto_core, SignK, ED25519_OUTPUT};
use serde::{Deserialize, Serialize};

#[cfg(not(feature = "rust"))]
pub use self::crypto::{
	decrypt_asymmetric,
	decrypt_raw_asymmetric,
	decrypt_raw_symmetric,
	decrypt_string_asymmetric,
	decrypt_string_symmetric,
	decrypt_sym_key,
	decrypt_sym_key_by_private_key,
	decrypt_symmetric,
	deserialize_head_from_string,
	done_fetch_sym_key,
	done_fetch_sym_key_by_private_key,
	done_fetch_sym_keys,
	done_register_sym_key,
	encrypt_asymmetric,
	encrypt_raw_asymmetric,
	encrypt_raw_symmetric,
	encrypt_string_asymmetric,
	encrypt_string_symmetric,
	encrypt_symmetric,
	generate_non_register_sym_key,
	generate_non_register_sym_key_by_public_key,
	prepare_register_sym_key,
	prepare_register_sym_key_by_public_key,
	split_head_and_encrypted_data,
	split_head_and_encrypted_string,
};
#[cfg(not(feature = "rust"))]
pub(crate) use self::crypto::{prepare_sign_key, prepare_verify_key};
#[cfg(feature = "rust")]
pub use self::crypto_rust::{
	decrypt_asymmetric,
	decrypt_raw_asymmetric,
	decrypt_raw_symmetric,
	decrypt_string_asymmetric,
	decrypt_string_symmetric,
	decrypt_sym_key,
	decrypt_sym_key_by_private_key,
	decrypt_symmetric,
	deserialize_head_from_string,
	done_fetch_sym_key,
	done_fetch_sym_key_by_private_key,
	done_fetch_sym_keys,
	done_register_sym_key,
	encrypt_asymmetric,
	encrypt_raw_asymmetric,
	encrypt_raw_symmetric,
	encrypt_string_asymmetric,
	encrypt_string_symmetric,
	encrypt_symmetric,
	generate_non_register_sym_key,
	generate_non_register_sym_key_by_public_key,
	prepare_register_sym_key,
	prepare_register_sym_key_by_public_key,
	split_head_and_encrypted_data,
	split_head_and_encrypted_string,
};
use crate::util::public::handle_server_response;
use crate::util::{import_public_key_from_pem_with_alg, import_verify_key_from_pem_with_alg, PrivateKeyFormatInt, SignKeyFormatInt, SymKeyFormatInt};
use crate::SdkError;

pub(crate) fn sign_internally(key: &SignKeyFormatInt, data: &[u8]) -> Result<(SignHead, Vec<u8>), SdkError>
{
	let signed_data = crypto_core::sign(&key.key, data)?;

	let alg = match &key.key {
		SignK::Ed25519(_) => ED25519_OUTPUT.to_string(),
	};

	Ok((
		SignHead {
			id: key.key_id.to_string(),
			alg,
		},
		signed_data,
	))
}

pub(crate) fn verify_internally<'a>(verify_key: &UserVerifyKeyData, data_with_sig: &'a [u8], sign_head: &SignHead) -> Result<&'a [u8], SdkError>
{
	let verify_k = import_verify_key_from_pem_with_alg(verify_key.verify_key_pem.as_str(), verify_key.verify_key_alg.as_str())?;

	//check if the verify key is the right key id
	if verify_key.verify_key_id != sign_head.id {
		return Err(SdkError::SigFoundNotKey);
	}

	//verify the data with the right key
	let (encrypted_data_without_sig, check) = crypto_core::verify(&verify_k, data_with_sig)?;

	if !check {
		return Err(SdkError::VerifyFailed);
	}

	Ok(encrypted_data_without_sig)
}

/**
Get the head and the data.

This can not only be used internally, to get the used key_id
*/
pub(crate) fn split_head_and_encrypted_data_internally<'a, T: Deserialize<'a>>(data_with_head: &'a [u8]) -> Result<(T, &[u8]), SdkError>
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

	let head = serde_json::from_slice(&data_with_head[..i]).map_err(SdkError::JsonParseFailed)?;

	//ignore the zero byte
	Ok((head, &data_with_head[i + 1..]))
}

/**
Get head from string.

Just the head because of life time issues and we need the full data for encrypt and decrypt
*/
fn split_head_and_encrypted_string_internally(encrypted_data_with_head: &str) -> Result<EncryptedHead, SdkError>
{
	let encrypted = Base64::decode_vec(encrypted_data_with_head).map_err(|_| SdkError::DecodeEncryptedDataFailed)?;

	let (head, _) = split_head_and_encrypted_data_internally(&encrypted)?;

	Ok(head)
}

pub(crate) fn put_head_and_encrypted_data_internally<T: Serialize>(head: &T, encrypted: &[u8]) -> Result<Vec<u8>, SdkError>
{
	let head = serde_json::to_string(head).map_err(|_| SdkError::JsonToStringFailed)?;

	let mut out = Vec::with_capacity(head.len() + 1 + encrypted.len());

	out.extend(head.as_bytes());
	out.extend([0u8]);
	out.extend(encrypted);

	Ok(out)
}

/**
Get the head from string

This can be used to get the head struct when getting the head as string, like raw decrypt in the non rust sdk.
*/
fn deserialize_head_from_string_internally(head: &str) -> Result<EncryptedHead, SdkError>
{
	EncryptedHead::from_string(head).map_err(SdkError::JsonParseFailed)
}

fn encrypt_raw_symmetric_internally(
	key: &SymKeyFormatInt,
	data: &[u8],
	sign_key: Option<&SignKeyFormatInt>,
) -> Result<(EncryptedHead, Vec<u8>), SdkError>
{
	let mut encrypt_head = EncryptedHead {
		id: key.key_id.to_string(),
		sign: None,
	};

	let mut encrypted = crypto_core::encrypt_symmetric(&key.key, data)?;

	//sign the data
	if let Some(sk) = sign_key {
		let (sign_head, data_with_sign) = sign_internally(sk, &encrypted)?;
		encrypted = data_with_sign;
		encrypt_head.sign = Some(sign_head);
	}

	Ok((encrypt_head, encrypted))
}

fn decrypt_raw_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	//the head needs to be checked before to know which key should be used here and if there is a sig and what verify key should be used

	//check if sig was set
	match &head.sign {
		None => Ok(crypto_core::decrypt_symmetric(&key.key, encrypted_data)?), //no sig used, go ahead
		Some(h) => {
			match verify_key {
				None => {
					//just split the data, use the alg here
					let (_, encrypted_data_without_sig) = crypto_core::split_sig_and_data(h.alg.as_str(), encrypted_data)?;
					Ok(crypto_core::decrypt_symmetric(&key.key, encrypted_data_without_sig)?)
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(vk, encrypted_data, h)?;
					Ok(crypto_core::decrypt_symmetric(&key.key, encrypted_data_without_sig)?)
				},
			}
		},
	}
}

fn encrypt_raw_asymmetric_internally(
	reply_public_key: &UserPublicKeyData,
	data: &[u8],
	sign_key: Option<&SignKeyFormatInt>,
) -> Result<(EncryptedHead, Vec<u8>), SdkError>
{
	let public_key = import_public_key_from_pem_with_alg(
		reply_public_key.public_key_pem.as_str(),
		reply_public_key.public_key_alg.as_str(),
	)?;

	let mut encrypt_head = EncryptedHead {
		id: reply_public_key.public_key_id.to_string(),
		sign: None,
	};

	let mut encrypted = crypto_core::encrypt_asymmetric(&public_key, data)?;

	//sign the data
	if let Some(sk) = sign_key {
		let (sign_head, data_with_sign) = sign_internally(sk, &encrypted)?;
		encrypted = data_with_sign;
		encrypt_head.sign = Some(sign_head);
	}

	Ok((encrypt_head, encrypted))
}

fn decrypt_raw_asymmetric_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_data: &[u8],
	head: &EncryptedHead,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	match &head.sign {
		None => Ok(crypto_core::decrypt_asymmetric(&private_key.key, encrypted_data)?),
		Some(h) => {
			match verify_key {
				None => {
					let (_, encrypted_data_without_sig) = crypto_core::split_sig_and_data(h.alg.as_str(), encrypted_data)?;
					Ok(crypto_core::decrypt_asymmetric(
						&private_key.key,
						encrypted_data_without_sig,
					)?)
				},
				Some(vk) => {
					let encrypted_data_without_sig = verify_internally(vk, encrypted_data, h)?;
					Ok(crypto_core::decrypt_asymmetric(
						&private_key.key,
						encrypted_data_without_sig,
					)?)
				},
			}
		},
	}
}

fn encrypt_symmetric_internally(key: &SymKeyFormatInt, data: &[u8], sign_key: Option<&SignKeyFormatInt>) -> Result<Vec<u8>, SdkError>
{
	let (head, encrypted) = encrypt_raw_symmetric_internally(key, data, sign_key)?;

	put_head_and_encrypted_data_internally(&head, &encrypted)
}

fn decrypt_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data_with_head: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	let (head, encrypted_data) = split_head_and_encrypted_data_internally(encrypted_data_with_head)?;

	decrypt_raw_symmetric_internally(key, encrypted_data, &head, verify_key)
}

fn encrypt_asymmetric_internally(reply_public_key: &UserPublicKeyData, data: &[u8], sign_key: Option<&SignKeyFormatInt>)
	-> Result<Vec<u8>, SdkError>
{
	let (head, encrypted_data) = encrypt_raw_asymmetric_internally(reply_public_key, data, sign_key)?;

	put_head_and_encrypted_data_internally(&head, &encrypted_data)
}

fn decrypt_asymmetric_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_data_with_head: &[u8],
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<Vec<u8>, SdkError>
{
	let (head, encrypted_data) = split_head_and_encrypted_data_internally(encrypted_data_with_head)?;

	decrypt_raw_asymmetric_internally(private_key, encrypted_data, &head, verify_key)
}

pub(crate) fn encrypt_string_symmetric_internally(key: &SymKeyFormatInt, data: &str, sign_key: Option<&SignKeyFormatInt>)
	-> Result<String, SdkError>
{
	let encrypted = encrypt_symmetric_internally(key, data.as_bytes(), sign_key)?;

	Ok(Base64::encode_string(&encrypted))
}

fn decrypt_string_symmetric_internally(
	key: &SymKeyFormatInt,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	let encrypted = Base64::decode_vec(encrypted_data_with_head).map_err(|_| SdkError::DecodeEncryptedDataFailed)?;

	let decrypted = decrypt_symmetric_internally(key, &encrypted, verify_key)?;

	String::from_utf8(decrypted).map_err(|_| SdkError::DecodeEncryptedDataFailed)
}

fn encrypt_string_asymmetric_internally(
	reply_public_key: &UserPublicKeyData,
	data: &str,
	sign_key: Option<&SignKeyFormatInt>,
) -> Result<String, SdkError>
{
	let encrypted = encrypt_asymmetric_internally(reply_public_key, data.as_bytes(), sign_key)?;

	Ok(Base64::encode_string(&encrypted))
}

fn decrypt_string_asymmetric_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_data_with_head: &str,
	verify_key: Option<&UserVerifyKeyData>,
) -> Result<String, SdkError>
{
	let encrypted = Base64::decode_vec(encrypted_data_with_head).map_err(|_| SdkError::DecodeEncryptedDataFailed)?;

	let decrypted = decrypt_asymmetric_internally(private_key, &encrypted, verify_key)?;

	String::from_utf8(decrypted).map_err(|_| SdkError::DecodeEncryptedDataFailed)
}

/**
# Prepare key registration on the server

1. create a new symmetric key
2. export the symmetric key in base64
3. encrypt the symmetric key with the master key
4. return the server input
*/
fn prepare_register_sym_key_internally(master_key: &SymKeyFormatInt) -> Result<(String, SymKeyFormatInt), SdkError>
{
	let (encrypted_key, sym_key_alg, key) = crypto_core::generate_symmetric_with_master_key(&master_key.key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	let sym_key_format = SymKeyFormatInt {
		key,
		key_id: "".to_string(),
	};

	Ok((
		GeneratedSymKeyHeadServerInput {
			encrypted_key_string,
			alg: sym_key_alg.to_string(),
			master_key_id: master_key.key_id.to_string(),
		}
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)?,
		sym_key_format,
	))
}

/**
In two fn to avoid an extra request to get the key with the id
 */
fn done_register_sym_key_internally(key_id: &str, non_registered_sym_key: &mut SymKeyFormatInt)
{
	//put the key id to the non registered key
	non_registered_sym_key.key_id = key_id.to_string();
}

/**
# Prepare key register

but this time encrypted by a users public key

Return the non registered version but only to register the key on the server to get the id,
then put the id back in
*/
fn prepare_register_sym_key_by_public_key_internally(reply_public_key: &UserPublicKeyData) -> Result<(String, SymKeyFormatInt), SdkError>
{
	let public_key = import_public_key_from_pem_with_alg(
		reply_public_key.public_key_pem.as_str(),
		reply_public_key.public_key_alg.as_str(),
	)?;

	let (encrypted_key, sym_key_alg, key) = crypto_core::generate_symmetric_with_public_key(&public_key)?;

	let encrypted_key_string = Base64::encode_string(&encrypted_key);

	let sym_key_format = SymKeyFormatInt {
		key,
		key_id: "".to_string(),
	};

	Ok((
		GeneratedSymKeyHeadServerInput {
			encrypted_key_string,
			alg: sym_key_alg.to_string(),
			master_key_id: reply_public_key.public_key_id.to_string(),
		}
		.to_string()
		.map_err(|_| SdkError::JsonToStringFailed)?,
		sym_key_format,
	))
}

/**
# Get the key from server fetch

Decrypted the server output with the master key
*/
fn done_fetch_sym_key_internally(master_key: &SymKeyFormatInt, server_out: &str, non_registered: bool) -> Result<SymKeyFormatInt, SdkError>
{
	let out: GeneratedSymKeyHeadServerOutput = if non_registered {
		GeneratedSymKeyHeadServerOutput::from_string(server_out).map_err(SdkError::JsonParseFailed)?
	} else {
		handle_server_response(server_out)?
	};

	decrypt_sym_key_internally(master_key, &out)
}

/**
# Get the key from server fetch

decrypt it with the private key
*/
fn done_fetch_sym_key_by_private_key_internally(
	private_key: &PrivateKeyFormatInt,
	server_out: &str,
	non_registered: bool,
) -> Result<SymKeyFormatInt, SdkError>
{
	let out: GeneratedSymKeyHeadServerOutput = if non_registered {
		GeneratedSymKeyHeadServerOutput::from_string(server_out).map_err(SdkError::JsonParseFailed)?
	} else {
		handle_server_response(server_out)?
	};

	decrypt_sym_key_by_private_key_internally(private_key, &out)
}

/**
# Get the key from server fetch

like done_fetch_sym_key_internally but this time with an array of keys as server output
*/
fn done_fetch_sym_keys_internally(master_key: &SymKeyFormatInt, server_out: &str) -> Result<(Vec<SymKeyFormatInt>, u128, SymKeyId), SdkError>
{
	let server_out: Vec<GeneratedSymKeyHeadServerOutput> = handle_server_response(server_out)?;

	let mut keys = Vec::with_capacity(server_out.len());

	let last_element = &server_out[server_out.len() - 1];
	let last_time = last_element.time;
	let last_id = last_element.key_id.to_string();

	for out in server_out {
		keys.push(decrypt_sym_key_internally(master_key, &out)?)
	}

	Ok((keys, last_time, last_id))
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
) -> Result<SymKeyFormatInt, SdkError>
{
	let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| SdkError::KeyDecryptFailed)?;

	let key = crypto_core::get_symmetric_key_from_master_key(
		&master_key.key,
		&encrypted_sym_key,
		encrypted_symmetric_key_info.alg.as_str(),
	)?;

	Ok(SymKeyFormatInt {
		key,
		key_id: encrypted_symmetric_key_info.key_id.to_string(),
	})
}

/**
# Get a symmetric key which was encrypted by a public key
*/
fn decrypt_sym_key_by_private_key_internally(
	private_key: &PrivateKeyFormatInt,
	encrypted_symmetric_key_info: &GeneratedSymKeyHeadServerOutput,
) -> Result<SymKeyFormatInt, SdkError>
{
	let encrypted_sym_key = Base64::decode_vec(&encrypted_symmetric_key_info.encrypted_key_string).map_err(|_| SdkError::KeyDecryptFailed)?;

	let key = crypto_core::get_symmetric_key_from_private_key(
		&private_key.key,
		&encrypted_sym_key,
		encrypted_symmetric_key_info.alg.as_str(),
	)?;

	Ok(SymKeyFormatInt {
		key,
		key_id: encrypted_symmetric_key_info.key_id.to_string(),
	})
}

/**
# Simulates the server key output

This is used when the keys are not managed by the sentclose server.

First call prepare_register_sym_key_internally to encrypt the key, then decrypt_sym_key_internally to get the raw key.

Return both, the decrypted to use it, the encrypted to save it and use it for the next time with decrypt_sym_key_internally
*/
fn generate_non_register_sym_key_internally(master_key: &SymKeyFormatInt) -> Result<(SymKeyFormatInt, GeneratedSymKeyHeadServerOutput), SdkError>
{
	let (pre_out, _key) = prepare_register_sym_key_internally(master_key)?;

	let server_input = GeneratedSymKeyHeadServerInput::from_string(pre_out.as_str()).map_err(SdkError::JsonParseFailed)?;

	let server_output = GeneratedSymKeyHeadServerOutput {
		alg: server_input.alg,
		encrypted_key_string: server_input.encrypted_key_string,
		master_key_id: server_input.master_key_id,
		key_id: "non_registered".to_string(),
		time: 0,
	};

	let decrypt_out = decrypt_sym_key_internally(master_key, &server_output)?;

	Ok((decrypt_out, server_output))
}

fn generate_non_register_sym_key_by_public_key_internally(
	reply_public_key: &UserPublicKeyData,
) -> Result<(SymKeyFormatInt, GeneratedSymKeyHeadServerOutput), SdkError>
{
	let (pre_out, mut key) = prepare_register_sym_key_by_public_key_internally(reply_public_key)?;

	let server_input = GeneratedSymKeyHeadServerInput::from_string(pre_out.as_str()).map_err(SdkError::JsonParseFailed)?;

	let server_output = GeneratedSymKeyHeadServerOutput {
		alg: server_input.alg,
		encrypted_key_string: server_input.encrypted_key_string,
		master_key_id: server_input.master_key_id,
		key_id: "non_registered".to_string(),
		time: 0,
	};

	key.key_id = "non_registered".to_string();

	Ok((key, server_output))
}
