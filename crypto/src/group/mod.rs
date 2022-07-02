//use here key ids from the api, the core sdk don't care about the ids because we have to call every function with the right keys
//but in the higher level mod we must care
//handle the key id for get group, and the rotation + accept / invite user

use base64ct::{Base64, Encoding};
use sendclose_crypto_common::group::{CreateData, KeyRotationData};
use sendclose_crypto_core::group::{key_rotation as key_rotation_core, prepare_create as prepare_create_core};
use sendclose_crypto_core::{Error, Pk, Sk, SymKey};

use crate::user::export_key_to_pem;

#[cfg(not(feature = "rust"))]
mod group;

#[cfg(feature = "rust")]
mod group_rust;

#[cfg(not(feature = "rust"))]
pub use self::group::{key_rotation, prepare_create};
#[cfg(feature = "rust")]
pub use self::group_rust::{key_rotation, prepare_create};

fn prepare_create_internally(creators_public_key: &Pk, creator_public_key_id: String) -> Result<String, Error>
{
	let out = prepare_create_core(creators_public_key)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key = Base64::encode_string(&out.encrypted_group_key);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);

	//2. export the public key
	let public_group_key = match out.public_group_key {
		Pk::Ecies(k) => export_key_to_pem(&k)?,
	};

	let create_out = CreateData {
		public_group_key,
		encrypted_group_key,
		encrypted_private_group_key,
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		group_key_alg: out.group_key_alg.to_string(),
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		creator_public_key_id,
	};

	Ok(create_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}

fn key_rotation_internally(
	previous_group_key: &SymKey,
	invoker_public_key: &Pk,
	previous_group_key_id: String,
	invoker_public_key_id: String,
) -> Result<String, Error>
{
	let out = key_rotation_core(previous_group_key, invoker_public_key)?;

	//1. encode the values to base64 for the server
	let encrypted_group_key_by_user = Base64::encode_string(&out.encrypted_group_key_by_user);
	let encrypted_private_group_key = Base64::encode_string(&out.encrypted_private_group_key);
	let encrypted_group_key_by_ephemeral = Base64::encode_string(&out.encrypted_group_key_by_ephemeral);
	let encrypted_ephemeral_key = Base64::encode_string(&out.encrypted_ephemeral_key);

	//2. export the public key
	let public_group_key = match out.public_group_key {
		Pk::Ecies(k) => export_key_to_pem(&k)?,
	};

	let rotation_out = KeyRotationData {
		encrypted_group_key_by_user,
		group_key_alg: out.group_key_alg.to_string(),
		encrypted_group_key_alg: out.encrypted_group_key_alg.to_string(),
		encrypted_private_group_key,
		public_group_key,
		keypair_encrypt_alg: out.keypair_encrypt_alg.to_string(),
		encrypted_group_key_by_ephemeral,
		ephemeral_alg: out.ephemeral_alg.to_string(),
		encrypted_ephemeral_key,
		previous_group_key_id,
		invoker_public_key_id,
	};

	Ok(rotation_out
		.to_string()
		.map_err(|_| Error::JsonToStringFailed)?)
}
