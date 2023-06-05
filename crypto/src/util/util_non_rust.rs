use alloc::string::String;

use base64ct::{Base64, Encoding};
use sentc_crypto_core::SymKey;
use serde::{Deserialize, Serialize};
use serde_json::{from_str, to_string};

use crate::SdkError;

#[derive(Serialize, Deserialize)]
pub enum ExportedCoreSymKey
{
	Aes
	{
		key: String
	},
}

/**
Export a core sym key.

This is only used when this key is stored in the client and is never send to the server
*/
pub(crate) fn export_core_sym_key(key: SymKey) -> ExportedCoreSymKey
{
	match key {
		SymKey::Aes(k) => {
			let sym_key = Base64::encode_string(&k);

			ExportedCoreSymKey::Aes {
				key: sym_key,
			}
		},
	}
}

pub(crate) fn export_core_sym_key_to_string(key: SymKey) -> Result<String, SdkError>
{
	let key = export_core_sym_key(key);

	to_string(&key).map_err(|_e| SdkError::JsonToStringFailed)
}

pub(crate) fn import_core_sym_key(key_string: &str) -> Result<SymKey, SdkError>
{
	let key_format = from_str(key_string).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

	import_core_sym_key_from_format(&key_format)
}

pub(crate) fn import_core_sym_key_from_format(key: &ExportedCoreSymKey) -> Result<SymKey, SdkError>
{
	match key {
		ExportedCoreSymKey::Aes {
			key,
		} => {
			//to bytes via base64
			let bytes = Base64::decode_vec(key.as_str()).map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

			let key = bytes
				.try_into()
				.map_err(|_| SdkError::ImportSymmetricKeyFailed)?;

			Ok(SymKey::Aes(key))
		},
	}
}
