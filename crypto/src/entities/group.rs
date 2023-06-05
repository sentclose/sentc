use alloc::string::String;

use sentc_crypto_common::{EncryptionKeyPairId, SymKeyId};
use serde::{Deserialize, Serialize};

//==================================================================================================
//export

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataKeyExport
{
	pub private_key_id: EncryptionKeyPairId,
	pub key_data: String, //serde string
}

#[derive(Serialize, Deserialize)]
pub struct GroupOutDataHmacKeyExport
{
	pub group_key_id: SymKeyId,
	pub key_data: String, //serde string
}
