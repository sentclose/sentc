use sendclose_crypto_core::{Error, Pk, SymKey};

use crate::group::{key_rotation_internally, prepare_create_internally};

pub fn prepare_create(creators_public_key: &Pk, creator_public_key_id: String) -> Result<String, Error>
{
	prepare_create_internally(creators_public_key, creator_public_key_id)
}

pub fn key_rotation(
	previous_group_key: &SymKey,
	invoker_public_key: &Pk,
	previous_group_key_id: String,
	invoker_public_key_id: String,
) -> Result<String, Error>
{
	key_rotation_internally(previous_group_key, invoker_public_key, previous_group_key_id, invoker_public_key_id)
}
