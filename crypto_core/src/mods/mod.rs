use alloc::vec::Vec;

use crate::{alg, ClientRandomValue};

pub(crate) mod user;

pub fn generate_salt(client_random_value: ClientRandomValue) -> Vec<u8>
{
	match client_random_value {
		ClientRandomValue::Argon2(v) => alg::pw_hash::argon2::generate_salt(v),
	}
}
