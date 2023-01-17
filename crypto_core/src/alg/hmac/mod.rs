use crate::HMAC_SHA256_OUTPUT;

pub(crate) mod hmac_sha256;

pub enum HmacKey
{
	HmacSha256([u8; 32]),
}

pub struct HmacKeyOutput
{
	pub alg: &'static str,
	pub key: HmacKey,
}

pub fn getting_alg_from_hmac_key(key: &HmacKey) -> &'static str
{
	match key {
		HmacKey::HmacSha256(_) => HMAC_SHA256_OUTPUT,
	}
}
