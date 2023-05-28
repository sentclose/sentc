use crate::ED25519_OUTPUT;

pub(crate) mod ed25519;

pub enum SignK
{
	Ed25519([u8; 32]),
}

pub enum VerifyK
{
	Ed25519([u8; 32]),
}

pub(crate) struct SignOutput
{
	pub alg: &'static str,
	pub sign_key: SignK,
	pub verify_key: VerifyK,
}

pub struct SafetyNumber<'a>
{
	pub verify_key: &'a VerifyK,
	pub user_info: &'a str,
}

pub fn get_alg_from_sign_key(key: SignK) -> &'static str
{
	match key {
		SignK::Ed25519(_) => ED25519_OUTPUT,
	}
}

pub fn get_alg_from_verify_key(key: VerifyK) -> &'static str
{
	match key {
		VerifyK::Ed25519(_) => ED25519_OUTPUT,
	}
}
