pub(crate) mod ed25519;

pub enum SignK
{
	Ed25519([u8; 32]),
}

pub enum VerifyK
{
	Ed25519([u8; 32]),
}

pub struct SignOutput
{
	pub alg: &'static str,
	pub sign_key: SignK,
	pub verify_key: VerifyK,
}
