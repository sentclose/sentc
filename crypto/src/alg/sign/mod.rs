pub(crate) mod ed25519;

pub(crate) enum SignK
{
	Ed25519([u8; 32]),
}

pub(crate) enum VerifyK
{
	Ed25519([u8; 32]),
}

pub(crate) struct SignOutput
{
	pub alg: &'static str,
	pub sign_key: SignK,
	pub verify_key: VerifyK,
}
