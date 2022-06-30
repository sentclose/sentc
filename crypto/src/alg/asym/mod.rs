pub(crate) mod ecies;

pub(crate) enum Pk
{
	Ecies([u8; 32]),
}

pub(crate) enum Sk
{
	Ecies([u8; 32]),
}

pub(crate) struct AsymKeyOutput
{
	pub pk: Pk,
	pub sk: Sk,
	pub alg: &'static str,
}
