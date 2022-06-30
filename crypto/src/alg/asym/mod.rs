pub(crate) mod ecies;

pub enum Pk
{
	Ecies([u8; 32]),
}

pub enum Sk
{
	Ecies([u8; 32]),
}

pub(crate) struct AsymKeyOutput
{
	pub pk: Pk,
	pub sk: Sk,
	pub alg: &'static str,
}
