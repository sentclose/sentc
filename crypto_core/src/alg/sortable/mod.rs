use crate::alg::sortable::ope::OPE_OUT;

pub(crate) mod ope;

pub enum SortableKey
{
	Ope([u8; 16]),
}

pub struct SortableOutput
{
	pub alg: &'static str,
	pub key: SortableKey,
}

pub fn getting_alg_from_sortable_key(key: &SortableKey) -> &'static str
{
	match key {
		SortableKey::Ope(_) => OPE_OUT,
	}
}
