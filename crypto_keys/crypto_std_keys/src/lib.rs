#![no_std]
#![allow(clippy::infallible_destructuring_match, clippy::tabs_in_doc_comments, clippy::from_over_into)]

extern crate alloc;

use rand_core::{CryptoRng, OsRng, RngCore};

pub mod core;
#[cfg(feature = "wrapper")]
pub mod util;

fn get_rand() -> impl CryptoRng + RngCore
{
	#[cfg(feature = "default_env")]
	OsRng
}
