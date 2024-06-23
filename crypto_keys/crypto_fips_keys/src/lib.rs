#![allow(clippy::infallible_destructuring_match, clippy::tabs_in_doc_comments, clippy::from_over_into)]

pub mod core;
#[cfg(all(feature = "sdk", feature = "full"))]
pub mod sdk;
#[cfg(feature = "wrapper")]
pub mod util;

//Load openssl in fips mode: openssl::provider::Provider::load(None, "fips")?;
