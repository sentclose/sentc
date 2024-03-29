#[cfg(not(feature = "rust"))]
mod non_rust;
#[cfg(feature = "rust")]
mod rust;

use alloc::string::String;

use sentc_crypto_utils::handle_server_response;
use sentc_crypto_utils::http::{make_req, HttpMethod};

#[cfg(not(feature = "rust"))]
pub(crate) use crate::content::non_rust::ContentRes;
#[cfg(feature = "rust")]
pub(crate) use crate::content::rust::ContentRes;

pub enum ContentFetchLimit
{
	Small,
	Medium,
	Large,
	XLarge,
}

pub async fn fetch_content_for_group(
	base_url: String,
	auth_token: &str,
	jwt: &str,
	id: &str,
	group_as_member: Option<&str>,
	cat_id: Option<&str>,
	last_fetched_time: &str,
	last_fetched_group_id: &str,
	limit: ContentFetchLimit,
) -> ContentRes
{
	let limit = match limit {
		ContentFetchLimit::Small => "small",
		ContentFetchLimit::Medium => "med",
		ContentFetchLimit::Large => "large",
		ContentFetchLimit::XLarge => "xlarge",
	};

	let url = match cat_id {
		Some(c_id) => base_url + "/api/v1/content/group/" + id + "/" + limit + "/" + c_id + "/" + last_fetched_time + "/" + last_fetched_group_id,
		None => base_url + "/api/v1/content/group/" + id + "/" + limit + "/" + "/all/" + last_fetched_time + "/" + last_fetched_group_id,
	};

	let res = make_req(
		HttpMethod::GET,
		url.as_str(),
		auth_token,
		None,
		Some(jwt),
		group_as_member,
	)
	.await?;

	Ok(handle_server_response(&res)?)
}
