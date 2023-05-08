use alloc::vec::Vec;

use sentc_crypto_common::content::ListContentItem;

use crate::SdkFullError;

pub type ContentRes = Result<Vec<ListContentItem>, SdkFullError>;
