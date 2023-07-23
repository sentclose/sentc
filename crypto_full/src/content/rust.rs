use alloc::vec::Vec;

use sentc_crypto::SdkError;
use sentc_crypto_common::content::ListContentItem;

pub type ContentRes = Result<Vec<ListContentItem>, SdkError>;
