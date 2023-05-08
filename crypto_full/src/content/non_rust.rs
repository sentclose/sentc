use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::content::ListContentItem;

pub type ContentRes = Result<Vec<ListContentItem>, String>;
