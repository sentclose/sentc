use alloc::string::String;
use alloc::vec::Vec;

use sentc_crypto_common::file::FileData;

pub type FileRes = Result<FileData, String>;
pub type ByteRes = Result<Vec<u8>, String>;
pub type VoidRes = Result<(), String>;

pub type FileRegRes = Result<String, String>;
