#[cfg(not(feature = "rust"))]
use alloc::string::String;

use crate::SdkError;

#[cfg(feature = "rust")]
pub type VoidRes = Result<(), SdkError>;

#[cfg(not(feature = "rust"))]
pub type VoidRes = Result<(), String>;

pub fn check_kick_user(user_rank: i32, admin_rank: i32) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkError::GroupPermission)?;
	}

	if admin_rank > user_rank {
		//user has a higher rank
		return Err(SdkError::GroupUserKickRank)?;
	}

	Ok(())
}

pub fn check_group_delete(admin_rank: i32) -> VoidRes
{
	if admin_rank > 1 {
		return Err(SdkError::GroupPermission)?;
	}

	Ok(())
}

pub fn check_get_join_reqs(admin_rank: i32) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkError::GroupPermission)?;
	}

	Ok(())
}

pub fn check_make_invite_req(admin_rank: i32) -> VoidRes
{
	if admin_rank > 2 {
		return Err(SdkError::GroupPermission)?;
	}

	Ok(())
}

pub fn check_create_sub_group(admin_rank: i32) -> VoidRes
{
	if admin_rank > 1 {
		return Err(SdkError::GroupPermission)?;
	}

	Ok(())
}
