//! This module exists to contain submodules that correspond to types that we
//! know how to humanize. These submodules are suitable for use with
//! #[serde(with = "module")].

pub mod duration;
pub mod percentage;
pub mod time_of_day;
pub mod tokens;
