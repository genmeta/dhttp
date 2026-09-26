use std::{
    borrow::{Borrow, Cow},
    fmt::{self, Display},
    hash::{Hash, Hasher},
    ops::Deref,
    str::FromStr,
};

use bytes::{Bytes, BytesMut};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt, Snafu};

// Keep the existing private types and conversions in this module.
include!("name/bytes.rs");
include!("name/validation.rs");
include!("name/dns_name.rs");
include!("name/dhttp_name.rs");
include!("name/conversions.rs");

#[cfg(test)]
#[path = "../tests/unit/name.rs"]
mod tests;
