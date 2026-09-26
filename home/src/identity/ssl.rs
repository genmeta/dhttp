use std::{
    iter,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

use futures::{Stream, StreamExt, stream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use snafu::{IntoError, ResultExt, Snafu};
use tokio::{
    fs::{self, ReadDir},
    io::{self, AsyncWriteExt},
};
use x509_parser::prelude::Pem;

use crate::identity::{Identity, normalize_profile_name};

use crate::{
    DhttpHome,
    identity::{IdentityProfile, IdentityProfileFromPathError},
};

pub const SSL_DIR_NAME: &str = "ssl";
pub const CERT_FILE_NAME: &str = "fullchain.crt";
pub const KEY_FILE_NAME: &str = "privkey.pem";
pub const OCSP_FILE_NAME: &str = "ocsp.der";

static SAVE_IDENTITY_TRANSACTION_ID: AtomicU64 = AtomicU64::new(0);

include!("ssl/errors.rs");
include!("ssl/profile.rs");
include!("ssl/home.rs");

#[cfg(test)]
#[path = "../../tests/unit/ssl.rs"]
mod tests;
