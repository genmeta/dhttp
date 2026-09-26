use std::path::PathBuf;

use crate::{
    action::RequestAction,
    db::entities::location::{location, rule},
    matcher::LocationRulesMatcher,
};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Set, Statement};

use super::service::location_service::LocationService;
use super::*;

struct TestHome {
    path: PathBuf,
}

impl TestHome {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "dhttp-access-db-tests-{name}-{}",
            chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn home(&self) -> DhttpHome {
        DhttpHome::new(self.path.clone())
    }
}

impl Drop for TestHome {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

include!("schema.rs");
include!("rules.rs");
include!("behavior.rs");
