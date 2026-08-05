use sea_orm::DbErr;

use crate::error::location::{LocateLocationFailed, MatchLocationFailed};

use super::location_service::{RemoveRuleByIdFailed, RemoveRuleFailed, ReplaceRuleByIdFailed};

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum EnsureStoreError {
    #[snafu(display("failed to query access store location rule sets"))]
    QueryStore { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum ListRuleSetsError {
    #[snafu(display("failed to query location rule sets"))]
    QueryRuleSets { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum MatchLocationError {
    #[snafu(display("failed to query exact location rule set"))]
    QueryExactLocation { source: DbErr },
    #[snafu(display("failed to query location rule sets for pattern matching"))]
    QueryLocations { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum ListRulesError {
    #[snafu(display("failed to begin transaction for listing location rules"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to match location rule set while listing rules"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("location rule set does not match request path"))]
    NoMatchedLocation { source: MatchLocationFailed },
    #[snafu(display("failed to load location rules"))]
    LoadRules { source: DbErr },
    #[snafu(display("failed to commit transaction after listing location rules"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum ListRulesByPatternError {
    #[snafu(display("failed to begin transaction for listing location rules by pattern"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to locate location rule set while listing rules by pattern"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("location rule set does not exist"))]
    LocationNotExist { source: LocateLocationFailed },
    #[snafu(display("failed to load location rules by pattern"))]
    LoadRules { source: DbErr },
    #[snafu(display("failed to commit transaction after listing location rules by pattern"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum RemoveRuleSetError {
    #[snafu(display("failed to begin transaction for removing location rule set"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to locate location rule set before removal"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("location rule set does not exist"))]
    LocationNotExist { source: LocateLocationFailed },
    #[snafu(display("failed to delete location rule set"))]
    DeleteRuleSet { source: DbErr },
    #[snafu(display("failed to commit transaction after removing location rule set"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum ListAllRulesError {
    #[snafu(display("failed to begin transaction for listing all location rules"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to load all location rule sets"))]
    LoadLocations { source: DbErr },
    #[snafu(display("failed to load all location rules"))]
    LoadRules { source: DbErr },
    #[snafu(display("failed to commit transaction after listing all location rules"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum RemoveRulesError {
    #[snafu(display("failed to begin transaction for removing location rules"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to locate location rule set before removing rules"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("failed to select location rule ids for removal"))]
    LoadRuleIds { source: DbErr },
    #[snafu(display("location rule cannot be removed"))]
    Rule { source: RemoveRuleFailed },
    #[snafu(display("failed to delete location rules"))]
    DeleteRules { source: DbErr },
    #[snafu(display("failed to commit transaction after removing location rules"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum RemoveRulesByIdsError {
    #[snafu(display("failed to begin transaction for removing location rules by ids"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to locate location rule set before removing rules by ids"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("failed to load requested location rules by ids"))]
    LoadRules { source: DbErr },
    #[snafu(display("location rule cannot be removed by id"))]
    Rule { source: RemoveRuleByIdFailed },
    #[snafu(display("failed to delete location rules by ids"))]
    DeleteRules { source: DbErr },
    #[snafu(display("failed to commit transaction after removing location rules by ids"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum MatchOrCreateLocationError {
    #[snafu(display("failed to locate location rule set before creating it"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("failed to insert location rule set"))]
    InsertLocation { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum AppendRuleError {
    #[snafu(display("failed to begin transaction for appending location rule"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to match or create location rule set before appending rule"))]
    MatchOrCreateLocation { source: MatchOrCreateLocationError },
    #[snafu(display("failed to load existing location rules before appending rule"))]
    LoadExistingRules { source: DbErr },
    #[snafu(display("failed to insert location rule"))]
    InsertRule { source: DbErr },
    #[snafu(display("failed to load inserted location rule"))]
    LoadInsertedRule { source: DbErr },
    #[snafu(display("inserted location rule `{id}` could not be loaded"))]
    InsertedRuleMissing { id: i32 },
    #[snafu(display("failed to commit transaction after appending location rule"))]
    Commit { source: DbErr },
}

#[derive(Debug, snafu::Snafu)]
#[snafu(module, visibility(pub(crate)))]
pub enum ReplaceRuleByIdError {
    #[snafu(display("failed to begin transaction for replacing location rule by id"))]
    BeginTransaction { source: DbErr },
    #[snafu(display("failed to locate location rule set before replacing rule by id"))]
    MatchLocation { source: MatchLocationError },
    #[snafu(display("failed to load current location rule by id"))]
    LoadRule { source: DbErr },
    #[snafu(display("location rule cannot be replaced by id"))]
    Rule { source: ReplaceRuleByIdFailed },
    #[snafu(display("failed to update location rule by id"))]
    UpdateRule { source: DbErr },
    #[snafu(display("failed to commit transaction after replacing location rule by id"))]
    Commit { source: DbErr },
}
