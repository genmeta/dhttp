use sea_orm_migration::prelude::*;

const INDEX_NAME: &str = "idx_location_rules_logical_unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Rule evaluation is newest-first, so preserve the effective rule when
        // collapsing duplicates before adding the constraint.
        manager
            .get_connection()
            .execute_unprepared(
                r#"DELETE FROM location_rules AS older
                   WHERE EXISTS (
                       SELECT 1
                       FROM location_rules AS newer
                       WHERE newer.location_id = older.location_id
                         AND newer.action = older.action
                         AND json_extract(newer.exprs, '$.polish')
                             IS json_extract(older.exprs, '$.polish')
                         AND (
                             newer.created_at > older.created_at
                             OR (
                                 newer.created_at = older.created_at
                                 AND newer.id > older.id
                             )
                         )
                   )"#,
            )
            .await?;

        manager
            .get_connection()
            .execute_unprepared(&format!(
                "CREATE UNIQUE INDEX IF NOT EXISTS {INDEX_NAME} ON location_rules \
                 (location_id, action, json_extract(exprs, '$.polish'))"
            ))
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .get_connection()
            .execute_unprepared(&format!("DROP INDEX IF EXISTS {INDEX_NAME}"))
            .await?;

        Ok(())
    }
}
