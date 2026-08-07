use sea_orm_migration::prelude::*;

const INDEX_NAME: &str = "idx_location_rules_logical_unique";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Keep the earliest row for each logical rule before adding the constraint.
        manager
            .get_connection()
            .execute_unprepared(
                r#"DELETE FROM location_rules
                   WHERE id NOT IN (
                       SELECT MIN(id)
                       FROM location_rules
                       GROUP BY location_id, action, json_extract(exprs, '$.polish')
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
