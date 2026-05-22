use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 启用外键约束
        manager
            .get_connection()
            .execute_unprepared("PRAGMA foreign_keys = ON;")
            .await?;

        // 创建位置规则集表
        manager
            .create_table(
                Table::create()
                    .table(LocationRuleSets::Table)
                    .if_not_exists()
                    .col(pk_auto(LocationRuleSets::Id))
                    .col(string_uniq(LocationRuleSets::Pattern))
                    .col(timestamp(LocationRuleSets::CreatedAt))
                    .col(timestamp(LocationRuleSets::UpdatedAt))
                    .to_owned(),
            )
            .await?;

        // 创建位置规则表
        manager
            .create_table(
                Table::create()
                    .table(LocationRules::Table)
                    .if_not_exists()
                    .col(pk_auto(LocationRules::Id))
                    .col(integer(LocationRules::LocationId))
                    .col(integer(LocationRules::Action))
                    .col(json(LocationRules::Exprs))
                    .col(timestamp(LocationRules::CreatedAt))
                    .col(timestamp(LocationRules::UpdatedAt))
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-location_rule-location_id")
                            .from(LocationRules::Table, LocationRules::LocationId)
                            .to(LocationRuleSets::Table, LocationRuleSets::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 按相反顺序删除表（先删除有外键的表）
        manager
            .drop_table(Table::drop().table(LocationRules::Table).to_owned())
            .await?;

        manager
            .drop_table(Table::drop().table(LocationRuleSets::Table).to_owned())
            .await?;

        Ok(())
    }
}

// 位置规则集表
#[derive(DeriveIden)]
enum LocationRuleSets {
    Table,
    Id,
    Pattern,
    CreatedAt,
    UpdatedAt,
}

// 位置规则表
#[derive(DeriveIden)]
enum LocationRules {
    Table,
    Id,
    LocationId,
    Action,
    Exprs,
    CreatedAt,
    UpdatedAt,
}
