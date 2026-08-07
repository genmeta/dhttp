pub use sea_orm_migration::prelude::*;

mod m20250909_154000_create_table;
mod m20260807_120000_unique_location_rules;

pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    // Override the name of migration table
    fn migration_table_name() -> sea_orm::DynIden {
        Alias::new("migration").into_iden()
    }

    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20250909_154000_create_table::Migration),
            Box::new(m20260807_120000_unique_location_rules::Migration),
        ]
    }
}
