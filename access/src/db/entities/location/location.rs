use crate::pattern::LocationPattern;
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 位置规则集
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "location_rule_sets")]
pub struct Model {
    /// 规则集ID，主键
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    /// URL路径匹配模式
    #[sea_orm(unique)]
    pub pattern: LocationPattern,
    /// 创建时间
    pub created_at: DateTimeUtc,
    /// 更新时间
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::Rule")]
    Rules,
}

impl Related<super::Rule> for Entity {
    fn to() -> RelationDef {
        Relation::Rules.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
