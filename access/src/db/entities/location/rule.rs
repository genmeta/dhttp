use crate::{action::RequestAction, expr::exprs::LocationRuleExprs};
use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// 位置规则
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "location_rules")]
pub struct Model {
    /// 规则ID，主键
    #[sea_orm(primary_key, auto_increment = true)]
    pub id: i32,
    /// 所属位置规则集ID，建立索引以优化查询性能
    // #[sea_orm(indexed)]
    pub location_id: i32,
    /// 访问控制动作：allow/deny
    pub action: RequestAction,
    /// 规则表达式
    pub exprs: LocationRuleExprs,
    /// 创建时间
    pub created_at: DateTimeUtc,
    /// 更新时间
    pub updated_at: DateTimeUtc,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::Location",
        from = "Column::LocationId",
        to = "super::location::Column::Id",
        on_delete = "Cascade"
    )]
    Location,
}

impl Related<super::Location> for Entity {
    fn to() -> RelationDef {
        Relation::Location.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
