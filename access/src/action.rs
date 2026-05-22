use std::fmt::Display;

#[cfg(feature = "orm")]
use sea_orm::{DeriveActiveEnum, EnumIter};
use serde::{Deserialize, Serialize};

/// 访问控制动作类型
///
/// 定义了当规则匹配时应该执行的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "orm", derive(EnumIter, DeriveActiveEnum))]
#[cfg_attr(feature = "orm", sea_orm(rs_type = "i32", db_type = "Integer"))]
pub enum ConnectionAction {
    /// 允许连接
    #[cfg_attr(feature = "orm", sea_orm(num_value = 0))]
    Allow,

    /// 静默丢弃连接
    #[cfg_attr(feature = "orm", sea_orm(num_value = 1))]
    Deny,
}

impl ConnectionAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            ConnectionAction::Allow => "allow",
            ConnectionAction::Deny => "deny",
        }
    }
}

impl Display for ConnectionAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "cli", derive(clap::ValueEnum))]
#[cfg_attr(feature = "orm", derive(EnumIter, DeriveActiveEnum))]
#[cfg_attr(feature = "orm", sea_orm(rs_type = "i32", db_type = "Integer"))]
pub enum RequestAction {
    /// 允许请求
    #[cfg_attr(feature = "orm", sea_orm(num_value = 0))]
    Allow,
    /// 拒绝请求
    #[cfg_attr(feature = "orm", sea_orm(num_value = 1))]
    Deny,
}

impl RequestAction {
    fn as_str(&self) -> &'static str {
        match self {
            RequestAction::Allow => "allow",
            RequestAction::Deny => "deny",
        }
    }
}

impl Display for RequestAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
