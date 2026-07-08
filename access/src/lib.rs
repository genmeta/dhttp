pub mod action;
pub mod error;
pub mod expr;
pub mod matcher;
pub mod pattern;
pub mod policy;

#[macro_export]
#[cfg(feature = "orm")]
macro_rules! orm_new_type {
    (@json $ty:ty) => {
        const _: () = {
            use std::any::type_name;

            use sea_orm::sea_query::{ArrayType, ValueType, ValueTypeErr};
            use sea_orm::{ColIdx, ColumnType, DbErr, QueryResult, TryGetError, TryGetable, Value};

            impl ValueType for $ty {
                #[inline]
                fn try_from(v: Value) -> Result<Self, ValueTypeErr> {
                    let value = <serde_json::Value as ValueType>::try_from(v)?;
                    serde_json::from_value(value).map_err(|_| ValueTypeErr)
                }

                #[inline]
                fn type_name() -> String {
                    String::from(type_name::<Self>())
                }

                #[inline]
                fn array_type() -> ArrayType {
                    ArrayType::Json
                }

                #[inline]
                fn column_type() -> ColumnType {
                    ColumnType::Json
                }
            }

            impl TryGetable for $ty {
                #[inline]
                fn try_get_by<I: ColIdx>(res: &QueryResult, index: I) -> Result<Self, TryGetError> {
                    res.try_get_by::<serde_json::Value, I>(index)
                        .and_then(|value| {
                            serde_json::from_value::<Self>(value)
                                .map_err(|e| DbErr::Type(e.to_string()))
                        })
                        .map_err(TryGetError::DbErr)
                }
            }

            impl From<$ty> for Value {
                fn from(value: $ty) -> Self {
                    Self::from(serde_json::to_value(value).unwrap())
                }
            }
        };
    };
}

#[macro_export]
#[cfg(not(feature = "orm"))]
macro_rules! orm_new_type {
    (@json $ty:ty) => {};
}

#[cfg(feature = "orm")]
pub mod db;
#[cfg(feature = "migration")]
pub mod migration;
