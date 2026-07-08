use std::{future::Future, pin::Pin};

use snafu::Snafu;

use crate::{
    action::RequestAction,
    expr::{
        atomics::{AtomicLocationRuleExpr, EvalError},
        eval::Evaluable,
    },
    pattern::LocationPattern,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocationRuleDecision {
    pub location: LocationPattern,
    pub action: RequestAction,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LocationRuleDecisionError {
    #[snafu(display("no access rule set matched request path `{path}`"))]
    NoRuleSet { path: String },

    #[snafu(display("access rule set `{location}` matched, but no rule matched"))]
    NoRuleInSet { location: LocationPattern },

    #[snafu(display("failed to evaluate access rules from backend"))]
    Backend {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

impl LocationRuleDecisionError {
    pub fn backend<E>(source: E) -> Self
    where
        E: std::error::Error + Send + Sync + 'static,
    {
        Self::Backend {
            source: Box::new(source),
        }
    }
}

pub type LocationRuleResult = Result<LocationRuleDecision, LocationRuleDecisionError>;

pub type LocationRuleFuture<'a> = Pin<Box<dyn Future<Output = LocationRuleResult> + Send + 'a>>;

pub trait LocationRuleRequest: Send + Sync {
    fn eval_atomic(&self, expr: &AtomicLocationRuleExpr) -> Result<bool, EvalError>;
}

pub trait LocationRuleEvaluator: Send + Sync {
    fn evaluate<'a>(
        &'a self,
        path: &'a str,
        request: &'a (dyn LocationRuleRequest + Send + Sync),
    ) -> LocationRuleFuture<'a>;
}

impl Evaluable<dyn LocationRuleRequest + Send + Sync + '_> for AtomicLocationRuleExpr {
    type Value = Result<bool, EvalError>;

    fn eval(&self, request: &(dyn LocationRuleRequest + Send + Sync + '_)) -> Self::Value {
        request.eval_atomic(self)
    }
}
