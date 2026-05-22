use crate::expr::{
    eval::{BooleanOperator, EvalRuleError, Evaluable},
    exprs::Exprs,
};

pub struct Rule<'e, Expr, Action> {
    exprs: &'e Exprs<BooleanOperator, Expr>,
    action: Action,
}

impl<'e, Expr, Action> Rule<'e, Expr, Action> {
    pub fn new(exprs: &'e Exprs<BooleanOperator, Expr>, action: Action) -> Self {
        Self { exprs, action }
    }
}

impl<State, Expr, E, Action> Evaluable<State> for Rule<'_, Expr, Action>
where
    State: ?Sized,
    Expr: Evaluable<State, Value = Result<bool, E>>,
    E: EvalRuleError<Action> + Clone,
    Action: Clone,
{
    type Value = Option<Action>;

    fn eval(&self, state: &State) -> Self::Value {
        match self.exprs.try_eval(state) {
            Ok(Ok(matched)) => matched.then_some(self.action.clone()),
            Ok(Err(eval_error)) => eval_error.fallback(self.action.clone()),
            Err(_invalid_polish) => None,
        }
    }
}
