use std::fmt::Display;

use crate::expr::exprs::Part;

pub trait Evaluable<State: ?Sized> {
    type Value;
    fn eval(&self, state: &State) -> Self::Value;
}

pub trait BeOperator<Value> {
    fn operand(&self) -> usize;

    fn operate(&self, values: &mut dyn Iterator<Item = Value>) -> Option<Value>;

    /// Dyn-compatible?
    fn short_circuit(&self, values: &mut dyn Iterator<Item = &Value>) -> Option<(Value, usize)> {
        _ = values;
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BooleanOperator {
    And,
    Or,
    Not,
}

impl Display for BooleanOperator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BooleanOperator::And => write!(f, "AND"),
            BooleanOperator::Or => write!(f, "OR"),
            BooleanOperator::Not => write!(f, "NOT"),
        }
    }
}

impl BeOperator<bool> for BooleanOperator {
    fn operand(&self) -> usize {
        match self {
            BooleanOperator::And => 2,
            BooleanOperator::Or => 2,
            BooleanOperator::Not => 1,
        }
    }

    fn operate(&self, values: &mut dyn Iterator<Item = bool>) -> Option<bool> {
        Some(match self {
            BooleanOperator::And => values.next()? && values.next()?,
            BooleanOperator::Or => values.next()? || values.next()?,
            BooleanOperator::Not => !values.next()?,
        })
    }

    fn short_circuit(&self, values: &mut dyn Iterator<Item = &bool>) -> Option<(bool, usize)> {
        match self {
            BooleanOperator::And => (!values.next()?).then_some((false, 1)),
            BooleanOperator::Or => values.next()?.then_some((true, 1)),
            BooleanOperator::Not => None,
        }
    }
}

impl<E: Clone> BeOperator<Result<bool, E>> for BooleanOperator {
    fn operand(&self) -> usize {
        <Self as BeOperator<bool>>::operand(self)
    }

    fn operate(
        &self,
        values: &mut dyn Iterator<Item = Result<bool, E>>,
    ) -> Option<Result<bool, E>> {
        Some(match self {
            BooleanOperator::And => {
                let l = values.next()?;
                let r = values.next()?;
                r.and_then(|r| l.map(|l| l && r))
            }
            BooleanOperator::Or => {
                let l = values.next()?;
                let r = values.next()?;
                r.and_then(|r| l.map(|l| l || r))
            }
            BooleanOperator::Not => {
                let v = values.next()?;
                v.map(|v| !v)
            }
        })
    }

    fn short_circuit(
        &self,
        values: &mut dyn Iterator<Item = &Result<bool, E>>,
    ) -> Option<(Result<bool, E>, usize)> {
        match self {
            BooleanOperator::And => match values.next()? {
                Ok(false) => Some((Ok(false), 1)),
                Err(e) => Some((Err(e.clone()), 1)),
                Ok(true) => None,
            },
            BooleanOperator::Or => match values.next()? {
                Ok(true) => Some((Ok(true), 1)),
                Err(e) => Some((Err(e.clone()), 1)),
                Ok(false) => None,
            },
            BooleanOperator::Not => None,
        }
    }
}

impl BeOperator<()> for BooleanOperator {
    fn operand(&self) -> usize {
        <Self as BeOperator<bool>>::operand(self)
    }

    fn operate(&self, values: &mut dyn Iterator<Item = ()>) -> Option<()> {
        for _ in 0..(<Self as BeOperator<()>>::operand(self)) {
            values.next()?;
        }
        Some(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, snafu::Snafu)]
pub enum EvalPolishError {
    #[snafu(display("polish notation expression is incomplete"))]
    IncompleteExpression,
    #[snafu(display("polish notation expression contains extra operands"))]
    ExtraOperands,
    #[snafu(display("polish notation operator is missing operands"))]
    MissingOperands,
}

pub struct VM<Operator, Value> {
    short_circuit: usize,
    ops: Vec<Operator>,
    values: Vec<Value>,
}

impl<Operator, Value> Default for VM<Operator, Value> {
    fn default() -> Self {
        Self {
            short_circuit: Default::default(),
            ops: Default::default(),
            values: Default::default(),
        }
    }
}

impl<Operator: BeOperator<Value>, Value> VM<Operator, Value> {
    pub fn new() -> Self {
        Self::default()
    }

    fn try_eval(&mut self) -> Result<(), EvalPolishError> {
        while let Some(op) = self.ops.last() {
            if self.values.len() >= op.operand() {
                let value = op
                    .operate(&mut self.values.drain(self.values.len() - op.operand()..))
                    .ok_or(EvalPolishError::MissingOperands)?;
                self.values.push(value);
                self.ops.pop();
            } else if let Some((value, consumed)) = op.short_circuit(&mut self.values.iter().rev())
            {
                self.values.truncate(self.values.len() - consumed);
                self.values.push(value);
                self.short_circuit += op.operand() - consumed;
                self.ops.pop();
            } else {
                break;
            }
        }
        Ok(())
    }

    pub fn try_run(
        mut self,
        parts: impl IntoIterator<Item = Part<Operator, Value>>,
    ) -> Result<Value, EvalPolishError> {
        for part in parts {
            match (part, self.short_circuit) {
                (Part::Operator(opeartor), 0) => {
                    self.ops.push(opeartor);
                }
                (Part::Expr(value), 0) => {
                    self.values.push(value);
                    self.try_eval()?;
                }
                (Part::Operator(opeartor), _n) => self.short_circuit += opeartor.operand() - 1,
                (Part::Expr(_value), _n) => self.short_circuit -= 1,
            }
        }
        if !self.ops.is_empty() || self.short_circuit != 0 || self.values.is_empty() {
            return Err(EvalPolishError::IncompleteExpression);
        }
        if self.values.len() != 1 {
            return Err(EvalPolishError::ExtraOperands);
        }
        self.values
            .pop()
            .ok_or(EvalPolishError::IncompleteExpression)
    }
}

pub trait EvalRuleError<Action> {
    fn fallback(&self, matched_action: Action) -> Option<Action>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::expr::exprs::Part;

    #[test]
    fn boolean_operator_missing_operands_returns_none() {
        let mut values = std::iter::empty::<bool>();

        assert_eq!(BooleanOperator::And.operate(&mut values), None);
    }

    #[test]
    fn vm_reports_incomplete_polish_notation() {
        let result =
            VM::<BooleanOperator, bool>::new().try_run([Part::Operator(BooleanOperator::And)]);

        assert!(matches!(result, Err(EvalPolishError::IncompleteExpression)));
    }

    #[test]
    fn vm_reports_extra_operands() {
        let result =
            VM::<BooleanOperator, bool>::new().try_run([Part::Expr(true), Part::Expr(false)]);

        assert!(matches!(result, Err(EvalPolishError::ExtraOperands)));
    }
}
