use super::*;
use crate::expr::exprs::Part;

#[test]
fn boolean_operator_missing_operands_returns_none() {
    let mut values = std::iter::empty::<bool>();

    assert_eq!(BooleanOperator::And.operate(&mut values), None);
}

#[test]
fn vm_reports_incomplete_polish_notation() {
    let result = VM::<BooleanOperator, bool>::new().try_run([Part::Operator(BooleanOperator::And)]);

    assert!(matches!(result, Err(EvalPolishError::IncompleteExpression)));
}

#[test]
fn vm_reports_extra_operands() {
    let result = VM::<BooleanOperator, bool>::new().try_run([Part::Expr(true), Part::Expr(false)]);

    assert!(matches!(result, Err(EvalPolishError::ExtraOperands)));
}
