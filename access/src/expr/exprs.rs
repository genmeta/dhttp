use std::{fmt::Display, ops::Index, slice::SliceIndex, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::expr::{
    atomics::AtomicLocationRuleExpr,
    eval::{BeOperator, BooleanOperator, EvalPolishError, Evaluable, VM},
    parse::{self, TokenStream},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Part<Operator, Expr> {
    Operator(Operator),
    Expr(Expr),
}

impl<Operator: Display, Expr: Display> Display for Part<Operator, Expr> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Part::Operator(operator) => operator.fmt(f),
            Part::Expr(expr) => expr.fmt(f),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exprs<Operator, Expr> {
    parts: Vec<Part<Operator, Expr>>,
}

impl<Operator, Expr, I> Index<I> for Exprs<Operator, Expr>
where
    I: SliceIndex<[Part<Operator, Expr>]>,
{
    type Output = <[Part<Operator, Expr>] as Index<I>>::Output;

    fn index(&self, index: I) -> &Self::Output {
        self.parts.index(index)
    }
}

impl<Operator, Expr> IntoIterator for Exprs<Operator, Expr> {
    type Item = Part<Operator, Expr>;

    type IntoIter = std::vec::IntoIter<Part<Operator, Expr>>;

    fn into_iter(self) -> Self::IntoIter {
        self.parts.into_iter()
    }
}

impl<'e, Operator, Expr> IntoIterator for &'e Exprs<Operator, Expr> {
    type Item = &'e Part<Operator, Expr>;

    type IntoIter = std::slice::Iter<'e, Part<Operator, Expr>>;

    fn into_iter(self) -> Self::IntoIter {
        self.parts.iter()
    }
}

impl<Operator, Expr> From<Vec<Part<Operator, Expr>>> for Exprs<Operator, Expr> {
    fn from(parts: Vec<Part<Operator, Expr>>) -> Self {
        Self { parts }
    }
}

impl<Operator, Expr> From<Part<Operator, Expr>> for Exprs<Operator, Expr> {
    fn from(value: Part<Operator, Expr>) -> Self {
        vec![value].into()
    }
}

impl<Operator, Expr> Default for Exprs<Operator, Expr> {
    fn default() -> Self {
        Self {
            parts: Default::default(),
        }
    }
}

impl<Operator, Expr> FromIterator<Part<Operator, Expr>> for Exprs<Operator, Expr> {
    fn from_iter<T: IntoIterator<Item = Part<Operator, Expr>>>(iter: T) -> Self {
        Self {
            parts: iter.into_iter().collect(),
        }
    }
}

impl<Value, Operator, Expr, State> Evaluable<State> for Exprs<Operator, Expr>
where
    Operator: BeOperator<Value> + Clone,
    Expr: Evaluable<State, Value = Value>,
    State: ?Sized,
{
    type Value = Result<Value, EvalPolishError>;

    fn eval(&self, state: &State) -> Self::Value {
        self.try_eval(state)
    }
}

impl<Operator, Expr> Exprs<Operator, Expr> {
    pub fn try_eval<Value, State>(&self, state: &State) -> Result<Value, EvalPolishError>
    where
        Operator: BeOperator<Value> + Clone,
        Expr: Evaluable<State, Value = Value>,
        State: ?Sized,
    {
        VM::new().try_run(self.parts.iter().map(|part| match part {
            Part::Operator(op) => Part::Operator(op.clone()),
            Part::Expr(a) => Part::Expr(a.eval(state)),
        }))
    }

    pub fn validate_arity(&self) -> Result<(), EvalPolishError>
    where
        Operator: BeOperator<()> + Clone,
    {
        VM::new()
            .try_run(self.parts.iter().map(|part| match part {
                Part::Operator(op) => Part::Operator(op.clone()),
                Part::Expr(_) => Part::Expr(()),
            }))
            .map(|_| ())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationRuleExprs {
    infix: String,
    polish: Exprs<BooleanOperator, AtomicLocationRuleExpr>,
}

impl LocationRuleExprs {
    pub fn infix(&self) -> &str {
        &self.infix
    }

    pub fn polish(&self) -> &Exprs<BooleanOperator, AtomicLocationRuleExpr> {
        &self.polish
    }
}

impl Display for LocationRuleExprs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { infix, .. } = self;
        if let [Part::Expr(AtomicLocationRuleExpr::ClientName(pattern))] =
            self.polish.parts.as_slice()
        {
            let pattern = pattern.as_ref().as_str();
            if let Some(prefix) = pattern
                .strip_suffix(".dhttp.net")
                .filter(|prefix| !prefix.is_empty())
            {
                return write!(f, "{prefix}~");
            }
            return write!(f, "{pattern}");
        }
        write!(f, "{infix}")
    }
}

crate::orm_new_type!(@json LocationRuleExprs);

impl<Operator: Display, Expr: Display> Serialize for Exprs<Operator, Expr> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut s = String::new();
        self.parts
            .iter()
            .try_for_each(|part| {
                use std::fmt::Write;
                write!(s, "{part} ")
            })
            .map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(&s)
    }
}

mod deserialize_exprs {
    use peg::{error::ParseError, str::LineCol};
    use serde::Deserializer;
    use snafu::ResultExt;

    use super::*;
    use crate::expr::parse::InvalidPatternExpr;

    #[derive(snafu::Snafu, Debug)]
    pub enum DeserializeExprsError {
        // issue: https://github.com/shepmaster/snafu/issues/99
        String {
            message: String,
        },
        #[snafu(display(
            "failed to deserialize rule exprs while lexing `{input}` (internal error, database changed?)"
        ))]
        Lex {
            input: String,
            source: ParseError<LineCol>,
        },
        #[snafu(display(
            "failed to deserialize rule exprs while parsing `{input}` (internal error, database changed?)"
        ))]
        Parse {
            input: String,
            source: ParseError<LineCol>,
        },
        #[snafu(display(
            "failed to deserialize rule exprs while parsing pattern (internal error, database changed?)"
        ))]
        PatternParse {
            source: InvalidPatternExpr,
        },
        #[snafu(display(
            "failed to deserialize rule exprs while validating polish notation (internal error, database changed?)"
        ))]
        InvalidPolish {
            source: EvalPolishError,
        },
    }

    impl<'de> Deserialize<'de> for Exprs<BooleanOperator, AtomicLocationRuleExpr> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            (|| -> Result<_, DeserializeExprsError> {
                let polish = String::deserialize(deserializer).map_err(|e| {
                    let message =
                        format!("Deserialize rule exprs failed in deserializing string: {e}");
                    StringSnafu { message }.build()
                })?;
                let tokens = TokenStream::new(&polish).context(LexSnafu { input: &polish })?;
                let exprs = parse::polish_location_rule_exprs(&tokens)
                    .context(ParseSnafu { input: &polish })?
                    .context(PatternParseSnafu)?;
                exprs.validate_arity().context(InvalidPolishSnafu)?;
                Ok(exprs)
            })()
            .map_err(serde::de::Error::custom)
        }
    }
}

pub use deserialize_exprs::*;

mod parse_exprs {
    use peg::{error::ParseError, str::LineCol};
    use snafu::ResultExt;

    use super::*;
    use crate::expr::parse::{self, InvalidPatternExpr};

    #[derive(snafu::Snafu, Debug)]
    pub enum ParseExprsError {
        #[snafu(display("failed to parse rule exprs"))]
        Pattern { source: InvalidPatternExpr },
        #[snafu(display("failed to parse rule exprs `{input}`"))]
        Incomplete {
            input: String,
            source: ParseError<LineCol>,
        },
    }

    impl FromStr for LocationRuleExprs {
        type Err = ParseExprsError;

        fn from_str(infix: &str) -> Result<Self, Self::Err> {
            let infix = infix.to_string();
            let tokens =
                parse::TokenStream::new(&infix).context(IncompleteSnafu { input: &infix })?;
            let polish = parse::infix_location_rule_exprs(&tokens)
                .context(IncompleteSnafu { input: &infix })?
                .context(PatternSnafu)?;
            Ok(Self { infix, polish })
        }
    }
}

#[cfg(feature = "cli")]
impl clap::Args for LocationRuleExprs {
    fn augment_args(cmd: clap::Command) -> clap::Command {
        cmd.arg(
            clap::Arg::new("expr")
                .help("The expression to filter requests")
                .required(true)
                .num_args(1..)
                .action(clap::ArgAction::Append),
        )
    }

    fn augment_args_for_update(cmd: clap::Command) -> clap::Command {
        Self::augment_args(cmd)
    }
}

#[cfg(feature = "cli")]
impl clap::FromArgMatches for LocationRuleExprs {
    fn from_arg_matches(matches: &clap::ArgMatches) -> Result<Self, clap::Error> {
        use clap::{Error, error::ErrorKind};

        let patrs = matches
            .get_many::<String>("expr")
            .unwrap()
            .cloned()
            .collect::<Vec<_>>();

        patrs
            .join(" ")
            .parse()
            .map_err(snafu::Report::from_error)
            .map_err(|e| Error::raw(ErrorKind::InvalidValue, e))
    }

    fn update_from_arg_matches(&mut self, matches: &clap::ArgMatches) -> Result<(), clap::Error> {
        *self = Self::from_arg_matches(matches)?;
        Ok(())
    }
}
