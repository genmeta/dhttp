#![allow(clippy::mutable_key_type)]

use std::{collections::BTreeMap, fmt::Display, str::FromStr};

use derive_more::{From, Into};
use serde::{Deserialize, Serialize};
use snafu::{OptionExt, ResultExt};

use crate::{
    action::RequestAction,
    error::location::MatchLocationFailed,
    expr::{
        atomics::AtomicLocationRuleExpr, eval::Evaluable, exprs::LocationRuleExprs, rule::Rule,
    },
    pattern::{LocationPattern, LocationPatternKind, Pattern},
};

pub struct PatternMatcher<Kind, Item> {
    map: BTreeMap<Pattern<Kind>, Item>,
}

pub type LocationPatternMatcher<Item> = PatternMatcher<LocationPatternKind, Item>;

impl<Kind, Item> Default for PatternMatcher<Kind, Item> {
    fn default() -> Self {
        Self {
            map: Default::default(),
        }
    }
}

impl<Kind, Item> FromIterator<(Pattern<Kind>, Item)> for PatternMatcher<Kind, Item>
where
    Pattern<Kind>: Ord,
{
    fn from_iter<T: IntoIterator<Item = (Pattern<Kind>, Item)>>(iter: T) -> Self {
        Self {
            map: iter.into_iter().collect(),
        }
    }
}

impl<Index> LocationPatternMatcher<Index> {
    pub fn r#match<'set: 's, 's>(
        &'set self,
        s: &'s str,
    ) -> Option<(&'set Index, &'set LocationPattern, &'s str)> {
        // pattern has been shored by priority
        self.map
            .iter()
            .find_map(|(pattern, index)| pattern.r#match(s).map(|s| (index, pattern, s)))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternWithTime<Kind>
where
    Pattern<Kind>: FromStr<Err: Display>,
{
    timestamp: i64, // why i64?
    pattern: Pattern<Kind>,
}

impl<Kind> Display for PatternWithTime<Kind>
where
    Pattern<Kind>: FromStr<Err: Display>,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.pattern.fmt(f)
    }
}

impl<Kind> PatternWithTime<Kind>
where
    Pattern<Kind>: FromStr<Err: Display>,
{
    pub fn new(timestamp: i64, pattern: Pattern<Kind>) -> Self {
        Self { timestamp, pattern }
    }
}

impl<Kind> PartialOrd for PatternWithTime<Kind>
where
    Self: Ord,
    Pattern<Kind>: FromStr<Err: Display>,
{
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for PatternWithTime<LocationPatternKind> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.pattern.priority().cmp(&other.pattern.priority()))
            // 时间倒序，新规则更提前
            .then_with(|| self.timestamp.cmp(&other.timestamp).reverse())
    }
}

#[derive(snafu::Snafu, Debug)]
pub enum MatchRuleFailed<MatchSet: snafu::Error + 'static> {
    #[snafu(display("no rule set matched"))]
    MatchSet { source: MatchSet },

    #[snafu(display("rule set matched, but no rule matched"))]
    MatchRuleInSet,
}

#[derive(Default, Debug, Clone, From, Into, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocationRulesMatcher {
    pub map:
        BTreeMap<PatternWithTime<LocationPatternKind>, Vec<(LocationRuleExprs, RequestAction)>>,
}

impl LocationRulesMatcher {
    #[allow(clippy::type_complexity)]
    pub fn match_rules(
        &self,
        path: &str,
    ) -> Result<(&LocationPattern, &[(LocationRuleExprs, RequestAction)]), MatchLocationFailed>
    {
        use crate::error::location::NoMatchedPathSnafu;
        self.map
            .iter()
            .find(|(PatternWithTime { pattern, .. }, ..)| pattern.is_match(path))
            .map(|(PatternWithTime { pattern, .. }, rules)| (pattern, rules.as_slice()))
            .context(NoMatchedPathSnafu {
                path: path.to_string(),
            })
    }

    pub fn match_rule<'r, NewRequest>(
        &'r self,
        path: &str,
        new_request: &NewRequest,
    ) -> Result<(&'r LocationPattern, RequestAction), MatchRuleFailed<MatchLocationFailed>>
    where
        Rule<'r, AtomicLocationRuleExpr, RequestAction>:
            Evaluable<NewRequest, Value = Option<RequestAction>>,
    {
        let (location_pattern, rules) = self.match_rules(path).context(MatchSetSnafu)?;
        rules
            .iter()
            // rules are ordered by created time. Reverse to make the latest rule evaluated first.
            .rev()
            .map(|(exprs, action)| Rule::new(exprs.polish(), *action))
            .find_map(|rule| rule.eval(new_request))
            .map(|action| (location_pattern, action))
            .context(MatchRuleInSetSnafu)
    }
}
