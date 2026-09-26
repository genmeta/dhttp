use crate::{
    action::RequestAction,
    expr::{atomics::AtomicLocationRuleExpr, atomics::EvalError, exprs::LocationRuleExprs},
    matcher::{LocationRulesMatcher, PatternWithTime},
    pattern::{LocationPattern, LocationPatternKind},
    policy::{LocationRuleDecisionError, LocationRuleEvaluator, LocationRuleRequest},
};

struct TestRequest {
    client_name: Option<String>,
}

impl TestRequest {
    fn named(name: &str) -> Self {
        Self {
            client_name: Some(name.to_owned()),
        }
    }
}

impl LocationRuleRequest for TestRequest {
    fn eval_atomic(&self, expr: &AtomicLocationRuleExpr) -> Result<bool, EvalError> {
        use crate::expr::eval::Evaluable;
        Ok(match expr {
            AtomicLocationRuleExpr::Any(..) => true,
            AtomicLocationRuleExpr::ClientName(pattern) => {
                pattern.eval(&self.client_name.as_deref())?
            }
            AtomicLocationRuleExpr::Method(_) => false,
            AtomicLocationRuleExpr::Header(_) => false,
            AtomicLocationRuleExpr::Query(_) => false,
        })
    }
}

fn root_allow_all_matcher() -> LocationRulesMatcher {
    let mut matcher = LocationRulesMatcher::default();
    matcher.map.insert(
        PatternWithTime::<LocationPatternKind>::new(
            1,
            "/".parse::<LocationPattern>().expect("valid root pattern"),
        ),
        vec![(
            "*".parse::<LocationRuleExprs>()
                .expect("valid any-client expr"),
            RequestAction::Allow,
        )],
    );
    matcher
}

#[tokio::test]
async fn matcher_policy_evaluator_allows_matching_rule() {
    let matcher = root_allow_all_matcher();
    let request = TestRequest::named("alice.pilot.dhttp.net");

    let decision = matcher
        .evaluate("/", &request)
        .await
        .expect("matcher should decide");

    assert_eq!(decision.location.to_string(), "/");
    assert_eq!(decision.action, RequestAction::Allow);
}

#[tokio::test]
async fn matcher_policy_evaluator_reports_no_rule_set() {
    let matcher = LocationRulesMatcher::default();
    let request = TestRequest::named("alice.pilot.dhttp.net");

    let error = matcher
        .evaluate("/missing", &request)
        .await
        .expect_err("empty matcher should not match");

    assert!(matches!(error, LocationRuleDecisionError::NoRuleSet { .. }));
}
