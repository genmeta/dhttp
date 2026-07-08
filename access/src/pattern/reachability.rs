use std::collections::{BTreeSet, VecDeque};

use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, dense},
};
use snafu::{ResultExt, Snafu};

use super::{LocationPattern, NormalPattern};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReachabilityError {
    #[snafu(display("failed to compile pattern automaton for `{pattern}`"))]
    CompilePattern {
        pattern: String,
        source: PatternAutomatonError,
    },

    #[snafu(display("{domain} pattern `{pattern}` cannot match any valid {domain}"))]
    EmptyIntersection { domain: &'static str, pattern: String },
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum PatternAutomatonError {
    #[snafu(display("failed to build regex DFA"))]
    BuildRegex { source: regex_automata::dfa::dense::BuildError },
}

pub trait PatternInputLanguage {
    fn label() -> &'static str;
    fn start() -> DomainState;
    fn step(state: DomainState, byte: u8) -> Option<DomainState>;
    fn is_accept(state: DomainState) -> bool;
    fn alphabet() -> &'static [u8];

    fn accepts(input: &[u8]) -> bool {
        let mut state = Self::start();
        for byte in input {
            let Some(next) = Self::step(state, *byte) else {
                return false;
            };
            state = next;
        }
        Self::is_accept(state)
    }
}

pub trait PatternLanguage {
    fn pattern_text(&self) -> &str;
    fn search_regex(&self) -> String;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DomainState {
    kind: u16,
    len: u16,
    flags: u16,
}

impl DomainState {
    const fn new(kind: u16, len: u16, flags: u16) -> Self {
        Self { kind, len, flags }
    }
}

impl PatternLanguage for NormalPattern {
    fn pattern_text(&self) -> &str {
        self.as_str()
    }

    fn search_regex(&self) -> String {
        self.regex.as_str().to_owned()
    }
}

impl PatternLanguage for LocationPattern {
    fn pattern_text(&self) -> &str {
        self.as_str()
    }

    fn search_regex(&self) -> String {
        self.regex.as_str().to_owned()
    }
}

pub fn validate_reachable<P, L>(pattern: &P) -> Result<(), ReachabilityError>
where
    P: PatternLanguage,
    L: PatternInputLanguage,
{
    let regex = pattern.search_regex();
    let dfa = dense::Builder::new()
        .configure(dense::Config::new().minimize(true))
        .build(&regex)
        .map_err(|source| PatternAutomatonError::BuildRegex { source })
        .context(reachability_error::CompilePatternSnafu {
            pattern: pattern.pattern_text().to_string(),
        })?;

    if intersects::<L>(&dfa) {
        Ok(())
    } else {
        reachability_error::EmptyIntersectionSnafu {
            domain: L::label(),
            pattern: pattern.pattern_text().to_string(),
        }
        .fail()
    }
}

fn intersects<L>(dfa: &dense::DFA<Vec<u32>>) -> bool
where
    L: PatternInputLanguage,
{
    let input = Input::new("").anchored(Anchored::No);
    let Ok(regex_start) = dfa.start_state_forward(&input) else {
        return false;
    };
    let matched_start = dfa.is_match_state(regex_start);

    let mut seen = BTreeSet::new();
    let mut queue = VecDeque::from([(regex_start, L::start(), matched_start)]);

    while let Some((regex_state, domain_state, matched)) = queue.pop_front() {
        if !seen.insert((regex_state, domain_state, matched)) {
            continue;
        }
        let matched = matched || dfa.is_match_state(regex_state);
        if matched && L::is_accept(domain_state) {
            return true;
        }
        if dfa.is_dead_state(regex_state) {
            continue;
        }
        for byte in L::alphabet() {
            let Some(next_domain) = L::step(domain_state, *byte) else {
                continue;
            };
            let next_regex = dfa.next_state(regex_state, *byte);
            let next_matched = matched || dfa.is_match_state(next_regex);
            queue.push_back((next_regex, next_domain, next_matched));
        }
    }
    false
}

const TCHARS: &[u8] = b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const URI_PCHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@%/";
const URI_QUERY_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@%/?";
const HOST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
const FIELD_VALUE_CHARS: &[u8] = b"\t ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

pub struct ClientNameLanguage;
pub struct LocationPathLanguage;
pub struct HttpMethodLanguage;
pub struct HeaderNameLanguage;
pub struct HeaderValueLanguage;
pub struct QueryKeyLanguage;
pub struct QueryValueLanguage;

impl PatternInputLanguage for ClientNameLanguage {
    fn label() -> &'static str {
        "client name"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(state: DomainState, byte: u8) -> Option<DomainState> {
        let total = state.flags.checked_add(1)?;
        if total > 253 {
            return None;
        }

        match (state.kind, byte) {
            (0, byte) if is_host_alphanumeric(byte) => Some(DomainState::new(1, 1, total)),
            (1 | 2, byte) if is_host_alphanumeric(byte) => {
                let label_len = state.len.checked_add(1)?;
                (label_len <= 63).then_some(DomainState::new(1, label_len, total))
            }
            (1 | 2, b'-') => {
                let label_len = state.len.checked_add(1)?;
                (label_len <= 63).then_some(DomainState::new(2, label_len, total))
            }
            (1, b'.') => Some(DomainState::new(0, 0, total)),
            _ => None,
        }
    }

    fn is_accept(state: DomainState) -> bool {
        state.kind == 1
    }

    fn alphabet() -> &'static [u8] {
        HOST_CHARS
    }
}

impl PatternInputLanguage for HttpMethodLanguage {
    fn label() -> &'static str {
        "HTTP method"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(_state: DomainState, byte: u8) -> Option<DomainState> {
        TCHARS
            .contains(&byte)
            .then_some(DomainState::new(0, 1, 0))
    }

    fn is_accept(state: DomainState) -> bool {
        state.len == 1
    }

    fn alphabet() -> &'static [u8] {
        TCHARS
    }
}

impl PatternInputLanguage for HeaderNameLanguage {
    fn label() -> &'static str {
        "header name"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(_state: DomainState, byte: u8) -> Option<DomainState> {
        TCHARS
            .contains(&byte)
            .then_some(DomainState::new(0, 1, 0))
    }

    fn is_accept(state: DomainState) -> bool {
        state.len == 1
    }

    fn alphabet() -> &'static [u8] {
        TCHARS
    }
}

impl PatternInputLanguage for HeaderValueLanguage {
    fn label() -> &'static str {
        "header value"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(_state: DomainState, byte: u8) -> Option<DomainState> {
        FIELD_VALUE_CHARS
            .contains(&byte)
            .then_some(DomainState::new(0, 0, 0))
    }

    fn is_accept(_state: DomainState) -> bool {
        true
    }

    fn alphabet() -> &'static [u8] {
        FIELD_VALUE_CHARS
    }
}

impl PatternInputLanguage for LocationPathLanguage {
    fn label() -> &'static str {
        "location path"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(state: DomainState, byte: u8) -> Option<DomainState> {
        match state.kind {
            0 if byte == b'/' => Some(DomainState::new(1, 0, 0)),
            1 if URI_PCHARS.contains(&byte) => Some(DomainState::new(1, 0, 0)),
            _ => None,
        }
    }

    fn is_accept(state: DomainState) -> bool {
        state.kind == 1
    }

    fn alphabet() -> &'static [u8] {
        URI_PCHARS
    }
}

impl PatternInputLanguage for QueryKeyLanguage {
    fn label() -> &'static str {
        "query key"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(_state: DomainState, byte: u8) -> Option<DomainState> {
        URI_QUERY_CHARS
            .contains(&byte)
            .then_some(DomainState::new(0, 0, 0))
    }

    fn is_accept(_state: DomainState) -> bool {
        true
    }

    fn alphabet() -> &'static [u8] {
        URI_QUERY_CHARS
    }
}

impl PatternInputLanguage for QueryValueLanguage {
    fn label() -> &'static str {
        "query value"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(_state: DomainState, byte: u8) -> Option<DomainState> {
        URI_QUERY_CHARS
            .contains(&byte)
            .then_some(DomainState::new(0, 0, 0))
    }

    fn is_accept(_state: DomainState) -> bool {
        true
    }

    fn alphabet() -> &'static [u8] {
        URI_QUERY_CHARS
    }
}

fn is_host_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc1123_host_accepts_digit_start_and_rejects_underscore() {
        assert!(ClientNameLanguage::accepts(b"3com.example"));
        assert!(ClientNameLanguage::accepts(b"alice.dhttp.net"));
        assert!(!ClientNameLanguage::accepts(b"_service.example"));
        assert!(!ClientNameLanguage::accepts(b"-bad.example"));
        assert!(!ClientNameLanguage::accepts(b"bad-.example"));
    }

    #[test]
    fn rfc9110_token_domains_accept_tchars() {
        assert!(HttpMethodLanguage::accepts(b"GET"));
        assert!(HttpMethodLanguage::accepts(b"M-SEARCH"));
        assert!(HeaderNameLanguage::accepts(b"content-type"));
        assert!(!HeaderNameLanguage::accepts(b"bad header"));
    }

    #[test]
    fn rfc3986_path_and_query_domains_use_raw_uri_characters() {
        assert!(LocationPathLanguage::accepts(b"/api/a%20b"));
        assert!(!LocationPathLanguage::accepts(b"api/no-leading-slash"));
        assert!(QueryKeyLanguage::accepts(b"q"));
        assert!(QueryValueLanguage::accepts(b"a/b?c"));
    }

    #[test]
    fn reachability_rejects_smart_quote_name_pattern() {
        let pattern: NormalPattern = "“*?”".parse().unwrap();

        let error = validate_reachable::<_, ClientNameLanguage>(&pattern).unwrap_err();

        assert!(matches!(error, ReachabilityError::EmptyIntersection { .. }));
    }
}
