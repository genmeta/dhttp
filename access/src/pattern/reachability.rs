use std::collections::{BTreeSet, VecDeque};

use regex_automata::{
    Anchored, Input,
    dfa::{Automaton, dense},
};
use snafu::{ResultExt, Snafu};

use super::{ClientNamePattern, DomainPattern, LocationPattern, NormalPattern};

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum ReachabilityError {
    #[snafu(display("failed to compile pattern automaton for `{pattern}`"))]
    CompilePattern {
        pattern: String,
        source: Box<regex_automata::dfa::dense::BuildError>,
    },

    #[snafu(display("{domain} pattern `{pattern}` cannot match any valid {domain}"))]
    EmptyIntersection {
        domain: &'static str,
        pattern: String,
    },
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

impl PatternLanguage for ClientNamePattern {
    fn pattern_text(&self) -> &str {
        self.as_str()
    }

    fn search_regex(&self) -> String {
        self.regex.as_str().to_owned()
    }
}

impl PatternLanguage for DomainPattern {
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
        .map_err(Box::new)
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
        if L::is_accept(domain_state) {
            let eoi_state = dfa.next_eoi_state(regex_state);
            if matched || dfa.is_match_state(eoi_state) {
                return true;
            }
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

const TCHARS: &[u8] =
    b"!#$%&'*+-.^_`|~0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
const URI_PATH_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$&'()*+,;=:@%/";
const URI_QUERY_KEY_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$'()*+,;:@%/?";
const URI_QUERY_VALUE_ALPHABET: &[u8] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~!$'()*+,;=:@%/?";
const HOST_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.";
const FIELD_VALUE_CHARS: &[u8] = b"\t ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

pub struct ClientNameLanguage;
pub struct DomainNameLanguage;
pub struct LocationPathLanguage;
pub struct HttpMethodLanguage;
pub struct HeaderNameLanguage;
pub struct HeaderValueLanguage;
pub struct QueryKeyLanguage;
pub struct QueryValueLanguage;

include!("reachability/languages.rs");

#[cfg(test)]
#[path = "../../tests/unit/reachability.rs"]
mod tests;
