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

impl PatternInputLanguage for DomainNameLanguage {
    fn label() -> &'static str {
        "domain"
    }

    fn start() -> DomainState {
        ClientNameLanguage::start()
    }

    fn step(state: DomainState, byte: u8) -> Option<DomainState> {
        ClientNameLanguage::step(state, byte)
    }

    fn is_accept(state: DomainState) -> bool {
        ClientNameLanguage::is_accept(state)
    }

    fn alphabet() -> &'static [u8] {
        ClientNameLanguage::alphabet()
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
        TCHARS.contains(&byte).then_some(DomainState::new(0, 1, 0))
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
        TCHARS.contains(&byte).then_some(DomainState::new(0, 1, 0))
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
        match (state.kind, byte) {
            (0, b'/') => Some(DomainState::new(1, 0, 0)),
            (1, b'%') => Some(DomainState::new(2, 0, 0)),
            (1, byte) if is_uri_path_plain_char(byte) => Some(DomainState::new(1, 0, 0)),
            (2, byte) if byte.is_ascii_hexdigit() => Some(DomainState::new(3, 0, 0)),
            (3, byte) if byte.is_ascii_hexdigit() => Some(DomainState::new(1, 0, 0)),
            _ => None,
        }
    }

    fn is_accept(state: DomainState) -> bool {
        state.kind == 1
    }

    fn alphabet() -> &'static [u8] {
        URI_PATH_ALPHABET
    }
}

impl PatternInputLanguage for QueryKeyLanguage {
    fn label() -> &'static str {
        "query key"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(state: DomainState, byte: u8) -> Option<DomainState> {
        match (state.kind, byte) {
            (0, b'%') => Some(DomainState::new(1, 0, 0)),
            (0, byte) if is_uri_query_key_plain_char(byte) => Some(DomainState::new(0, 0, 0)),
            (1, byte) if byte.is_ascii_hexdigit() => Some(DomainState::new(2, 0, 0)),
            (2, byte) if byte.is_ascii_hexdigit() => Some(DomainState::new(0, 0, 0)),
            _ => None,
        }
    }

    fn is_accept(state: DomainState) -> bool {
        state.kind == 0
    }

    fn alphabet() -> &'static [u8] {
        URI_QUERY_KEY_ALPHABET
    }
}

impl PatternInputLanguage for QueryValueLanguage {
    fn label() -> &'static str {
        "query value"
    }

    fn start() -> DomainState {
        DomainState::new(0, 0, 0)
    }

    fn step(state: DomainState, byte: u8) -> Option<DomainState> {
        match (state.kind, byte) {
            (0, b'%') => Some(DomainState::new(1, 0, 0)),
            (0, byte) if is_uri_query_value_plain_char(byte) => Some(DomainState::new(0, 0, 0)),
            (1, byte) if byte.is_ascii_hexdigit() => Some(DomainState::new(2, 0, 0)),
            (2, byte) if byte.is_ascii_hexdigit() => Some(DomainState::new(0, 0, 0)),
            _ => None,
        }
    }

    fn is_accept(state: DomainState) -> bool {
        state.kind == 0
    }

    fn alphabet() -> &'static [u8] {
        URI_QUERY_VALUE_ALPHABET
    }
}

fn is_host_alphanumeric(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
}

fn is_uri_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

fn is_uri_sub_delim(byte: u8) -> bool {
    matches!(
        byte,
        b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
    )
}

fn is_uri_pchar_plain(byte: u8) -> bool {
    is_uri_unreserved(byte) || is_uri_sub_delim(byte) || matches!(byte, b':' | b'@')
}

fn is_uri_path_plain_char(byte: u8) -> bool {
    is_uri_pchar_plain(byte) || byte == b'/'
}

fn is_uri_query_plain_char(byte: u8) -> bool {
    is_uri_pchar_plain(byte) || matches!(byte, b'/' | b'?')
}

fn is_uri_query_key_plain_char(byte: u8) -> bool {
    is_uri_query_plain_char(byte) && !matches!(byte, b'&' | b'=')
}

fn is_uri_query_value_plain_char(byte: u8) -> bool {
    is_uri_query_plain_char(byte) && byte != b'&'
}
