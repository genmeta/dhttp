use super::*;
use std::collections::HashMap;

#[test]
fn pool_keys_share_named_peers_across_directions_and_separate_anonymous_peers() {
    let local: Arc<str> = Arc::from("alice.dhttp.net");
    let remote: Arc<str> = Arc::from("bob.dhttp.net");
    let mut entries = HashMap::from([(
        ConnectionKey::Incoming {
            local: local.clone(),
            remote: Some(remote.clone()),
        },
        "named",
    )]);
    assert_eq!(
        entries.get(&ConnectionKey::Outgoing {
            local: Some(crate::endpoint::test_support::named("alice")),
            remote: Arc::from("bob.dhttp.net"),
        }),
        Some(&"named"),
    );
    entries.insert(
        ConnectionKey::Incoming {
            local: local.clone(),
            remote: None,
        },
        "anonymous peer",
    );
    entries.insert(
        ConnectionKey::Outgoing {
            local: None,
            remote: local,
        },
        "anonymous local",
    );
    assert_eq!(entries.len(), 3);
}

#[test]
fn different_origin_ports_do_not_share_connections() {
    let key = |remote: &str| ConnectionKey::Outgoing {
        local: Some(crate::endpoint::test_support::named("alice")),
        remote: Arc::from(remote),
    };
    let entries = HashMap::from([
        (key("ddns.genmeta.net:4433"), "first"),
        (key("ddns.genmeta.net:8443"), "second"),
    ]);
    assert_eq!(entries.len(), 2);
    assert_eq!(entries.get(&key("ddns.genmeta.net:4433")), Some(&"first"));
    assert_eq!(entries.get(&key("ddns.genmeta.net:8443")), Some(&"second"));
}
