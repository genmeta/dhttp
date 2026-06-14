mod bootstrap;

pub mod ddns;
pub mod endpoint;
pub mod message;
pub mod network;
pub use dhttp_access as access;
pub mod certificate {
    pub use dhttp_identity::certificate::*;
}
pub mod identity {
    pub use dhttp_identity::identity::*;
}
pub mod name {
    pub use dhttp_identity::name::*;
}
pub mod trust;

pub use dhttp_home as home;
pub use h3x;
pub use h3x::dquic;

#[cfg(test)]
mod tests {
    #[test]
    fn facade_reexports_access_core_types() {
        fn assert_same_type(
            value: Option<crate::access::action::RequestAction>,
        ) -> Option<dhttp_access::action::RequestAction> {
            value
        }

        let _ = assert_same_type;
    }

    #[test]
    fn facade_reexports_access_http_types() {
        let request = http::Request::builder()
            .uri("https://example.com")
            .body(())
            .expect("request should build");
        let _ = crate::access::expr::atomics::HttpRequest::new(None, &request);
    }

    #[test]
    fn facade_reexports_access_orm_types() {
        fn assert_type<T>() {}

        assert_type::<crate::access::db::base::matcher::LocationRulesMatcher>();
    }
}
