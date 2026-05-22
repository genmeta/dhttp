#[allow(clippy::module_inception)]
pub mod location {
    pub mod location;
    pub use location::Entity as Location;
    pub mod rule;
    pub use rule::Entity as Rule;
}
