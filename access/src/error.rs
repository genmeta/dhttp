use crate::pattern::LocationPattern;

pub mod location {
    use super::*;

    #[derive(snafu::Snafu, Debug)]
    #[snafu(visibility(pub))]
    pub enum MatchLocationFailed {
        #[snafu(display("no location rule set matches `{location}`"))]
        NoMatchedLocation { location: LocationPattern },
        #[snafu(display("no location rule set matches `{path}`"))]
        NoMatchedPath { path: String },
    }

    #[derive(snafu::Snafu, Debug)]
    #[snafu(visibility(pub))]
    pub enum LocateLocationFailed {
        #[snafu(display("location rule set `{location}` does not exist"))]
        LocationNotExist { location: LocationPattern },
    }
}
