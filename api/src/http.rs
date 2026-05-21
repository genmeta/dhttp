/// Ordered HTTP header pairs used at language boundaries.
pub type HeaderPairs = Vec<(String, String)>;

/// HTTP body bytes used at language boundaries.
pub type Body = Vec<u8>;

/// HTTP method text used at language boundaries.
pub type Method = String;

/// HTTP URI text used at language boundaries.
pub type Uri = String;

/// HTTP authority text used at language boundaries.
pub type Authority = String;

/// HTTP status code used at language boundaries.
pub type Status = u16;
