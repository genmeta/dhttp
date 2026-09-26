impl<Kind> Display for Pattern<Kind> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl<Kind> Serialize for Pattern<Kind> {
    #[inline]
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de, Kind> Deserialize<'de> for Pattern<Kind>
where
    Self: FromStr<Err: Display>,
{
    #[inline]
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl<Kind: PartialEq> PartialEq for Pattern<Kind> {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.pattern == other.pattern
    }
}

impl<Kind: Eq> Eq for Pattern<Kind> {}

impl<Kind: PartialOrd> PartialOrd for Pattern<Kind> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.kind
            .partial_cmp(&other.kind)
            .map(|ord| ord.then_with(|| self.pattern.cmp(&other.pattern)))
    }
}

impl<Kind: Ord> Ord for Pattern<Kind> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.kind
            .cmp(&other.kind)
            .then_with(|| self.pattern.cmp(&other.pattern))
    }
}
