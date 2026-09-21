//! Port of `src/util/version.hpp`.
//!
//! Used only to decide whether the committed data files are older than the ones
//! published by the repository, so the comparison is deliberately loose: a part
//! that does not parse counts as zero.

use std::cmp::Ordering;
use std::fmt;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Version {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl Version {
    pub fn parse(version: &str) -> Self {
        let mut parts = version
            .split('.')
            .map(|p| p.trim().parse::<u32>().unwrap_or(0));
        Self {
            major: parts.next().unwrap_or(0),
            minor: parts.next().unwrap_or(0),
            patch: parts.next().unwrap_or(0),
        }
    }
}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then(self.minor.cmp(&other.minor))
            .then(self.patch.cmp(&other.patch))
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_short_and_long_forms() {
        assert_eq!(
            Version::parse("3.2"),
            Version {
                major: 3,
                minor: 2,
                patch: 0
            }
        );
        assert_eq!(
            Version::parse("3.2.1"),
            Version {
                major: 3,
                minor: 2,
                patch: 1
            }
        );
        assert_eq!(Version::parse(""), Version::default());
        assert_eq!(Version::parse("garbage"), Version::default());
        assert_eq!(
            Version::parse("2.0.0"),
            Version {
                major: 2,
                minor: 0,
                patch: 0
            }
        );
    }

    #[test]
    fn orders_by_component() {
        assert!(Version::parse("3.1") < Version::parse("3.2"));
        assert!(Version::parse("3.2") < Version::parse("3.2.1"));
        assert!(Version::parse("2.9.9") < Version::parse("3.0"));
        assert_eq!(Version::parse("3.2"), Version::parse("3.2.0"));
    }

    #[test]
    fn displays_canonically() {
        assert_eq!(Version::parse("3.2").to_string(), "3.2.0");
        assert_eq!(Version::parse("1.2.3").to_string(), "1.2.3");
    }
}
