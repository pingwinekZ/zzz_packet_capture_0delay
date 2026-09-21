//! The one thing this crate needs from the outside world.
//!
//! The C++ version called `squi::Networking::get` — an HTTP client it got for free
//! from its GUI toolkit. Here the seam is a trait: [`Fetcher`] is what the refresh
//! logic talks to, [`HttpFetcher`] is the real implementation the CLI and the GUI
//! use, and tests supply canned responses through [`StaticFetcher`], so nothing in
//! the test suite touches the network.

use std::collections::HashMap;
use std::time::Duration;

pub trait Fetcher {
    fn get(&self, url: &str) -> Result<String, String>;
}

/// Adapter for a plain closure. A blanket `impl<F: Fn(..)> Fetcher for F` would
/// be simpler to call but risks an overlap conflict, so closures go through this
/// explicit wrapper.
pub struct ClosureFetcher<F>(pub F);

impl<F> Fetcher for ClosureFetcher<F>
where
    F: Fn(&str) -> Result<String, String>,
{
    fn get(&self, url: &str) -> Result<String, String> {
        (self.0)(url)
    }
}

/// A [`Fetcher`] backed by a fixed set of URLs, for tests and offline runs.
///
/// This is what makes the refresh logic testable: it exercises the real code path,
/// including the ordering and the "validate before overwriting" rule, without a
/// network round trip.
#[derive(Debug, Default, Clone)]
pub struct StaticFetcher {
    responses: HashMap<String, String>,
}

impl StaticFetcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, url: impl Into<String>, body: impl Into<String>) -> Self {
        self.responses.insert(url.into(), body.into());
        self
    }
}

impl Fetcher for StaticFetcher {
    fn get(&self, url: &str) -> Result<String, String> {
        self.responses
            .get(url)
            .cloned()
            .ok_or_else(|| format!("no canned response for {url}"))
    }
}

/// A [`Fetcher`] that always fails, for tests that assert offline behaviour.
pub struct OfflineFetcher;

impl Fetcher for OfflineFetcher {
    fn get(&self, _url: &str) -> Result<String, String> {
        Err("offline".into())
    }
}

/// The real [`Fetcher`]: HTTPS through `ureq`.
///
/// Every data file is HTTPS-only (`github.com` redirects plain HTTP, and
/// `static.nanoka.cc` is TLS), so this is the one place the workspace has a TLS
/// stack. `ureq`'s default provider is `rustls`, which needs no system TLS library
/// on either target — the alternative, the `native-tls` feature, would reach
/// `schannel` on Windows but drag OpenSSL in on Linux, and it is not used by
/// `ureq`'s convenience calls anyway.
///
/// An `Agent` is used rather than the `ureq::get` shortcut so a global timeout and
/// a user agent can be set; the connection pool is shared across the ~5 requests a
/// refresh makes.
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    agent: ureq::Agent,
}

impl HttpFetcher {
    /// A fetcher with a 30-second ceiling per request.
    pub fn new() -> Self {
        Self::with_timeout(Duration::from_secs(30))
    }

    pub fn with_timeout(timeout: Duration) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .user_agent(concat!("zzzcap/", env!("CARGO_PKG_VERSION")))
            .build();
        Self {
            agent: config.into(),
        }
    }
}

impl Default for HttpFetcher {
    fn default() -> Self {
        Self::new()
    }
}

impl Fetcher for HttpFetcher {
    fn get(&self, url: &str) -> Result<String, String> {
        // `call` fails on 4xx and 5xx as well as transport errors, which is what a
        // caller wants: a 404 must not be mistaken for an empty file.
        self.agent
            .get(url)
            .call()
            .map_err(|error| format!("GET {url}: {error}"))?
            .body_mut()
            .read_to_string()
            .map_err(|error| format!("GET {url}: {error}"))
    }
}
