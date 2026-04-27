//! URL → [`Transport`](crate::Transport) registry for the pure-Rust crate.
//!
//! This is intentionally separate from the Python-side
//! `dromedary.transport` registry: that one bridges into PyO3-wrapped
//! transports, this one stays in pure Rust. The two never share state.
//!
//! Out of the box the `file`/`memory`/`http`/`https` schemes are
//! pre-registered (and `webdav`/`webdavs` when the `webdav` feature is
//! on). The `sftp` scheme is opt-in: it needs a caller-supplied SSH
//! channel opener, which can't be inferred from the URL alone, so call
//! [`register_sftp`] once at startup if you want `sftp://` URLs to
//! resolve.
//!
//! Custom schemes can be registered with [`register`] / [`unregister`];
//! [`get_transport`] looks up the URL's scheme and dispatches.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use url::Url;

use crate::{Error, Result, Transport};

/// `HttpClient::new` has its own error type; map into the transport
/// `Error` so the registry can present a uniform failure surface.
fn http_client_err_to_transport_err(e: crate::http::client::ClientError) -> Error {
    use crate::http::client::ClientError;
    match e {
        ClientError::Transport(re) => Error::ConnectionError(re.to_string()),
        ClientError::InvalidRequest(s) => Error::TransportNotPossible(Some(s)),
        ClientError::Io(io) => Error::Io(io),
    }
}

/// Trait for things that can build a [`Transport`] from a URL string.
///
/// Returned objects are boxed trait objects so the registry can store
/// heterogeneous backends behind one map. Implementors typically just
/// forward to a concrete `Foo::new(url)` constructor.
pub trait TransportFactory: Send + Sync {
    fn build(&self, url: &str) -> Result<Box<dyn Transport>>;
}

/// Convenience blanket impl: a closure that returns
/// `Result<Box<dyn Transport>>` is automatically a factory.
impl<F> TransportFactory for F
where
    F: Fn(&str) -> Result<Box<dyn Transport>> + Send + Sync,
{
    fn build(&self, url: &str) -> Result<Box<dyn Transport>> {
        self(url)
    }
}

type Registry = RwLock<HashMap<String, Box<dyn TransportFactory>>>;

/// Lazily-initialised global registry. The first access seeds it with
/// the built-in schemes so `get_transport("file:///tmp")` works without
/// any setup.
fn registry() -> &'static Registry {
    static R: OnceLock<Registry> = OnceLock::new();
    R.get_or_init(|| {
        let mut m: HashMap<String, Box<dyn TransportFactory>> = HashMap::new();
        register_builtins(&mut m);
        RwLock::new(m)
    })
}

fn register_builtins(m: &mut HashMap<String, Box<dyn TransportFactory>>) {
    m.insert(
        "file".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport>> {
            Ok(Box::new(crate::local::LocalTransport::new(url)?))
        }),
    );
    m.insert(
        "memory".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport>> {
            Ok(Box::new(crate::memory::MemoryTransport::new(url)?))
        }),
    );
    // HTTP/HTTPS share a default-config client. Callers needing a custom
    // client (proxies, mTLS, custom CA bundle, ...) should construct
    // `HttpTransport` directly rather than going through the registry.
    fn build_http(url: &str) -> Result<Box<dyn Transport>> {
        let client = std::sync::Arc::new(
            crate::http::client::HttpClient::new(crate::http::client::HttpClientConfig::default())
                .map_err(http_client_err_to_transport_err)?,
        );
        Ok(Box::new(crate::http::transport::HttpTransport::new(
            url, client,
        )?))
    }
    // The registry owns each factory exclusively, so http and https get
    // separate boxed closures pointing at the same builder.
    m.insert("http".into(), Box::new(|u: &str| build_http(u)));
    m.insert("https".into(), Box::new(|u: &str| build_http(u)));

    #[cfg(feature = "webdav")]
    {
        fn build_webdav(url: &str) -> Result<Box<dyn Transport>> {
            let client = std::sync::Arc::new(
                crate::http::client::HttpClient::new(
                    crate::http::client::HttpClientConfig::default(),
                )
                .map_err(http_client_err_to_transport_err)?,
            );
            Ok(Box::new(
                crate::webdav::transport::HttpDavTransport::new(url, client)?,
            ))
        }
        m.insert("webdav".into(), Box::new(|u: &str| build_webdav(u)));
        m.insert("webdavs".into(), Box::new(|u: &str| build_webdav(u)));
    }
}

/// Register a factory for `scheme`, replacing any previous registration.
/// Returns the displaced factory if there was one.
///
/// Useful for tests, or for swapping the default HTTP client for one with
/// custom credentials/proxy/CA configuration.
pub fn register(
    scheme: &str,
    factory: Box<dyn TransportFactory>,
) -> Option<Box<dyn TransportFactory>> {
    registry().write().unwrap().insert(scheme.to_string(), factory)
}

/// Drop the registration for `scheme`. Returns the displaced factory if
/// there was one.
pub fn unregister(scheme: &str) -> Option<Box<dyn TransportFactory>> {
    registry().write().unwrap().remove(scheme)
}

/// True if a factory is registered for `scheme`.
pub fn is_registered(scheme: &str) -> bool {
    registry().read().unwrap().contains_key(scheme)
}

/// List the currently registered schemes. Order is unspecified.
pub fn registered_schemes() -> Vec<String> {
    registry().read().unwrap().keys().cloned().collect()
}

/// Build a transport for `url` by dispatching on its scheme.
///
/// Returns [`Error::TransportNotPossible`] if no factory is registered
/// for the URL's scheme, [`Error::UrlError`] if the URL doesn't parse.
pub fn get_transport(url: &str) -> Result<Box<dyn Transport>> {
    let parsed = Url::parse(url)?;
    let scheme = parsed.scheme().to_string();
    // Strip a `+vendor` qualifier — `http+urllib://` and `http://` should
    // resolve to the same factory. Mirrors `classify_reuse_for`'s rule.
    let key = scheme
        .split_once('+')
        .map(|(s, _)| s.to_string())
        .unwrap_or(scheme);
    let r = registry().read().unwrap();
    let factory = r.get(&key).ok_or_else(|| {
        Error::TransportNotPossible(Some(format!(
            "no transport registered for scheme `{}`",
            key
        )))
    })?;
    factory.build(url)
}

/// Register an SFTP factory backed by a caller-supplied SSH channel
/// opener. The opener takes the parsed URL's host/port/user/password and
/// returns a `Read + Write + Send` byte-stream the SFTP client will run
/// over (russh, ssh2, libssh, a spawned `ssh -s sftp` subprocess, ...).
///
/// Re-registering replaces any previous SFTP factory. Available only
/// when the `sftp` feature is enabled.
#[cfg(feature = "sftp")]
pub fn register_sftp<F>(opener: F)
where
    F: Fn(&Url) -> Result<crate::sftp::BoxedChannel> + Send + Sync + 'static,
{
    let opener = std::sync::Arc::new(opener);
    register(
        "sftp",
        Box::new(move |url: &str| -> Result<Box<dyn Transport>> {
            let parsed = Url::parse(url)?;
            let channel = opener(&parsed)?;
            Ok(Box::new(crate::sftp::SftpTransport::from_channel(
                url, channel,
            )?))
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_scheme_resolves_to_local_transport() {
        let dir = tempfile::tempdir().unwrap();
        let url = url::Url::from_directory_path(dir.path()).unwrap();
        let t = get_transport(url.as_str()).unwrap();
        // Round-trip a write through the boxed trait object to confirm
        // we got a real working transport, not an empty stub.
        t.put_bytes("hello", b"world", None).unwrap();
        assert_eq!(t.get_bytes("hello").unwrap(), b"world");
    }

    #[test]
    fn memory_scheme_resolves_to_memory_transport() {
        let t = get_transport("memory:///").unwrap();
        t.put_bytes("k", b"v", None).unwrap();
        assert_eq!(t.get_bytes("k").unwrap(), b"v");
    }

    #[test]
    fn unknown_scheme_returns_transport_not_possible() {
        let err = get_transport("xyzzy://example/").unwrap_err();
        assert!(
            matches!(err, Error::TransportNotPossible(Some(ref m)) if m.contains("xyzzy")),
            "unexpected error: {:?}",
            err
        );
    }

    #[test]
    fn invalid_url_returns_url_error() {
        let err = get_transport("not a url").unwrap_err();
        assert!(matches!(err, Error::UrlError(_)));
    }

    #[test]
    fn http_plus_vendor_qualifier_resolves_to_http_factory() {
        // We don't actually open a connection — just confirm dispatch
        // accepts the qualified form and reaches the http factory.
        // HttpTransport::new validates the URL synchronously.
        let t = get_transport("http+urllib://example.com/");
        assert!(t.is_ok(), "http+urllib should resolve: {:?}", t.err());
    }

    #[test]
    fn register_and_unregister_round_trips() {
        // Use a unique scheme so we don't collide with other tests
        // running in parallel.
        let scheme = "test-roundtrip-scheme";
        assert!(!is_registered(scheme));
        register(
            scheme,
            Box::new(|_url: &str| -> Result<Box<dyn Transport>> {
                Ok(Box::new(crate::memory::MemoryTransport::new("memory:///")?))
            }),
        );
        assert!(is_registered(scheme));
        let t = get_transport(&format!("{}://anywhere/", scheme)).unwrap();
        // The factory builds a memory transport regardless of the URL,
        // so it must be functional.
        t.put_bytes("k", b"v", None).unwrap();
        assert!(unregister(scheme).is_some());
        assert!(!is_registered(scheme));
    }

    #[test]
    fn registered_schemes_includes_builtins() {
        let s = registered_schemes();
        assert!(s.iter().any(|x| x == "file"));
        assert!(s.iter().any(|x| x == "memory"));
        assert!(s.iter().any(|x| x == "http"));
        assert!(s.iter().any(|x| x == "https"));
    }

    #[cfg(feature = "webdav")]
    #[test]
    fn webdav_scheme_is_registered_when_feature_on() {
        assert!(is_registered("webdav"));
        assert!(is_registered("webdavs"));
    }

    #[cfg(feature = "sftp")]
    #[test]
    fn sftp_factory_uses_caller_supplied_opener() {
        use std::os::unix::net::UnixStream;
        // Spin up the same loopback fake server the sftp tests use so
        // we can verify the registry-built transport is functional. The
        // opener returns one end of a UnixStream pair; the other end
        // runs the fake server.
        register_sftp(|_url: &Url| -> Result<crate::sftp::BoxedChannel> {
            let (a, b) = UnixStream::pair().map_err(Error::Io)?;
            crate::sftp::tests::loopback::spawn_for_registry(b);
            Ok(Box::new(a))
        });
        let t = get_transport("sftp://test/tmp/").unwrap();
        t.put_bytes("k", b"v", None).unwrap();
        assert_eq!(t.get_bytes("k").unwrap(), b"v");
        unregister("sftp");
    }
}
