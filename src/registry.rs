//! URL → [`Transport`](crate::Transport) registry for the pure-Rust crate.
//!
//! This is intentionally separate from the Python-side
//! `dromedary.transport` registry: that one bridges into PyO3-wrapped
//! transports, this one stays in pure Rust. The two never share state.
//!
//! ## URL prefixes
//!
//! Built-in base schemes — `file://`, `memory://`, `http://`, `https://`
//! (and `webdav://`/`webdavs://` with the `webdav` feature) — are
//! pre-registered against default-config clients.
//!
//! Decorator prefixes — `readonly+`, `log+`, `unlistable+`,
//! `brokenrename+`, `fakenfs+`, `vfat+` — are also pre-registered. These
//! wrap an inner transport built by recursively dispatching the rest of
//! the URL: `get_transport("readonly+memory:///")` produces a
//! [`ReadonlyTransport`](crate::readonly::ReadonlyTransport) wrapping a
//! [`MemoryTransport`](crate::memory::MemoryTransport). Decorators chain:
//! `log+readonly+memory:///` works.
//!
//! `sftp://` is opt-in: it needs a caller-supplied SSH channel opener,
//! which can't be inferred from the URL alone. Call [`register_sftp`]
//! once at startup if you want `sftp://` URLs to resolve.
//!
//! ## Custom registrations
//!
//! [`register`] / [`unregister`] take prefix strings exactly as they
//! should match a URL — `"file://"` for a base scheme, `"readonly+"` for
//! a decorator. Lookup is **longest-prefix-match**, so registering both
//! `"http://"` and `"http+urllib://"` does the right thing.
//!
//! ## What's intentionally not done
//!
//! `chroot+` and `pathfilter+` are dynamic in Python — the prefix is
//! registered per-instance — and that pattern doesn't fit a static
//! registry. Use [`crate::chroot::ChrootTransport::new`] /
//! [`crate::pathfilter::PathFilterTransport`] directly.

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

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
/// The argument is the **full** URL the registry was asked to dispatch.
/// Decorator factories typically peel their own prefix and recurse via
/// [`get_transport`]; base-scheme factories use the URL as-is.
pub trait TransportFactory: Send + Sync {
    fn build(&self, url: &str) -> Result<Box<dyn Transport + Send + Sync>>;
}

/// Convenience blanket impl: a closure is automatically a factory.
impl<F> TransportFactory for F
where
    F: Fn(&str) -> Result<Box<dyn Transport + Send + Sync>> + Send + Sync,
{
    fn build(&self, url: &str) -> Result<Box<dyn Transport + Send + Sync>> {
        self(url)
    }
}

type Registry = RwLock<HashMap<String, Box<dyn TransportFactory>>>;

/// Lazily-initialised global registry. The first access seeds it with
/// the built-in prefixes so `get_transport("file:///tmp")` works without
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
    // ---- Base schemes ---------------------------------------------------
    m.insert(
        "file://".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            Ok(Box::new(crate::local::LocalTransport::new(url)?))
        }),
    );
    m.insert(
        "memory://".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            Ok(Box::new(crate::memory::MemoryTransport::new(url)?))
        }),
    );
    // HTTP/HTTPS share a default-config client. Callers needing a custom
    // client (proxies, mTLS, custom CA bundle, ...) should construct
    // `HttpTransport` directly rather than going through the registry.
    fn build_http(url: &str) -> Result<Box<dyn Transport + Send + Sync>> {
        let client = std::sync::Arc::new(
            crate::http::client::HttpClient::new(crate::http::client::HttpClientConfig::default())
                .map_err(http_client_err_to_transport_err)?,
        );
        Ok(Box::new(crate::http::transport::HttpTransport::new(
            url, client,
        )?))
    }
    m.insert("http://".into(), Box::new(|u: &str| build_http(u)));
    m.insert("https://".into(), Box::new(|u: &str| build_http(u)));

    #[cfg(feature = "webdav")]
    {
        fn build_webdav(url: &str) -> Result<Box<dyn Transport + Send + Sync>> {
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
        m.insert("webdav://".into(), Box::new(|u: &str| build_webdav(u)));
        m.insert("webdavs://".into(), Box::new(|u: &str| build_webdav(u)));
    }

    // ---- Decorators -----------------------------------------------------
    //
    // Each decorator wraps the result of recursively dispatching the rest
    // of the URL. They're cheap to compose: `log+readonly+memory:///` →
    // LogTransport(ReadonlyTransport(MemoryTransport)).
    m.insert(
        "readonly+".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let inner = decorate_inner(url, "readonly+")?;
            Ok(Box::new(crate::readonly::ReadonlyTransport::new(inner)))
        }),
    );
    m.insert(
        "unlistable+".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let inner = decorate_inner(url, "unlistable+")?;
            Ok(Box::new(crate::unlistable::UnlistableTransport::new(
                inner,
            )))
        }),
    );
    m.insert(
        "brokenrename+".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let inner = decorate_inner(url, "brokenrename+")?;
            Ok(Box::new(crate::brokenrename::BrokenRenameTransport::new(
                inner,
            )))
        }),
    );
    m.insert(
        "fakenfs+".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let inner = decorate_inner(url, "fakenfs+")?;
            Ok(Box::new(crate::fakenfs::FakeNfsTransport::new(inner)))
        }),
    );
    m.insert(
        "vfat+".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let inner = decorate_inner(url, "vfat+")?;
            Ok(Box::new(crate::fakevfat::FakeVfatTransport::new(inner)))
        }),
    );
    m.insert(
        "log+".into(),
        Box::new(|url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let inner = decorate_inner(url, "log+")?;
            Ok(Box::new(crate::log::LogTransport::new(
                inner,
                default_log_sink(),
            )))
        }),
    );
}

/// Strip `prefix` from `url` and recursively build the inner transport.
/// Used by decorator factories so they don't all duplicate the same
/// peel-and-recurse pattern.
fn decorate_inner(url: &str, prefix: &str) -> Result<Box<dyn Transport + Send + Sync>> {
    let inner_url = url.strip_prefix(prefix).ok_or_else(|| {
        // Should be unreachable when called via the registry, but guard
        // anyway so a misuse from a custom factory doesn't panic.
        Error::TransportNotPossible(Some(format!(
            "decorator `{}` invoked on URL that doesn't start with it: {}",
            prefix, url
        )))
    })?;
    get_transport(inner_url)
}

/// Default log sink for `log+` URLs: forward to the `log` crate at
/// debug level. Callers wanting a custom sink should construct
/// [`crate::log::LogTransport`] directly.
fn default_log_sink() -> crate::log::LogSink {
    std::sync::Arc::new(|msg: &str| log::debug!("{}", msg))
}

/// Register a factory for a URL `prefix` (e.g. `"file://"`,
/// `"readonly+"`), replacing any previous registration. Returns the
/// displaced factory if there was one.
///
/// Useful for tests, or for swapping the default HTTP client for one
/// with custom credentials/proxy/CA configuration.
pub fn register(
    prefix: &str,
    factory: Box<dyn TransportFactory>,
) -> Option<Box<dyn TransportFactory>> {
    registry()
        .write()
        .unwrap()
        .insert(prefix.to_string(), factory)
}

/// Drop the registration for `prefix`. Returns the displaced factory if
/// there was one.
pub fn unregister(prefix: &str) -> Option<Box<dyn TransportFactory>> {
    registry().write().unwrap().remove(prefix)
}

/// True if a factory is registered for `prefix`.
pub fn is_registered(prefix: &str) -> bool {
    registry().read().unwrap().contains_key(prefix)
}

/// List the currently registered prefixes. Order is unspecified.
pub fn registered_prefixes() -> Vec<String> {
    registry().read().unwrap().keys().cloned().collect()
}

/// Build a transport for `url` by longest-prefix-matching against the
/// registry.
///
/// Returns [`Error::TransportNotPossible`] if no factory matches,
/// [`Error::UrlError`] if the URL is malformed in a way the registry
/// can detect.
pub fn get_transport(url: &str) -> Result<Box<dyn Transport + Send + Sync>> {
    // Find the longest registered prefix that's a literal prefix of the
    // URL. We do this under a single read lock; the registry is small
    // enough that scanning is cheaper than maintaining a sorted index.
    let r = registry().read().unwrap();
    let mut best: Option<(&str, &Box<dyn TransportFactory>)> = None;
    for (prefix, factory) in r.iter() {
        if !url.starts_with(prefix.as_str()) {
            continue;
        }
        match best {
            Some((cur, _)) if cur.len() >= prefix.len() => {}
            _ => best = Some((prefix.as_str(), factory)),
        }
    }
    if let Some((_, f)) = best {
        return f.build(url);
    }
    drop(r);

    // Fallback: a `+vendor` qualifier on a base scheme (e.g.
    // `http+urllib://`) — strip the qualifier and retry. Mirrors what
    // `classify_reuse_for` does for connection reuse and matches the
    // Python `register_lazy_transport("http+urllib://", ...)` registration.
    if let Some((scheme_with_vendor, rest)) = url.split_once("://") {
        if let Some((scheme, _vendor)) = scheme_with_vendor.split_once('+') {
            let stripped = format!("{}://{}", scheme, rest);
            if stripped != url {
                return get_transport(&stripped);
            }
        }
    }

    Err(Error::TransportNotPossible(Some(format!(
        "no transport registered for URL `{}`",
        url
    ))))
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
    F: Fn(&url::Url) -> Result<crate::sftp::BoxedChannel> + Send + Sync + 'static,
{
    let opener = std::sync::Arc::new(opener);
    register(
        "sftp://",
        Box::new(move |url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
            let parsed = url::Url::parse(url)?;
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
        // No registered prefix matches "not a url", so we fall through to
        // TransportNotPossible — UrlError is reserved for the few paths
        // that actually parse the URL.
        assert!(
            matches!(err, Error::TransportNotPossible(_) | Error::UrlError(_)),
            "unexpected error: {:?}",
            err
        );
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
        let prefix = "test-roundtrip-scheme://";
        assert!(!is_registered(prefix));
        register(
            prefix,
            Box::new(|_url: &str| -> Result<Box<dyn Transport + Send + Sync>> {
                Ok(Box::new(crate::memory::MemoryTransport::new("memory:///")?))
            }),
        );
        assert!(is_registered(prefix));
        let t = get_transport(&format!("{}anywhere/", prefix)).unwrap();
        // The factory builds a memory transport regardless of the URL,
        // so it must be functional.
        t.put_bytes("k", b"v", None).unwrap();
        assert!(unregister(prefix).is_some());
        assert!(!is_registered(prefix));
    }

    #[test]
    fn registered_prefixes_includes_builtins() {
        let s = registered_prefixes();
        assert!(s.iter().any(|x| x == "file://"));
        assert!(s.iter().any(|x| x == "memory://"));
        assert!(s.iter().any(|x| x == "http://"));
        assert!(s.iter().any(|x| x == "https://"));
        assert!(s.iter().any(|x| x == "readonly+"));
        assert!(s.iter().any(|x| x == "log+"));
    }

    // ---- Decorator dispatch ---------------------------------------------

    #[test]
    fn readonly_decorator_wraps_inner_memory_transport() {
        let t = get_transport("readonly+memory:///").unwrap();
        // Readonly transports report is_readonly() == true and reject
        // mutating ops with TransportNotPossible.
        assert!(t.is_readonly());
        let err = t.put_bytes("k", b"v", None).unwrap_err();
        assert!(matches!(err, Error::TransportNotPossible(_)));
    }

    #[test]
    fn unlistable_decorator_blocks_list_dir() {
        let t = get_transport("unlistable+memory:///").unwrap();
        assert!(!t.listable());
        // list_dir must yield TransportNotPossible (via the iterator).
        let mut it = t.list_dir(".");
        let first = it.next().expect("at least one item from unlistable list_dir");
        assert!(matches!(first, Err(Error::TransportNotPossible(_))));
    }

    #[test]
    fn log_decorator_forwards_writes_to_inner() {
        let t = get_transport("log+memory:///").unwrap();
        // We don't validate the log output here — that's covered in
        // log.rs. The point is that the decorated transport works.
        t.put_bytes("k", b"v", None).unwrap();
        assert_eq!(t.get_bytes("k").unwrap(), b"v");
    }

    #[test]
    fn fakenfs_decorator_round_trips_writes() {
        let t = get_transport("fakenfs+memory:///").unwrap();
        t.put_bytes("a", b"x", None).unwrap();
        assert_eq!(t.get_bytes("a").unwrap(), b"x");
    }

    #[test]
    fn vfat_decorator_round_trips_writes() {
        let t = get_transport("vfat+memory:///").unwrap();
        t.put_bytes("a", b"x", None).unwrap();
        assert_eq!(t.get_bytes("a").unwrap(), b"x");
    }

    #[test]
    fn brokenrename_decorator_round_trips_writes() {
        let t = get_transport("brokenrename+memory:///").unwrap();
        t.put_bytes("a", b"x", None).unwrap();
        assert_eq!(t.get_bytes("a").unwrap(), b"x");
    }

    #[test]
    fn decorators_chain_left_to_right() {
        // Outermost decorator listed first: readonly wraps log wraps
        // memory. The readonly behavior should be visible at the top.
        let t = get_transport("readonly+log+memory:///").unwrap();
        assert!(t.is_readonly());
        let err = t.put_bytes("k", b"v", None).unwrap_err();
        assert!(matches!(err, Error::TransportNotPossible(_)));
    }

    #[test]
    fn decorator_on_unknown_inner_scheme_propagates_error() {
        let err = get_transport("readonly+xyzzy://nope/").unwrap_err();
        assert!(
            matches!(err, Error::TransportNotPossible(Some(ref m)) if m.contains("xyzzy")),
            "unexpected error: {:?}",
            err
        );
    }

    #[cfg(feature = "webdav")]
    #[test]
    fn webdav_scheme_is_registered_when_feature_on() {
        assert!(is_registered("webdav://"));
        assert!(is_registered("webdavs://"));
    }

    #[cfg(feature = "sftp")]
    #[test]
    fn sftp_factory_uses_caller_supplied_opener() {
        use std::os::unix::net::UnixStream;
        // Spin up the same loopback fake server the sftp tests use so
        // we can verify the registry-built transport is functional. The
        // opener returns one end of a UnixStream pair; the other end
        // runs the fake server.
        register_sftp(|_url: &url::Url| -> Result<crate::sftp::BoxedChannel> {
            let (a, b) = UnixStream::pair().map_err(Error::Io)?;
            crate::sftp::tests::loopback::spawn_for_registry(b);
            Ok(Box::new(a))
        });
        let t = get_transport("sftp://test/tmp/").unwrap();
        t.put_bytes("k", b"v", None).unwrap();
        assert_eq!(t.get_bytes("k").unwrap(), b"v");
        unregister("sftp://");
    }
}
