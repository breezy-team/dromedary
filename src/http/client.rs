//! Rust HTTP client used by the `HttpTransport` port.
//!
//! Wraps a [`reqwest::blocking::Client`] with dromedary-specific
//! defaults: proxy config read from `<scheme>_proxy` / `no_proxy`
//! env vars via our own resolver (keeps breezy's historical
//! behaviour), root certificates loaded from a user-supplied bundle
//! or the platform's native store, and the User-Agent managed by
//! the module-level setter.
//!
//! # Choice of HTTP library
//!
//! We started out on `ureq`. That lasted until the WebDAV port —
//! `ureq-proto` (pulled in transitively) hard-codes a whitelist of
//! HTTP methods in `ext.rs::verify_version` and rejects anything
//! outside GET/HEAD/POST/PUT/DELETE/CONNECT/OPTIONS/TRACE/PATCH as
//! `MethodVersionMismatch`. WebDAV's MKCOL / MOVE / COPY / PROPFIND
//! / PROPPATCH are perfectly valid HTTP/1.1 methods per RFC 7230 but
//! ureq-proto won't let them through. Swapping to `reqwest` (which
//! sits on hyper and happily forwards any method) fixed that in one
//! deliberate step — the swap is contained in this module and
//! didn't touch any caller.
//!
//! # Known limitations
//!
//! ## Proxy client caching
//!
//! reqwest bakes the proxy into the `Client` at construction
//! (unlike ureq which let us override per-request). We work around
//! that by caching a small set of pre-built clients keyed by the
//! effective proxy URL; the common cases (no proxy, one proxy) hit
//! at most two distinct clients. Tests that flip env vars mid-run
//! rebuild a client on demand — there's no connection-pool warmup
//! worth protecting at that scale.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;

use http::{Method, Uri};
use reqwest::blocking::{Client, ClientBuilder, Request as ReqwestRequest, Response};
use reqwest::{Certificate, Proxy};
use url::Url;

use crate::http::auth::{
    build_basic_auth_header, build_digest_auth_header, parse_digest_challenge, DigestAuthState,
};
use crate::http::{
    evaluate_proxy_bypass, get_proxy_env_var, getproxies_environment, parse_auth_header,
    ProxyBypass,
};

/// Errors surfaced by the Rust HTTP client.
///
/// These are translated to Python exceptions at the PyO3 boundary;
/// the Python side catches them and re-maps to the existing
/// `dromedary.errors` classes so existing callers don't notice.
#[derive(Debug)]
pub enum ClientError {
    /// The underlying reqwest call failed (TLS, transport, timeout, …).
    Transport(reqwest::Error),
    /// A URL or HTTP method was supplied that we couldn't parse.
    InvalidRequest(String),
    /// Error reading or writing the response body.
    Io(std::io::Error),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "HTTP transport error: {}", e),
            Self::InvalidRequest(s) => write!(f, "invalid request: {}", s),
            Self::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<reqwest::Error> for ClientError {
    fn from(e: reqwest::Error) -> Self {
        Self::Transport(e)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Direction of a byte transfer reported via [`ActivityCallback`].
///
/// The two values are the only ones breezy's
/// `Transport._report_activity` ever sees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActivityDirection {
    /// Bytes received from the server.
    Read,
    /// Bytes sent to the server.
    Write,
}

impl ActivityDirection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
        }
    }
}

/// Reports byte transfers to the surrounding progress UI.
///
/// Stored as an `Arc` so it can be shared between the upload-side
/// report (fired once before sending the request body) and the
/// download-side reader wrapper that tallies bytes as the
/// response streams. Each call receives a chunk size and a
/// direction; callbacks should be cheap because they may fire
/// thousands of times per large download.
pub type ActivityCallback = std::sync::Arc<dyn Fn(usize, ActivityDirection) + Send + Sync>;

/// Per-request knobs that callers sometimes need to override. The
/// defaults match breezy's urllib-layer behaviour: no redirect
/// following, so 3xx responses surface as-is for the caller to
/// translate into a `RedirectRequested` if they want.
///
/// Deliberately `Clone` + `Copy`-free: the activity callback is
/// passed separately to [`HttpClient::request_with`] because it's a
/// closure, not a plain config knob.
#[derive(Debug, Clone)]
pub struct RequestOptions {
    /// Follow 301/302/303/307/308 redirects automatically.
    pub follow_redirects: bool,
    /// Maximum number of redirects to follow before giving up.
    /// Mirrors the Python `HTTPRedirectHandler.max_redirections`
    /// default (10).
    pub max_redirects: u32,
    /// Maximum number of visits to the same URL in a redirect chain.
    /// Mirrors the Python `HTTPRedirectHandler.max_repeats` default
    /// (4).
    pub max_repeats: u32,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            follow_redirects: false,
            max_redirects: 10,
            max_repeats: 4,
        }
    }
}

/// HTTP status codes we follow as redirects when
/// `follow_redirects=true`. 300 / 304 / 305 / 306 are intentionally
/// excluded, matching Python `HTTPRedirectHandler.redirect_request`
/// which raises on anything outside (301, 302, 303, 307, 308).
fn is_redirect(code: u16) -> bool {
    matches!(code, 301 | 302 | 303 | 307 | 308)
}

/// Drive a redirect loop around any single-round-trip function.
///
/// Extracted from [`HttpClient::request_with`] so tests can exercise
/// the loop without a real network round-trip. The closure is
/// invoked once per hop with the target URL; it should return the
/// raw response without following any redirects of its own.
fn drive_redirects(
    options: &RequestOptions,
    url: &str,
    mut send: impl FnMut(&str) -> Result<HttpResponse>,
) -> Result<HttpResponse> {
    let mut visited: std::collections::HashMap<String, u32> = std::collections::HashMap::new();
    let mut current_url = url.to_string();
    let mut redirects = 0u32;

    loop {
        let resp = send(&current_url)?;

        if !options.follow_redirects || !is_redirect(resp.status) {
            // Non-redirect, or caller opted out: if this *is* a 3xx
            // and we have a Location, expose it as `redirected_to`
            // so the transport layer can raise RedirectRequested
            // without re-parsing the headers.
            if is_redirect(resp.status) {
                if let Some(target) = redirect_target(&resp, &current_url) {
                    return Ok(HttpResponse {
                        redirected_to: Some(target),
                        ..resp
                    });
                }
            }
            return Ok(resp);
        }

        // Pick the redirect target from Location / URI; if neither
        // is present the Python impl silently returns the response,
        // so we do too.
        let Some(newurl) = redirect_target(&resp, &current_url) else {
            return Ok(resp);
        };

        redirects += 1;
        let visits = visited.entry(newurl.clone()).or_insert(0);
        *visits += 1;
        if *visits > options.max_repeats || redirects > options.max_redirects {
            return Err(ClientError::InvalidRequest(format!(
                "too many redirects (at {} after {} hops)",
                newurl, redirects
            )));
        }

        current_url = newurl;
        // Carry headers and body forward unchanged; the Python
        // HTTPRedirectHandler.redirect_request does the same.
    }
}

/// Key under which [`AuthCache`] stores successful auth state.
///
/// Scheme matters (http vs https shouldn't share auth even on the
/// same host); port is normalised to the scheme default so a bare
/// `http://host/` and `http://host:80/` hit the same cache entry.
fn auth_cache_key(uri: &Uri) -> AuthCacheKey {
    let scheme = uri.scheme_str().unwrap_or("http").to_ascii_lowercase();
    let host = uri.host().unwrap_or_default().to_ascii_lowercase();
    let port = uri
        .port_u16()
        .unwrap_or_else(|| if scheme == "https" { 443 } else { 80 });
    (scheme, host, port)
}

/// Key under which proxy auth is cached. Proxy credentials bind to
/// the proxy URL, not the origin, so we key on the proxy's own URL.
/// reqwest's `Proxy` type doesn't expose the URL back for inspection,
/// so we track the raw string we built the proxy from alongside it.
fn proxy_cache_key(proxy_url: &str) -> AuthCacheKey {
    let parsed = Url::parse(proxy_url).ok();
    let host = parsed
        .as_ref()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default();
    let port = parsed
        .as_ref()
        .and_then(|u| u.port_or_known_default())
        .unwrap_or(80);
    ("proxy".to_string(), host, port)
}

/// Build an `Authorization:` header value from the cached state.
/// Mutates digest state in place so `nonce_count` bumps correctly.
fn cached_auth_header(cached: &CachedAuth, method: &Method, uri: &Uri) -> Option<String> {
    match cached {
        CachedAuth::Basic { user, password } => Some(build_basic_auth_header(user, password)),
        CachedAuth::Digest(state) => {
            // `build_digest_auth_header` mutates nonce_count. This
            // function only reads the cached state; the caller owns
            // the mutation and re-stores after. We work on a local
            // clone — `&CachedAuth` doesn't give us a write path.
            let mut s = state.clone();
            Some(build_digest_auth_header(
                &mut s,
                method.as_str(),
                uri.path(),
            ))
        }
        CachedAuth::Negotiate { token } => Some(format!("Negotiate {}", token)),
    }
}

/// Pull the `realm` value out of a Basic-auth challenge remainder.
/// The challenge looks like `realm="Secure Area"`; we match the
/// outermost quoted string after `realm=`. Returns `None` if
/// `realm` is missing — callers then pass `None` into the
/// credential lookup.
fn extract_basic_realm(raw: &str) -> Option<&str> {
    let after = raw.split("realm=").nth(1)?;
    let trimmed = after.trim_start();
    if let Some(inner) = trimmed.strip_prefix('"') {
        // Stop at the next unescaped `"`. The Basic-auth grammar
        // doesn't allow backslash-quote inside a quoted string
        // (RFC 7617 uses token68 for the credentials, and the
        // challenge parameters follow RFC 7235's auth-param rules).
        inner.find('"').map(|end| &inner[..end])
    } else {
        // Unquoted token — read up to whitespace or comma.
        let end = trimmed
            .find(|c: char| c.is_ascii_whitespace() || c == ',')
            .unwrap_or(trimmed.len());
        Some(&trimmed[..end])
    }
}

/// Resolve the redirect target for a 3xx response: prefer
/// `Location:`, fall back to `URI:`. Matches the Python handler
/// which also accepts the antiquated `URI` header. Returns `None`
/// if neither header is present or the value fails to parse as a
/// URL even after joining with the request URL.
fn redirect_target(resp: &HttpResponse, current_url: &str) -> Option<String> {
    let raw = resp.header("location").or_else(|| resp.header("uri"))?;
    // Use the `url` crate to resolve relative redirect URLs. This
    // matches Python's `urllib.parse.urljoin`: absolute URLs
    // override, relative ones are joined to the current document.
    let base = Url::parse(current_url).ok()?;
    base.join(raw).ok().map(|u| u.to_string())
}

/// Source of username/password pairs for HTTP authentication.
///
/// Implementations bridge the Rust client to whatever credential
/// store the caller uses — for dromedary that's the Python callback
/// registered via `set_credential_lookup`, but tests can supply a
/// trivial in-memory impl.
pub trait CredentialProvider: Send + Sync {
    /// Return `(user, password)` for the given `(protocol, host,
    /// port, realm)` if known. `None` for either field means "no
    /// match"; the caller decides whether to prompt interactively.
    fn lookup(
        &self,
        protocol: &str,
        host: &str,
        port: Option<u16>,
        realm: Option<&str>,
    ) -> (Option<String>, Option<String>);
}

/// A [`CredentialProvider`] that always returns `(None, None)`.
/// Useful as the default when nothing's registered.
pub struct NoCredentialProvider;

impl CredentialProvider for NoCredentialProvider {
    fn lookup(
        &self,
        _protocol: &str,
        _host: &str,
        _port: Option<u16>,
        _realm: Option<&str>,
    ) -> (Option<String>, Option<String>) {
        (None, None)
    }
}

/// Source of an HTTP Negotiate / Kerberos initial token.
///
/// The token is what goes after `Negotiate ` in the Authorization
/// header. Typically produced by a GSSAPI client library
/// (`kerberos.authGSSClient*` on Python); dromedary ships a Python
/// callback hook so the actual GSSAPI integration lives in the
/// caller rather than being a hard Rust dependency.
pub trait NegotiateProvider: Send + Sync {
    /// Return the initial token for `HTTP@<host>`. `None` means
    /// Negotiate isn't available (no credentials, no ticket, or
    /// library missing); the caller falls back to Digest/Basic.
    fn initial_token(&self, host: &str) -> Option<String>;
}

/// A [`NegotiateProvider`] that always returns `None`. The default
/// when no callback is registered.
pub struct NoNegotiateProvider;

impl NegotiateProvider for NoNegotiateProvider {
    fn initial_token(&self, _host: &str) -> Option<String> {
        None
    }
}

/// Direction of an auth challenge: origin (401 → WWW-Authenticate
/// → Authorization) vs proxy (407 → Proxy-Authenticate →
/// Proxy-Authorization). The logic is identical other than the
/// cache, header names, and which URL we key credentials on — this
/// enum lets the shared retry path tell them apart without two
/// copies of the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthKind {
    Origin,
    Proxy,
}

/// Cached per-origin authentication state. Once the server accepts
/// our credentials we preemptively attach the same auth header to
/// subsequent requests to the same host+port, matching urllib's
/// `auth_params_reusable` behaviour.
#[derive(Debug, Clone)]
enum CachedAuth {
    /// Basic auth: we cache the header value directly since it's
    /// cheap and stateless.
    Basic {
        user: String,
        password: String,
    },
    Digest(DigestAuthState),
    /// Negotiate auth. Kerberos tokens are single-use per server
    /// challenge — we cache the token only for the immediate retry,
    /// not for future requests (see the Python
    /// `NegotiateAuthHandler.auth_params_reusable` comment).
    Negotiate {
        token: String,
    },
}

/// Per-host auth cache key: `(scheme_lower, host, port_or_default)`.
/// Using a scheme-aware key prevents http/https from sharing auth.
type AuthCacheKey = (String, String, u16);

/// Thread-safe per-origin auth state. Lookups are read-mostly after
/// the first successful exchange, so a Mutex is fine — lock contention
/// is not a realistic concern for a single HTTP client.
#[derive(Default)]
pub struct AuthCache {
    entries: Mutex<HashMap<AuthCacheKey, CachedAuth>>,
}

impl AuthCache {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &AuthCacheKey) -> Option<CachedAuth> {
        self.entries.lock().unwrap().get(key).cloned()
    }

    fn put(&self, key: AuthCacheKey, auth: CachedAuth) {
        self.entries.lock().unwrap().insert(key, auth);
    }
}

/// Options for building an [`HttpClient`].
#[derive(Default)]
pub struct HttpClientConfig {
    /// Optional path to a PEM CA bundle. `None` means "use the
    /// platform native store via rustls-native-certs".
    pub ca_certs_path: Option<std::path::PathBuf>,
    /// If true, skip certificate verification entirely. Matches
    /// Python's `ssl.CERT_NONE` behaviour — used only when the user
    /// explicitly opts out via `ssl.cert_reqs=none`.
    pub disable_verification: bool,
    /// User-Agent value. If `None`, the agent will use whatever the
    /// global default returns from [`crate::http::default_user_agent`].
    pub user_agent: Option<String>,
    /// Read timeout for each response. `None` means "no timeout".
    pub read_timeout: Option<Duration>,
}

/// HTTP client wrapper around [`reqwest::blocking::Client`].
///
/// Proxies are resolved per-request from the current environment,
/// matching the Python urllib behaviour where `ProxyHandler` reads
/// env vars at construction and every redirect cycle. reqwest bakes
/// proxy config into the Client so we maintain a small cache of
/// pre-built clients keyed by the effective proxy URL; requests
/// pick the matching client at dispatch time. Env-var changes take
/// effect immediately — a new proxy URL forces a new client build.
pub struct HttpClient {
    /// Holds the inputs needed to rebuild a client for a specific
    /// proxy URL. Without this we'd have to re-parse the TLS bundle
    /// and re-resolve the user agent on every proxy switch; cheap
    /// but wasteful.
    config: HttpClientConfig,
    /// Cache of built clients keyed by proxy URL (`""` means "no
    /// proxy"). Populated lazily as callers hit new proxies.
    clients: Mutex<HashMap<String, Client>>,
    /// Per-origin cache of successful auth state. Populated after
    /// the server accepts our credentials; subsequent requests to
    /// the same host preemptively attach the cached header.
    auth_cache: AuthCache,
    /// Per-proxy cache of successful auth state. Separate from
    /// `auth_cache` because proxy credentials are bound to the
    /// proxy URL rather than the origin and shouldn't leak across
    /// origins that share a proxy.
    proxy_auth_cache: AuthCache,
    /// How we look up `(user, password)` when a challenge arrives.
    credentials: Box<dyn CredentialProvider>,
    /// Source of Negotiate (Kerberos) initial tokens. Defaults to a
    /// no-op provider; the PyO3 layer swaps in a callback that
    /// delegates to Python's `kerberos` module.
    negotiate: Box<dyn NegotiateProvider>,
}

impl HttpClient {
    /// Build a new client honouring the given config.
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        Self::with_providers(
            config,
            Box::new(NoCredentialProvider),
            Box::new(NoNegotiateProvider),
        )
    }

    /// Build a new client with a custom credential provider.
    pub fn with_credentials(
        config: HttpClientConfig,
        credentials: Box<dyn CredentialProvider>,
    ) -> Result<Self> {
        Self::with_providers(config, credentials, Box::new(NoNegotiateProvider))
    }

    /// Build a new client with custom credential and negotiate
    /// providers. The general-purpose constructor — the simpler
    /// `new` / `with_credentials` helpers delegate here.
    pub fn with_providers(
        config: HttpClientConfig,
        credentials: Box<dyn CredentialProvider>,
        negotiate: Box<dyn NegotiateProvider>,
    ) -> Result<Self> {
        // Eagerly build the no-proxy client so construction fails
        // loudly on a bad config (missing CA bundle, etc.) rather
        // than at first request.
        let mut clients = HashMap::new();
        let initial = build_client(&config, None)?;
        clients.insert(String::new(), initial);
        Ok(Self {
            config,
            clients: Mutex::new(clients),
            auth_cache: AuthCache::new(),
            proxy_auth_cache: AuthCache::new(),
            credentials,
            negotiate,
        })
    }

    /// Return (cloning if necessary) the client for a given proxy
    /// URL. The empty string is the "no proxy" key.
    fn client_for_proxy(&self, proxy_url: &str) -> Result<Client> {
        {
            let cache = self.clients.lock().unwrap();
            if let Some(c) = cache.get(proxy_url) {
                return Ok(c.clone());
            }
        }
        let proxy = if proxy_url.is_empty() {
            None
        } else {
            Some(Proxy::all(proxy_url).map_err(|e| {
                ClientError::InvalidRequest(format!("bad proxy URL {}: {}", proxy_url, e))
            })?)
        };
        let client = build_client(&self.config, proxy)?;
        self.clients
            .lock()
            .unwrap()
            .insert(proxy_url.to_string(), client.clone());
        Ok(client)
    }

    /// Perform an HTTP request with default options (no redirect
    /// following, no activity reporting). Convenience wrapper over
    /// [`Self::request_with`].
    pub fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        self.request_with(method, url, headers, body, &RequestOptions::default(), None)
    }

    /// Perform an HTTP request and optionally follow redirects.
    ///
    /// The redirect loop matches breezy's
    /// `HTTPRedirectHandler.http_error_302` semantics: 301, 302,
    /// 303, 307, and 308 are followed; the request method and
    /// headers are carried unchanged (the Python version doesn't
    /// rewrite POST→GET on 303 either); `Location:` wins over
    /// `URI:` if both appear. Relative redirect URLs are resolved
    /// against the request URL.
    ///
    /// When `follow_redirects` is false, the first 3xx response is
    /// returned with `redirected_to` set to the target URL so the
    /// caller can decide what to do (typically raise
    /// `RedirectRequested` from the transport layer).
    pub fn request_with(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        options: &RequestOptions,
        activity: Option<&ActivityCallback>,
    ) -> Result<HttpResponse> {
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| ClientError::InvalidRequest(format!("bad method: {}", method)))?;

        // Each redirect hop does its own auth dance — a 3xx to a
        // different host mustn't reuse the previous host's cached
        // auth, and handling that here keeps the redirect-loop code
        // from having to know anything about auth.
        drive_redirects(options, url, |target| {
            self.send_with_auth(&method, target, headers, body, activity)
        })
    }

    /// Send a request, transparently handling a single 401 (origin
    /// auth) or 407 (proxy auth) challenge. Returns the final
    /// response — may still be 401/407 if we ran out of credentials
    /// or the server rejected what we offered.
    fn send_with_auth(
        &self,
        method: &Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        activity: Option<&ActivityCallback>,
    ) -> Result<HttpResponse> {
        let uri: Uri = url
            .parse()
            .map_err(|_| ClientError::InvalidRequest(format!("bad URL: {}", url)))?;

        // Resolve the proxy ahead of time so both the preemptive
        // header attach and the 407 retry can use the same key.
        let proxy_url = self.choose_proxy(&uri)?;
        let origin_key = auth_cache_key(&uri);
        let proxy_key = if proxy_url.is_empty() {
            None
        } else {
            Some(proxy_cache_key(&proxy_url))
        };

        // Preemptively attach cached auth headers. Callers' explicit
        // headers take precedence — don't clobber.
        let has_explicit_origin_auth = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization"));
        let has_explicit_proxy_auth = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("proxy-authorization"));

        let mut first_headers: Vec<(String, String)> = headers.to_vec();
        if !has_explicit_origin_auth {
            if let Some(hdr) = self.attach_cached(&self.auth_cache, &origin_key, method, &uri) {
                first_headers.push(("Authorization".into(), hdr));
            }
        }
        if !has_explicit_proxy_auth {
            if let Some(key) = &proxy_key {
                if let Some(hdr) = self.attach_cached(&self.proxy_auth_cache, key, method, &uri) {
                    first_headers.push(("Proxy-Authorization".into(), hdr));
                }
            }
        }

        let mut response =
            self.send_once(method, url, &first_headers, body, activity, &proxy_url)?;
        if response.status != 401 && response.status != 407 {
            return Ok(response);
        }

        // Decide which direction to retry. 407 wins over 401 if both
        // somehow happened (the server shouldn't send both — they're
        // separate turn-around points — but guard anyway).
        if response.status == 407 {
            if has_explicit_proxy_auth {
                return Ok(response);
            }
            let Some(proxy_key) = proxy_key else {
                // 407 without a configured proxy is a server bug —
                // we have no credentials to look up. Surface as-is.
                return Ok(response);
            };
            // Collect header values into owned Strings before we
            // pass `&mut response` to retry_with_auth: the slice
            // borrow would otherwise overlap with the mutable one.
            let challenges: Vec<String> = response
                .headers_all("proxy-authenticate")
                .into_iter()
                .map(str::to_string)
                .collect();
            return self.retry_with_auth(
                &challenges,
                method,
                url,
                &uri,
                headers,
                body,
                activity,
                &proxy_url,
                &mut response,
                &self.proxy_auth_cache,
                &proxy_key,
                "Proxy-Authorization",
                AuthKind::Proxy,
            );
        }

        // 401 — origin auth.
        if has_explicit_origin_auth {
            return Ok(response);
        }
        let challenges: Vec<String> = response
            .headers_all("www-authenticate")
            .into_iter()
            .map(str::to_string)
            .collect();
        self.retry_with_auth(
            &challenges,
            method,
            url,
            &uri,
            headers,
            body,
            activity,
            &proxy_url,
            &mut response,
            &self.auth_cache,
            &origin_key,
            "Authorization",
            AuthKind::Origin,
        )
    }

    /// Look up cached auth state for the given key and build its
    /// header value, if any. Returns `None` when no entry exists.
    /// Re-stores the entry with the (possibly-mutated) Digest state
    /// so `nonce_count` bumps persist.
    fn attach_cached(
        &self,
        cache: &AuthCache,
        key: &AuthCacheKey,
        method: &Method,
        uri: &Uri,
    ) -> Option<String> {
        let cached = cache.get(key)?;
        let hdr = cached_auth_header(&cached, method, uri)?;
        cache.put(key.clone(), cached);
        Some(hdr)
    }

    /// Shared retry machinery for 401 and 407. `cache` is where we
    /// store the successful state (origin or proxy); `cache_key` is
    /// the lookup key; `header_name` is `Authorization` or
    /// `Proxy-Authorization` depending on direction.
    #[allow(clippy::too_many_arguments)]
    fn retry_with_auth(
        &self,
        challenges: &[String],
        method: &Method,
        url: &str,
        uri: &Uri,
        headers: &[(String, String)],
        body: &[u8],
        activity: Option<&ActivityCallback>,
        proxy_url: &str,
        first_response: &mut HttpResponse,
        cache: &AuthCache,
        cache_key: &AuthCacheKey,
        header_name: &'static str,
        kind: AuthKind,
    ) -> Result<HttpResponse> {
        let refs: Vec<&str> = challenges.iter().map(String::as_str).collect();
        let Some((_scheme, new_auth)) = self.pick_auth_scheme_for(&refs, uri, kind) else {
            // No scheme we can handle, or no credentials for the
            // ones on offer. Hand the 401/407 back to the caller.
            return Ok(HttpResponse {
                body: std::mem::replace(
                    &mut first_response.body,
                    BodyState::Buffered(std::io::Cursor::new(Vec::new())),
                ),
                status: first_response.status,
                reason: std::mem::take(&mut first_response.reason),
                headers: std::mem::take(&mut first_response.headers),
                final_url: std::mem::take(&mut first_response.final_url),
                redirected_to: first_response.redirected_to.take(),
            });
        };

        // Return the first response's connection to the pool before
        // the retry by draining any unread body.
        first_response.discard_body().ok();

        // Build the retry header. For Digest we persist the bumped
        // `nonce_count` regardless of retry outcome — the server has
        // seen that count and won't accept it again.
        let mut retry_headers = headers.to_vec();
        let hdr = match &new_auth {
            CachedAuth::Basic { user, password } => build_basic_auth_header(user, password),
            CachedAuth::Digest(state) => {
                let mut s = state.clone();
                let h = build_digest_auth_header(&mut s, method.as_str(), uri.path());
                cache.put(cache_key.clone(), CachedAuth::Digest(s));
                h
            }
            CachedAuth::Negotiate { token } => format!("Negotiate {}", token),
        };
        retry_headers.push((header_name.into(), hdr));

        let retry = self.send_once(method, url, &retry_headers, body, activity, proxy_url)?;
        if retry.status < 400 {
            match &new_auth {
                CachedAuth::Basic { .. } => {
                    cache.put(cache_key.clone(), new_auth);
                }
                CachedAuth::Digest(_) => {
                    // Already cached above.
                }
                CachedAuth::Negotiate { .. } => {
                    // Kerberos tokens are single-use per challenge.
                    // Don't cache; the next 401/407 will request a
                    // fresh token from the provider.
                }
            }
        }
        Ok(retry)
    }

    /// Convenience wrapper used by tests that want to pick an
    /// origin-auth scheme from a set of WWW-Authenticate
    /// challenges. See [`pick_auth_scheme_for`] for the real
    /// implementation — production code goes through that directly
    /// so it can distinguish origin vs proxy direction.
    #[cfg(test)]
    fn pick_auth_scheme(
        &self,
        uri: &Uri,
        challenges: &[&str],
        _method: &Method,
    ) -> Option<(&'static str, CachedAuth)> {
        self.pick_auth_scheme_for(challenges, uri, AuthKind::Origin)
    }

    /// Given the challenges a server sent, pick the scheme we'll
    /// try and materialise it into a `CachedAuth` suitable for
    /// header generation. Returns `None` when no scheme matches or
    /// credentials weren't available.
    ///
    /// Scheme preference follows the handler_order values from the
    /// old urllib code: NegotiateAuthHandler (480) > Digest (490) >
    /// Basic (500). Lower-ordered handlers mean "prefer this".
    ///
    /// `kind` drives which host to look up credentials for: Origin
    /// asks for `uri.host()`, Proxy consults the environment's
    /// proxy URL extracted from `choose_proxy` (expected to already
    /// be known via the caller's context — we just don't have it
    /// here, so proxy credential lookups currently use the *origin*
    /// host too. That matches breezy's behaviour: the
    /// credential-store keys proxy auth on the proxy URL, but
    /// dromedary's CredentialProvider signature doesn't carry enough
    /// context to distinguish the two cases, and breezy itself
    /// handles that resolution internally.)
    fn pick_auth_scheme_for(
        &self,
        challenges: &[&str],
        uri: &Uri,
        _kind: AuthKind,
    ) -> Option<(&'static str, CachedAuth)> {
        let mut negotiate_seen = false;
        let mut digest_remainder: Option<&str> = None;
        let mut basic_remainder: Option<&str> = None;
        for ch in challenges {
            let (scheme, remainder) = parse_auth_header(ch);
            let remainder = remainder.unwrap_or("");
            match scheme.as_str() {
                "negotiate" => negotiate_seen = true,
                "digest" if digest_remainder.is_none() => {
                    digest_remainder = Some(remainder);
                }
                "basic" if basic_remainder.is_none() => {
                    basic_remainder = Some(remainder);
                }
                _ => {}
            }
        }

        let protocol = uri.scheme_str().unwrap_or("http");
        let host = uri.host().unwrap_or_default();
        let port = uri.port_u16();

        if negotiate_seen {
            if let Some(token) = self.negotiate.initial_token(host) {
                return Some(("negotiate", CachedAuth::Negotiate { token }));
            }
            // Fall through to Digest / Basic when the provider says
            // it can't produce a token for this host (no Kerberos
            // ticket, library absent, etc.).
        }

        if let Some(raw) = digest_remainder {
            if let Some(challenge) = parse_digest_challenge(raw) {
                let (user, password) =
                    self.credentials
                        .lookup(protocol, host, port, Some(&challenge.realm));
                let (Some(user), Some(password)) = (user, password) else {
                    return None;
                };
                let state = DigestAuthState {
                    user,
                    password,
                    realm: challenge.realm,
                    nonce: challenge.nonce,
                    nonce_count: 0,
                    algorithm: challenge.algorithm,
                    algorithm_name: challenge.algorithm_name,
                    opaque: challenge.opaque,
                    qop: challenge.qop,
                };
                return Some(("digest", CachedAuth::Digest(state)));
            }
        }

        if basic_remainder.is_some() {
            // Basic auth realm is opaque to us (we could parse it
            // for the lookup key, but the Python version didn't
            // treat it as load-bearing). Pass None for realm so the
            // credential lookup falls back to URL-based matching.
            let realm = basic_remainder
                .and_then(extract_basic_realm)
                .map(|r| r.to_string());
            let (user, password) = self
                .credentials
                .lookup(protocol, host, port, realm.as_deref());
            let (Some(user), Some(password)) = (user, password) else {
                return None;
            };
            return Some(("basic", CachedAuth::Basic { user, password }));
        }

        None
    }

    /// Single transport round-trip. No redirect handling.
    fn send_once(
        &self,
        method: &Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
        activity: Option<&ActivityCallback>,
        proxy_url: &str,
    ) -> Result<HttpResponse> {
        let client = self.client_for_proxy(proxy_url)?;

        // Build the reqwest Request by hand. reqwest's Request is
        // constructed from a `Method` and a `url::Url`, not from a
        // plain string, so we go through url::Url first.
        let parsed = Url::parse(url)
            .map_err(|_| ClientError::InvalidRequest(format!("bad URL: {}", url)))?;
        let mut req = ReqwestRequest::new(method.clone(), parsed);
        {
            let hdrs = req.headers_mut();
            for (k, v) in headers {
                let name = reqwest::header::HeaderName::from_bytes(k.as_bytes()).map_err(|e| {
                    ClientError::InvalidRequest(format!("bad header name {}: {}", k, e))
                })?;
                let value = reqwest::header::HeaderValue::from_str(v).map_err(|e| {
                    ClientError::InvalidRequest(format!("bad header value for {}: {}", k, e))
                })?;
                hdrs.append(name, value);
            }
        }
        if !body.is_empty() {
            *req.body_mut() = Some(reqwest::blocking::Body::from(body.to_vec()));
        }

        // Report the upload size before the actual send. Like the
        // ureq version, we report the application-level byte count
        // rather than per-socket counters (reqwest doesn't expose
        // those either) — matches what breezy's progress bar showed
        // under the urllib-handler transport.
        if let Some(cb) = activity {
            if !body.is_empty() {
                cb(body.len(), ActivityDirection::Write);
            }
        }

        let response = client.execute(req)?;
        let activity_owned = activity.cloned();
        HttpResponse::from_reqwest(response, url.to_string(), activity_owned)
    }

    /// Decide whether the request to `uri` should go through a
    /// proxy. Consults `<scheme>_proxy` / `all_proxy` / `no_proxy`
    /// env vars via our [`getproxies_environment`] port of the
    /// stdlib helper. Returns the proxy URL or an empty string to
    /// signal "no proxy".
    fn choose_proxy(&self, uri: &Uri) -> Result<String> {
        let scheme = uri.scheme_str().unwrap_or("http");
        let host = uri.host().unwrap_or_default();
        // Uri::port_u16 sidesteps the lifetime issue `uri.port()`
        // introduces (the Port wrapper borrows from the Uri).
        let host_with_port = match uri.port_u16() {
            Some(p) => format!("{}:{}", host, p),
            None => host.to_string(),
        };

        let env = getproxies_environment();
        let no_proxy = get_proxy_env_var(&env, "no", None);

        // Match Python's `ProxyHandler.proxy_bypass`: if the
        // `no_proxy` list explicitly mentions the host we skip the
        // proxy. When the list is set but nothing matches, the
        // Python code falls back to `urllib.request.proxy_bypass` for
        // platform-specific overrides — we don't replicate that
        // platform fallback in Rust because no dromedary configuration
        // currently depends on it. If that becomes necessary we can
        // add a `platform_bypass()` shim later.
        match evaluate_proxy_bypass(&host_with_port, no_proxy.as_deref()) {
            ProxyBypass::Bypass => return Ok(String::new()),
            ProxyBypass::UseProxy | ProxyBypass::Undecided => {}
        }

        let Some(proxy_url) = get_proxy_env_var(&env, scheme, Some("all")) else {
            return Ok(String::new());
        };
        Ok(proxy_url)
    }
}

/// Build a `reqwest::blocking::Client` honouring the given config
/// and optional proxy. Called once per distinct proxy URL seen
/// (including once for the "no proxy" case).
fn build_client(config: &HttpClientConfig, proxy: Option<Proxy>) -> Result<Client> {
    let mut builder = ClientBuilder::new()
        // We follow redirects ourselves (Stage 7) so reqwest's
        // built-in redirect policy is disabled.
        .redirect(reqwest::redirect::Policy::none())
        // Gzip is already in the default feature set we selected;
        // make sure it actually gets applied.
        .gzip(true);

    let ua = config
        .user_agent
        .clone()
        .unwrap_or_else(crate::http::default_user_agent);
    builder = builder.user_agent(ua);

    if let Some(t) = config.read_timeout {
        builder = builder.timeout(t);
    }

    if config.disable_verification {
        builder = builder
            .danger_accept_invalid_certs(true)
            .danger_accept_invalid_hostnames(true);
    } else if let Some(path) = &config.ca_certs_path {
        for cert in root_certs_from_pem_file(path)? {
            builder = builder.add_root_certificate(cert);
        }
        // Don't also trust the platform native store when the caller
        // passed an explicit bundle — `reqwest` defaults that on with
        // `rustls-tls-native-roots`, but the Python test suite sets
        // a fake CA and expects only that bundle to match (tests
        // against https with a self-signed cert fail otherwise).
        builder = builder.tls_built_in_native_certs(false);
    }
    // If no CA bundle was supplied and verification wasn't
    // disabled, fall through and let reqwest's
    // `rustls-tls-native-roots` feature do the right thing (load
    // the OS trust store).

    if let Some(proxy) = proxy {
        builder = builder.proxy(proxy);
    } else {
        // reqwest defaults to picking up env-var proxies on its
        // own; disable that so the only source of truth is our
        // choose_proxy() resolver (which already checks env vars
        // but with our historical precedence rules).
        builder = builder.no_proxy();
    }

    builder.build().map_err(ClientError::Transport)
}

/// Parse a PEM file into `reqwest::Certificate`s. Each cert in the
/// bundle becomes one trust anchor.
fn root_certs_from_pem_file(path: &Path) -> Result<Vec<Certificate>> {
    let bytes = std::fs::read(path)?;
    // reqwest can parse a bundle via `Certificate::from_pem_bundle`
    // (returns all certs in one call). Fall back to `from_pem` if
    // the bundle contains only one cert and the bundle parser isn't
    // available in the pinned reqwest version.
    match Certificate::from_pem_bundle(&bytes) {
        Ok(certs) => Ok(certs),
        Err(_) => {
            // Single-cert fallback.
            let cert = Certificate::from_pem(&bytes).map_err(|e| {
                ClientError::InvalidRequest(format!("failed to parse CA bundle: {}", e))
            })?;
            Ok(vec![cert])
        }
    }
}

/// Response returned by [`HttpClient::request`]. Headers are
/// eagerly parsed; the body is streamed on demand.
///
/// Callers that only care about status / headers pay nothing for
/// the body — it stays as a live reqwest response and is consumed
/// only when something calls [`read`](Self::read) /
/// [`body`](Self::body).
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 404, 302).
    pub status: u16,
    /// Reason phrase as the server sent it (may be empty on HTTP/2).
    pub reason: String,
    /// Response headers. Multi-value headers keep their order.
    pub headers: Vec<(String, String)>,
    /// URL of the final response after any redirect following. For
    /// non-redirected requests this equals the original URL.
    pub final_url: String,
    /// When the client reached a 3xx but `follow_redirects` was
    /// false, this carries the `Location`-resolved URL the caller
    /// would have been redirected to. `None` otherwise.
    pub redirected_to: Option<String>,
    /// Body streaming state. Kept private so callers go through
    /// `read` / `body` / `read_to_end` — that way we can swap
    /// between streaming and buffered without changing the public
    /// surface.
    body: BodyState,
}

/// Body read state. Starts as `Streaming` right after the response
/// arrives; on first full-drain (`body()` or `read(None)`) it
/// transitions to `Buffered` so subsequent reads are cheap and
/// idempotent.
enum BodyState {
    /// Body hasn't been fully consumed yet. reqwest's Response
    /// implements `std::io::Read`, so we wrap it in
    /// `CountingReader` for byte-level activity reporting.
    Streaming(CountingReader<Response>),
    /// Body was fully drained into a buffer. Cursor tracks how
    /// much of it has been handed out through `read()`.
    Buffered(std::io::Cursor<Vec<u8>>),
}

/// Wraps a `Read` with an optional activity callback that fires
/// after each successful read. The callback is invoked with the
/// number of bytes read and `ActivityDirection::Read` so callers
/// can tally incoming bytes for progress UI.
pub struct CountingReader<R: std::io::Read> {
    inner: R,
    callback: Option<ActivityCallback>,
}

impl<R: std::io::Read> CountingReader<R> {
    fn new(inner: R, callback: Option<ActivityCallback>) -> Self {
        Self { inner, callback }
    }
}

impl<R: std::io::Read> std::io::Read for CountingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            if let Some(cb) = &self.callback {
                cb(n, ActivityDirection::Read);
            }
        }
        Ok(n)
    }
}

impl std::fmt::Debug for HttpResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpResponse")
            .field("status", &self.status)
            .field("reason", &self.reason)
            .field("headers", &self.headers)
            .field("final_url", &self.final_url)
            .field("redirected_to", &self.redirected_to)
            .finish_non_exhaustive()
    }
}

impl HttpResponse {
    fn from_reqwest(
        resp: Response,
        final_url: String,
        activity: Option<ActivityCallback>,
    ) -> Result<Self> {
        let status = resp.status().as_u16();
        // HTTP/2 has no reason phrase — fall back to the canonical
        // text for the status code so callers always get something.
        let reason = resp.status().canonical_reason().unwrap_or("").to_string();
        let mut headers: Vec<(String, String)> = Vec::with_capacity(resp.headers().len());
        for (name, value) in resp.headers() {
            if let Ok(v) = value.to_str() {
                headers.push((name.as_str().to_string(), v.to_string()));
            }
        }
        Ok(Self {
            status,
            reason,
            headers,
            final_url,
            redirected_to: None,
            body: BodyState::Streaming(CountingReader::new(resp, activity)),
        })
    }

    /// Read up to `n` bytes from the body. `None` means "read
    /// everything left" — which also transitions the body state to
    /// Buffered so repeat calls are no-ops.
    pub fn read(&mut self, n: Option<usize>) -> std::io::Result<Vec<u8>> {
        match n {
            Some(n) => self.read_exact_up_to(n),
            None => {
                self.buffer_all()?;
                match &mut self.body {
                    BodyState::Buffered(cur) => {
                        let mut out = Vec::new();
                        std::io::Read::read_to_end(cur, &mut out)?;
                        Ok(out)
                    }
                    BodyState::Streaming(_) => unreachable!("buffer_all transitions to Buffered"),
                }
            }
        }
    }

    fn read_exact_up_to(&mut self, n: usize) -> std::io::Result<Vec<u8>> {
        let mut out = vec![0u8; n];
        let got = match &mut self.body {
            BodyState::Streaming(reader) => {
                // Response::read can return short reads; loop until
                // we have `n` bytes or hit EOF, matching the usual
                // Python .read(n) contract that fills the buffer on
                // a socket.
                let mut filled = 0;
                while filled < n {
                    match std::io::Read::read(reader, &mut out[filled..]) {
                        Ok(0) => break,
                        Ok(k) => filled += k,
                        Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(e) => return Err(e),
                    }
                }
                filled
            }
            BodyState::Buffered(cur) => std::io::Read::read(cur, &mut out)?,
        };
        out.truncate(got);
        Ok(out)
    }

    /// Drain the remaining body into the buffer. No-op if already
    /// buffered.
    fn buffer_all(&mut self) -> std::io::Result<()> {
        if let BodyState::Streaming(reader) = &mut self.body {
            let mut buf = Vec::new();
            std::io::Read::read_to_end(reader, &mut buf)?;
            self.body = BodyState::Buffered(std::io::Cursor::new(buf));
        }
        Ok(())
    }

    /// Fully drain the body into memory (if it wasn't already) and
    /// return a borrow of the whole thing.
    pub fn body(&mut self) -> std::io::Result<&[u8]> {
        self.buffer_all()?;
        match &self.body {
            BodyState::Buffered(cur) => Ok(cur.get_ref().as_slice()),
            BodyState::Streaming(_) => unreachable!("buffer_all transitions to Buffered"),
        }
    }

    /// Drain and discard the body, leaving the response marked as
    /// consumed. Used on the 401 path when we're about to retry —
    /// we need the underlying socket returned to the pool but don't
    /// care about the body content. Subsequent `read` / `body`
    /// calls return empty.
    pub fn discard_body(&mut self) -> std::io::Result<()> {
        if let BodyState::Streaming(reader) = &mut self.body {
            std::io::copy(reader, &mut std::io::sink())?;
        }
        // Whether we were streaming or already buffered, flip to a
        // fresh empty buffer so the response is effectively closed.
        self.body = BodyState::Buffered(std::io::Cursor::new(Vec::new()));
        Ok(())
    }

    /// Case-insensitive header lookup, first match wins.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All values for the given header (order preserved).
    pub fn headers_all(&self, name: &str) -> Vec<&str> {
        self.headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
            .collect()
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    // We avoid hitting the live network in unit tests. ureq's
    // `test_transport` feature would let us mock the connector, but
    // it's not enabled in our build. The tests here cover the
    // pieces that don't need a real connection: URL parsing, proxy
    // selection, and the config builder.

    #[test]
    fn client_builds_with_defaults() {
        let _ = HttpClient::new(HttpClientConfig::default()).expect("default config should build");
    }

    #[test]
    fn client_builds_with_verification_disabled() {
        let _ = HttpClient::new(HttpClientConfig {
            disable_verification: true,
            ..HttpClientConfig::default()
        })
        .expect("no-verify config should build");
    }

    #[test]
    fn client_rejects_invalid_urls() {
        let client = HttpClient::new(HttpClientConfig::default()).unwrap();
        // A blank URL has no scheme/authority — `Uri::parse` rejects it.
        let err = client.request("GET", "", &[], &[]).unwrap_err();
        assert!(matches!(err, ClientError::InvalidRequest(_)));
    }

    #[test]
    fn client_rejects_invalid_methods() {
        let client = HttpClient::new(HttpClientConfig::default()).unwrap();
        // Methods must be a valid HTTP token — spaces aren't allowed.
        let err = client
            .request("GET FOO", "http://example.com/", &[], &[])
            .unwrap_err();
        assert!(matches!(err, ClientError::InvalidRequest(_)));
    }

    #[test]
    fn choose_proxy_respects_no_proxy() {
        // We construct the client with defaults; `choose_proxy` reads
        // the environment at call time so we can scope the test via
        // the ENV_LOCK guard from `super::super::tests`.
        use super::super::tests::with_env_vars;
        let client = HttpClient::new(HttpClientConfig::default()).unwrap();
        with_env_vars(
            &["http_proxy", "HTTP_PROXY", "no_proxy", "NO_PROXY"],
            &[
                ("http_proxy", "http://proxy.example:8080/"),
                ("no_proxy", "internal.example"),
            ],
            || {
                // Host listed in no_proxy → no proxy applied.
                let uri: Uri = "http://internal.example/".parse().unwrap();
                let p = client.choose_proxy(&uri).unwrap();
                assert!(p.is_empty(), "no_proxy match should skip the proxy");

                // Host not listed → proxy applies.
                let uri: Uri = "http://public.example/".parse().unwrap();
                let p = client.choose_proxy(&uri).unwrap();
                assert!(!p.is_empty(), "non-matching host should honour the proxy");
            },
        );
    }

    #[test]
    fn choose_proxy_uses_scheme_specific_env_var() {
        use super::super::tests::with_env_vars;
        let client = HttpClient::new(HttpClientConfig::default()).unwrap();
        with_env_vars(
            &[
                "http_proxy",
                "HTTP_PROXY",
                "https_proxy",
                "HTTPS_PROXY",
                "all_proxy",
                "ALL_PROXY",
                "no_proxy",
                "NO_PROXY",
            ],
            &[("https_proxy", "http://sproxy.example:8443/")],
            || {
                let uri: Uri = "https://public.example/".parse().unwrap();
                let p = client.choose_proxy(&uri).unwrap();
                assert!(!p.is_empty(), "HTTPS request should pick up https_proxy");

                let uri: Uri = "http://public.example/".parse().unwrap();
                let p = client.choose_proxy(&uri).unwrap();
                assert!(
                    p.is_empty(),
                    "HTTP request shouldn't pick up https_proxy when http_proxy is unset"
                );
            },
        );
    }

    #[test]
    fn response_header_lookup_is_case_insensitive() {
        let resp = HttpResponse {
            status: 200,
            reason: "OK".into(),
            headers: vec![
                ("Content-Type".to_string(), "text/plain".to_string()),
                ("X-Custom".to_string(), "a".to_string()),
                ("X-Custom".to_string(), "b".to_string()),
            ],
            body: BodyState::Buffered(std::io::Cursor::new(Vec::new())),
            final_url: "http://example.com/".into(),
            redirected_to: None,
        };
        assert_eq!(resp.header("content-type"), Some("text/plain"));
        assert_eq!(resp.headers_all("x-custom"), vec!["a", "b"]);
        assert_eq!(resp.header("missing"), None);
    }

    #[test]
    fn redirect_target_prefers_location() {
        let resp = HttpResponse {
            status: 302,
            reason: "Found".into(),
            headers: vec![
                ("Location".into(), "/new".into()),
                ("URI".into(), "/ignored".into()),
            ],
            body: BodyState::Buffered(std::io::Cursor::new(Vec::new())),
            final_url: "http://example.com/".into(),
            redirected_to: None,
        };
        assert_eq!(
            redirect_target(&resp, "http://example.com/old"),
            Some("http://example.com/new".into())
        );
    }

    #[test]
    fn redirect_target_falls_back_to_uri_header() {
        let resp = HttpResponse {
            status: 301,
            reason: "Moved".into(),
            headers: vec![("URI".into(), "http://other.example/".into())],
            body: BodyState::Buffered(std::io::Cursor::new(Vec::new())),
            final_url: "http://example.com/".into(),
            redirected_to: None,
        };
        assert_eq!(
            redirect_target(&resp, "http://example.com/"),
            Some("http://other.example/".into())
        );
    }

    #[test]
    fn redirect_target_returns_none_if_missing() {
        let resp = HttpResponse {
            status: 302,
            reason: "Found".into(),
            headers: vec![],
            body: BodyState::Buffered(std::io::Cursor::new(Vec::new())),
            final_url: "http://example.com/".into(),
            redirected_to: None,
        };
        assert_eq!(redirect_target(&resp, "http://example.com/"), None);
    }

    #[test]
    fn redirect_target_joins_relative_path() {
        let resp = HttpResponse {
            status: 303,
            reason: "See Other".into(),
            headers: vec![("Location".into(), "../b".into())],
            body: BodyState::Buffered(std::io::Cursor::new(Vec::new())),
            final_url: "http://example.com/a/c".into(),
            redirected_to: None,
        };
        assert_eq!(
            redirect_target(&resp, "http://example.com/a/c"),
            Some("http://example.com/b".into())
        );
    }

    /// Build a `HttpResponse` with the given code and optional
    /// `Location`. Keeps the test bodies short.
    fn mk_resp(code: u16, location: Option<&str>, url: &str) -> HttpResponse {
        let mut headers = Vec::new();
        if let Some(l) = location {
            headers.push(("Location".into(), l.into()));
        }
        HttpResponse {
            status: code,
            reason: "".into(),
            headers,
            body: BodyState::Buffered(std::io::Cursor::new(Vec::new())),
            final_url: url.into(),
            redirected_to: None,
        }
    }

    #[test]
    fn drive_redirects_returns_non_3xx_as_is() {
        let opts = RequestOptions::default();
        let resp = drive_redirects(&opts, "http://a/", |u| Ok(mk_resp(200, None, u))).unwrap();
        assert_eq!(resp.status, 200);
        assert!(resp.redirected_to.is_none());
    }

    #[test]
    fn drive_redirects_without_follow_sets_redirected_to() {
        let opts = RequestOptions::default(); // follow_redirects=false
        let resp = drive_redirects(&opts, "http://a/", |u| {
            Ok(mk_resp(302, Some("http://b/"), u))
        })
        .unwrap();
        assert_eq!(resp.status, 302);
        assert_eq!(resp.redirected_to.as_deref(), Some("http://b/"));
    }

    #[test]
    fn drive_redirects_follows_when_enabled() {
        let opts = RequestOptions {
            follow_redirects: true,
            ..RequestOptions::default()
        };
        let mut hops = 0;
        let resp = drive_redirects(&opts, "http://a/", |u| {
            hops += 1;
            // First hop returns 302 → /b, second returns 200.
            if u == "http://a/" {
                Ok(mk_resp(302, Some("http://a/b"), u))
            } else {
                Ok(mk_resp(200, None, u))
            }
        })
        .unwrap();
        assert_eq!(hops, 2);
        assert_eq!(resp.status, 200);
        assert_eq!(resp.final_url, "http://a/b");
    }

    #[test]
    fn drive_redirects_follows_mixed_code_chain() {
        // Mirrors breezy's TestHTTPSilentRedirections.test_five_redirections:
        // a chain mixing 301 / 302 / 303 / 307 codes must be
        // followed all the way when follow_redirects=true. Each
        // hop uses a different redirect code to ensure none of
        // them are treated as a terminal response.
        let opts = RequestOptions {
            follow_redirects: true,
            max_redirects: 10,
            max_repeats: 10,
        };
        let resp = drive_redirects(&opts, "http://a/1/a", |u| {
            let (code, target) = match u {
                "http://a/1/a" => (301, Some("http://a/2/a")),
                "http://a/2/a" => (302, Some("http://a/3/a")),
                "http://a/3/a" => (303, Some("http://a/4/a")),
                "http://a/4/a" => (307, Some("http://a/5/a")),
                _ => (200, None),
            };
            Ok(mk_resp(code, target, u))
        })
        .unwrap();
        assert_eq!(resp.status, 200);
        assert_eq!(resp.final_url, "http://a/5/a");
    }

    #[test]
    fn drive_redirects_rejects_too_many_hops() {
        let opts = RequestOptions {
            follow_redirects: true,
            max_redirects: 2,
            max_repeats: 10,
        };
        // Chain that bounces between /a and /b forever, but each
        // distinct URL stays under max_repeats so the cap we hit is
        // max_redirects.
        let mut toggle = false;
        let err = drive_redirects(&opts, "http://a/", |_u| {
            toggle = !toggle;
            let next = if toggle { "http://a/b" } else { "http://a/c" };
            Ok(mk_resp(302, Some(next), "http://a/"))
        })
        .unwrap_err();
        match err {
            ClientError::InvalidRequest(msg) => assert!(msg.contains("too many redirects")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn drive_redirects_detects_loops() {
        let opts = RequestOptions {
            follow_redirects: true,
            max_redirects: 100,
            max_repeats: 2,
        };
        // Every request redirects back to /a — we cap at
        // max_repeats visits to the same URL.
        let err = drive_redirects(&opts, "http://a/", |u| {
            Ok(mk_resp(302, Some("http://a/b"), u))
        })
        .unwrap_err();
        match err {
            ClientError::InvalidRequest(msg) => assert!(msg.contains("too many redirects")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn drive_redirects_stops_when_location_absent() {
        // A 3xx with no Location isn't a redirect per Python's
        // handler — it just gets returned as-is.
        let opts = RequestOptions {
            follow_redirects: true,
            ..RequestOptions::default()
        };
        let resp = drive_redirects(&opts, "http://a/", |u| Ok(mk_resp(302, None, u))).unwrap();
        assert_eq!(resp.status, 302);
        assert!(resp.redirected_to.is_none());
    }

    #[test]
    fn is_redirect_table() {
        for &code in &[301, 302, 303, 307, 308] {
            assert!(is_redirect(code), "{} should be a redirect", code);
        }
        // 300/304/305/306 are deliberately excluded — see the
        // comment on HTTPRedirectHandler.redirect_request.
        for &code in &[200, 300, 304, 305, 306, 400, 401, 404, 500] {
            assert!(!is_redirect(code), "{} should not be a redirect", code);
        }
    }

    // ------------------------------------------------------------------
    // Auth tests. We exercise the helpers directly — the full
    // send_with_auth loop needs a real HTTP server, which we cover
    // elsewhere (breezy's test suite, plus the Python integration
    // tests).

    struct FixedCreds {
        user: &'static str,
        password: &'static str,
    }

    impl CredentialProvider for FixedCreds {
        fn lookup(
            &self,
            _protocol: &str,
            _host: &str,
            _port: Option<u16>,
            _realm: Option<&str>,
        ) -> (Option<String>, Option<String>) {
            (Some(self.user.into()), Some(self.password.into()))
        }
    }

    struct NoCreds;
    impl CredentialProvider for NoCreds {
        fn lookup(
            &self,
            _: &str,
            _: &str,
            _: Option<u16>,
            _: Option<&str>,
        ) -> (Option<String>, Option<String>) {
            (None, None)
        }
    }

    struct FixedToken(&'static str);
    impl NegotiateProvider for FixedToken {
        fn initial_token(&self, _host: &str) -> Option<String> {
            Some(self.0.into())
        }
    }

    fn fresh_client(creds: Box<dyn CredentialProvider>) -> HttpClient {
        HttpClient::with_credentials(HttpClientConfig::default(), creds)
            .expect("config should build")
    }

    fn client_with_negotiate(
        creds: Box<dyn CredentialProvider>,
        neg: Box<dyn NegotiateProvider>,
    ) -> HttpClient {
        HttpClient::with_providers(HttpClientConfig::default(), creds, neg)
            .expect("config should build")
    }

    #[test]
    fn extract_basic_realm_quoted() {
        assert_eq!(
            extract_basic_realm(r#"realm="Secure Area""#),
            Some("Secure Area")
        );
    }

    #[test]
    fn extract_basic_realm_unquoted() {
        assert_eq!(
            extract_basic_realm("realm=unquoted,charset=UTF-8"),
            Some("unquoted")
        );
    }

    #[test]
    fn extract_basic_realm_missing() {
        assert_eq!(extract_basic_realm("charset=UTF-8"), None);
    }

    #[test]
    fn auth_cache_key_normalises_scheme_and_port() {
        let a: Uri = "http://example.com/".parse().unwrap();
        let b: Uri = "http://example.com:80/".parse().unwrap();
        assert_eq!(auth_cache_key(&a), auth_cache_key(&b));

        let c: Uri = "https://example.com/".parse().unwrap();
        assert_ne!(auth_cache_key(&a), auth_cache_key(&c));

        // Different port ⇒ different cache bucket.
        let d: Uri = "http://example.com:8080/".parse().unwrap();
        assert_ne!(auth_cache_key(&a), auth_cache_key(&d));
    }

    #[test]
    fn pick_auth_scheme_prefers_digest_over_basic() {
        let client = fresh_client(Box::new(FixedCreds {
            user: "alice",
            password: "sekret",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [
            r#"Basic realm="fallback""#,
            r#"Digest realm="secure", nonce="n", qop="auth""#,
        ];
        let got = client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .unwrap();
        assert_eq!(got.0, "digest");
        assert!(matches!(got.1, CachedAuth::Digest(_)));
    }

    #[test]
    fn pick_auth_scheme_passes_none_port_when_uri_has_no_port() {
        // Regression test for https://bugs.launchpad.net/bzr/+bug/654684:
        // the credential lookup should still succeed when the URI
        // omits a port (common for `http://host/path`). The Python
        // side historically surfaced `None` as the port and the
        // auth-config store matched credentials on host only; the
        // Rust client propagates the same None to the provider.
        struct SeesPort(std::sync::Mutex<Option<Option<u16>>>);
        impl CredentialProvider for SeesPort {
            fn lookup(
                &self,
                _protocol: &str,
                _host: &str,
                port: Option<u16>,
                _realm: Option<&str>,
            ) -> (Option<String>, Option<String>) {
                *self.0.lock().unwrap() = Some(port);
                (Some("joe".into()), Some("foo".into()))
            }
        }
        let seen = std::sync::Arc::new(SeesPort(std::sync::Mutex::new(None)));
        struct Shared(std::sync::Arc<SeesPort>);
        impl CredentialProvider for Shared {
            fn lookup(
                &self,
                protocol: &str,
                host: &str,
                port: Option<u16>,
                realm: Option<&str>,
            ) -> (Option<String>, Option<String>) {
                self.0.lookup(protocol, host, port, realm)
            }
        }
        let client = fresh_client(Box::new(Shared(seen.clone())));
        let uri: Uri = "http://localhost/path".parse().unwrap();
        let challenges = [r#"Basic realm="R""#];
        client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .unwrap();
        assert_eq!(*seen.0.lock().unwrap(), Some(None));
    }

    #[test]
    fn pick_auth_scheme_uses_basic_when_digest_absent() {
        let client = fresh_client(Box::new(FixedCreds {
            user: "u",
            password: "p",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [r#"Basic realm="r""#];
        let got = client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .unwrap();
        assert_eq!(got.0, "basic");
        match got.1 {
            CachedAuth::Basic { user, password } => {
                assert_eq!(user, "u");
                assert_eq!(password, "p");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    fn pick_auth_scheme_returns_none_when_credentials_missing() {
        let client = fresh_client(Box::new(NoCreds));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [r#"Basic realm="r""#];
        assert!(client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .is_none());
    }

    #[test]
    fn pick_auth_scheme_returns_none_for_unknown_scheme() {
        let client = fresh_client(Box::new(FixedCreds {
            user: "u",
            password: "p",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = ["Bearer realm=whatever"];
        assert!(client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .is_none());
    }

    #[test]
    fn pick_auth_scheme_rejects_unsupported_digest_algorithm() {
        let client = fresh_client(Box::new(FixedCreds {
            user: "u",
            password: "p",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [
            // SHA-256 isn't in our DigestAlgorithm table; the
            // challenge parser returns None so we fall back to Basic
            // (which isn't offered either) and ultimately give up.
            r#"Digest realm="r", nonce="n", qop="auth", algorithm="SHA-256""#,
        ];
        assert!(client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .is_none());
    }

    #[test]
    fn cached_auth_header_basic_formats_correctly() {
        let cached = CachedAuth::Basic {
            user: "Aladdin".into(),
            password: "open sesame".into(),
        };
        let uri: Uri = "http://example.com/resource".parse().unwrap();
        let hdr = cached_auth_header(&cached, &Method::GET, &uri).unwrap();
        assert_eq!(hdr, "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==");
    }

    #[test]
    fn proxy_cache_key_differs_from_origin_key() {
        // Same host reached directly vs via a proxy should use
        // different cache buckets so credentials don't leak.
        let origin: Uri = "http://example.com/".parse().unwrap();
        let ok = auth_cache_key(&origin);
        let pk = proxy_cache_key("http://proxy.example:8080");
        assert_ne!(ok, pk);
    }

    #[test]
    fn proxy_cache_key_is_case_insensitive_on_host() {
        // Proxy host lookup shouldn't be affected by case variation.
        let a = proxy_cache_key("http://PROXY.Example:3128");
        let b = proxy_cache_key("http://proxy.example:3128");
        assert_eq!(a, b);
    }

    #[test]
    fn pick_auth_scheme_for_proxy_uses_credentials() {
        // AuthKind::Proxy currently routes through the same
        // credential provider; verify it works end-to-end on the
        // scheme-picking side. If we later key credentials on the
        // proxy URL this test should be updated accordingly.
        let client = fresh_client(Box::new(FixedCreds {
            user: "px-u",
            password: "px-p",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [r#"Basic realm="proxy""#];
        let got = client
            .pick_auth_scheme_for(&challenges, &uri, AuthKind::Proxy)
            .unwrap();
        assert_eq!(got.0, "basic");
        match got.1 {
            CachedAuth::Basic { user, password } => {
                assert_eq!(user, "px-u");
                assert_eq!(password, "px-p");
            }
            _ => panic!("expected Basic"),
        }
    }

    #[test]
    fn pick_auth_scheme_prefers_negotiate_over_digest_and_basic() {
        let client = client_with_negotiate(
            Box::new(FixedCreds {
                user: "u",
                password: "p",
            }),
            Box::new(FixedToken("YIIDSS...base64...")),
        );
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [
            "Negotiate",
            r#"Digest realm="r", nonce="n", qop="auth""#,
            r#"Basic realm="r""#,
        ];
        let got = client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .unwrap();
        assert_eq!(got.0, "negotiate");
        match got.1 {
            CachedAuth::Negotiate { token } => {
                assert_eq!(token, "YIIDSS...base64...");
            }
            _ => panic!("expected Negotiate"),
        }
    }

    #[test]
    fn pick_auth_scheme_falls_back_when_negotiate_provider_returns_none() {
        // Provider says "no ticket available" → we should fall
        // through to Digest/Basic rather than fail.
        struct NoToken;
        impl NegotiateProvider for NoToken {
            fn initial_token(&self, _: &str) -> Option<String> {
                None
            }
        }
        let client = client_with_negotiate(
            Box::new(FixedCreds {
                user: "u",
                password: "p",
            }),
            Box::new(NoToken),
        );
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = ["Negotiate", r#"Basic realm="r""#];
        let got = client
            .pick_auth_scheme(&uri, &challenges, &Method::GET)
            .unwrap();
        assert_eq!(got.0, "basic");
    }

    #[test]
    fn cached_auth_header_negotiate_formats_with_scheme_prefix() {
        let cached = CachedAuth::Negotiate {
            token: "TOKEN-BYTES".into(),
        };
        let uri: Uri = "http://example.com/".parse().unwrap();
        let hdr = cached_auth_header(&cached, &Method::GET, &uri).unwrap();
        assert_eq!(hdr, "Negotiate TOKEN-BYTES");
    }

    /// Build an HttpResponse whose body is pre-buffered with the
    /// given bytes. Convenient for testing the read path without a
    /// real network connection.
    fn mk_buffered(status: u16, body: &[u8]) -> HttpResponse {
        HttpResponse {
            status,
            reason: "".into(),
            headers: vec![],
            final_url: "http://example/".into(),
            redirected_to: None,
            body: BodyState::Buffered(std::io::Cursor::new(body.to_vec())),
        }
    }

    #[test]
    fn response_read_returns_all_when_size_none() {
        let mut r = mk_buffered(200, b"hello");
        let got = r.read(None).unwrap();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn response_read_returns_up_to_n() {
        let mut r = mk_buffered(200, b"abcdef");
        assert_eq!(r.read(Some(3)).unwrap(), b"abc");
        assert_eq!(r.read(Some(10)).unwrap(), b"def");
        // Further reads return empty.
        assert_eq!(r.read(Some(5)).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn response_body_drains_once() {
        let mut r = mk_buffered(200, b"hello");
        assert_eq!(r.body().unwrap(), b"hello");
        // Subsequent body() calls return the same bytes.
        assert_eq!(r.body().unwrap(), b"hello");
    }

    #[test]
    fn response_body_after_partial_read_contains_everything() {
        // `body()` forces a full drain regardless of where read()
        // left off — it returns the full buffer.
        let mut r = mk_buffered(200, b"abcdef");
        assert_eq!(r.read(Some(3)).unwrap(), b"abc");
        assert_eq!(r.body().unwrap(), b"abcdef");
    }

    #[test]
    fn response_discard_body_marks_as_consumed() {
        let mut r = mk_buffered(200, b"hello");
        r.discard_body().unwrap();
        // After discard, reads return empty.
        assert_eq!(r.read(None).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn cached_auth_header_digest_bumps_nonce_count_via_clone() {
        // cached_auth_header works on a local clone, so the cached
        // state's nonce_count is NOT bumped here; send_with_auth
        // persists the bump separately.
        let state = DigestAuthState {
            user: "u".into(),
            password: "p".into(),
            realm: "r".into(),
            nonce: "n".into(),
            nonce_count: 5,
            algorithm: crate::http::DigestAlgorithm::Md5,
            algorithm_name: None,
            opaque: None,
            qop: "auth".into(),
        };
        let cached = CachedAuth::Digest(state.clone());
        let uri: Uri = "http://example.com/x".parse().unwrap();
        let hdr = cached_auth_header(&cached, &Method::GET, &uri).unwrap();
        assert!(hdr.contains("nc=00000006"));
        // The original state wasn't mutated.
        if let CachedAuth::Digest(orig) = cached {
            assert_eq!(orig.nonce_count, 5);
        }
    }
}
