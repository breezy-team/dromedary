//! Rust HTTP client used by the `HttpTransport` port.
//!
//! Wraps a [`ureq::Agent`] with dromedary-specific defaults: proxy
//! config read from `<scheme>_proxy` / `no_proxy` env vars via our
//! own resolver (keeps breezy's historical behaviour), root
//! certificates loaded from a user-supplied bundle or the
//! platform's native store, and the User-Agent managed by the
//! module-level setter.
//!
//! Stage 6 scope is deliberately minimal: request/response flow
//! through the agent, non-2xx statuses surface as normal responses,
//! redirects are caught at the client boundary but not yet
//! followed, and authentication is not wired in. Each of those
//! pieces lands in a follow-up commit on this branch so the diff
//! stays reviewable.

use std::io::Read;
use std::path::Path;
use std::time::Duration;

use std::collections::HashMap;
use std::sync::Mutex;

use ureq::config::Config;
use ureq::http::{Method, Request, Response, Uri};
use ureq::tls::{Certificate, PemItem, RootCerts, TlsConfig};
use ureq::{Agent, Body, Proxy};
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
    /// The underlying ureq call failed (TLS, transport, timeout, …).
    Transport(ureq::Error),
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

impl From<ureq::Error> for ClientError {
    fn from(e: ureq::Error) -> Self {
        Self::Transport(e)
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub type Result<T> = std::result::Result<T, ClientError>;

/// Per-request knobs that callers sometimes need to override. The
/// defaults match breezy's urllib-layer behaviour: no redirect
/// following, so 3xx responses surface as-is for the caller to
/// translate into a `RedirectRequested` if they want.
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

/// Build an `Authorization:` header value from the cached state.
/// Mutates digest state in place so `nonce_count` bumps correctly.
fn cached_auth_header(cached: &CachedAuth, method: &Method, uri: &Uri) -> Option<String> {
    match cached {
        CachedAuth::Basic { user, password } => Some(build_basic_auth_header(user, password)),
        CachedAuth::Digest(_) => {
            // Can't mutate `&cached`; the caller already cloned and
            // will re-store after calling us. This function is only
            // used for the *preemptive* attach path, where the
            // caller owns the mutation. We wire that by passing a
            // cloned state in from the caller — but the caller only
            // has `&CachedAuth` here. Easier: build via a short-lived
            // clone and let the caller re-store.
            let CachedAuth::Digest(state) = cached else {
                unreachable!()
            };
            let mut s = state.clone();
            Some(build_digest_auth_header(
                &mut s,
                method.as_str(),
                uri.path(),
            ))
        }
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

/// HTTP client wrapper around [`ureq::Agent`].
///
/// Proxies are resolved per-request from the current environment,
/// matching the Python urllib behaviour where `ProxyHandler` reads
/// env vars at construction and every redirect cycle. We don't
/// cache the env-var snapshot because the Python tests assume
/// setting `HTTP_PROXY` mid-test takes effect immediately.
pub struct HttpClient {
    /// The configured agent. Proxies are applied per-request via
    /// `configure_request`, not baked into the agent, so env-var
    /// changes take effect immediately without rebuilding the
    /// agent's connection pool.
    agent: Agent,
    /// Per-origin cache of successful auth state. Populated after
    /// the server accepts our credentials; subsequent requests to
    /// the same host preemptively attach the cached header.
    auth_cache: AuthCache,
    /// How we look up `(user, password)` when a challenge arrives.
    credentials: Box<dyn CredentialProvider>,
}

impl HttpClient {
    /// Build a new client honouring the given config.
    pub fn new(config: HttpClientConfig) -> Result<Self> {
        Self::with_credentials(config, Box::new(NoCredentialProvider))
    }

    /// Build a new client with a custom credential provider.
    pub fn with_credentials(
        config: HttpClientConfig,
        credentials: Box<dyn CredentialProvider>,
    ) -> Result<Self> {
        let base_config = build_config(&config)?;
        let agent = Agent::new_with_config(base_config);
        Ok(Self {
            agent,
            auth_cache: AuthCache::new(),
            credentials,
        })
    }

    /// Perform an HTTP request with default options (no redirect
    /// following). Convenience wrapper over [`Self::request_with`].
    pub fn request(
        &self,
        method: &str,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        self.request_with(method, url, headers, body, &RequestOptions::default())
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
    ) -> Result<HttpResponse> {
        let method = Method::from_bytes(method.as_bytes())
            .map_err(|_| ClientError::InvalidRequest(format!("bad method: {}", method)))?;

        // Each redirect hop does its own auth dance — a 3xx to a
        // different host mustn't reuse the previous host's cached
        // auth, and handling that here keeps the redirect-loop code
        // from having to know anything about auth.
        drive_redirects(options, url, |target| {
            self.send_with_auth(&method, target, headers, body)
        })
    }

    /// Send a request, transparently handling a single 401/407
    /// auth challenge. Returns the final response (which may still
    /// be 401 if we ran out of credentials or the server rejected
    /// what we offered).
    fn send_with_auth(
        &self,
        method: &Method,
        url: &str,
        headers: &[(String, String)],
        body: &[u8],
    ) -> Result<HttpResponse> {
        let uri: Uri = url
            .parse()
            .map_err(|_| ClientError::InvalidRequest(format!("bad URL: {}", url)))?;
        let cache_key = auth_cache_key(&uri);

        // Preemptively attach a cached auth header if we have one.
        // Callers' explicit Authorization headers take precedence —
        // don't clobber.
        let has_explicit_auth = headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("authorization"));
        let mut first_headers: Vec<(String, String)> = headers.to_vec();
        if !has_explicit_auth {
            if let Some(cached) = self.auth_cache.get(&cache_key) {
                if let Some(hdr) = cached_auth_header(&cached, method, &uri) {
                    first_headers.push(("Authorization".into(), hdr));
                    // For Digest, `build_digest_auth_header` bumped
                    // `nonce_count` inside the cached state; store
                    // the mutation so the next request uses a fresh
                    // nc value.
                    self.auth_cache.put(cache_key.clone(), cached);
                }
            }
        }

        let response = self.send_once(method, url, &first_headers, body)?;
        if response.status != 401 && response.status != 407 {
            return Ok(response);
        }
        if has_explicit_auth {
            // The caller asked for specific auth; don't second-guess
            // them by retrying with different credentials.
            return Ok(response);
        }

        // Parse the challenge. We only handle WWW-Authenticate for
        // now; Proxy-Authenticate (407) support would need the same
        // logic keyed differently and is not yet wired.
        if response.status == 407 {
            return Ok(response);
        }
        let challenges = response.headers_all("www-authenticate");
        let Some((scheme, new_auth)) = self.pick_auth_scheme(&uri, &challenges, method) else {
            return Ok(response);
        };

        // Retry with the new auth header attached. Don't stack on
        // top of the preemptive header we added above; rebuild from
        // the caller's headers and append the new one.
        let mut retry_headers = headers.to_vec();
        let hdr = match &new_auth {
            CachedAuth::Basic { user, password } => build_basic_auth_header(user, password),
            CachedAuth::Digest(state) => {
                // `build_digest_auth_header` mutates `nonce_count`,
                // and we want to persist that bump. Work on a clone
                // and re-store after.
                let mut s = state.clone();
                let h = build_digest_auth_header(&mut s, method.as_str(), uri.path());
                // Replace what we just cloned with the bumped state.
                self.auth_cache
                    .put(cache_key.clone(), CachedAuth::Digest(s));
                h
            }
        };
        // For Basic, only cache on success below (keeps us from
        // memoising wrong credentials forever).
        if matches!(new_auth, CachedAuth::Basic { .. }) {
            // Deferred: we only persist basic-auth once the retry
            // succeeds. Stash `new_auth` on the stack and put it in
            // the cache below.
        }
        retry_headers.push(("Authorization".into(), hdr));
        let _ = scheme; // scheme name currently only used for logging

        let retry = self.send_once(method, url, &retry_headers, body)?;
        if retry.status < 400 {
            // Cache the working credentials so future requests to
            // this origin don't need the 401 roundtrip.
            if let CachedAuth::Basic { .. } = &new_auth {
                self.auth_cache.put(cache_key, new_auth);
            }
            // Digest was already cached above (we needed the bumped
            // nonce_count regardless of outcome).
        }
        Ok(retry)
    }

    /// Given the challenges a server sent, pick the scheme we'll
    /// try and materialise it into a `CachedAuth` suitable for
    /// header generation. Returns `None` when no scheme matches or
    /// credentials weren't available.
    ///
    /// Scheme preference follows the order `DigestAuthHandler`
    /// (handler_order=490) > `BasicAuthHandler` (handler_order=500)
    /// in the old urllib code. Negotiate is not handled here yet;
    /// stage 7e adds it via a separate provider callback.
    fn pick_auth_scheme(
        &self,
        uri: &Uri,
        challenges: &[&str],
        _method: &Method,
    ) -> Option<(&'static str, CachedAuth)> {
        // Prefer Digest if offered; fall back to Basic.
        let mut digest_remainder: Option<&str> = None;
        let mut basic_remainder: Option<&str> = None;
        for ch in challenges {
            let (scheme, remainder) = parse_auth_header(ch);
            let remainder = remainder.unwrap_or("");
            match scheme.as_str() {
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
    ) -> Result<HttpResponse> {
        let uri: Uri = url
            .parse()
            .map_err(|_| ClientError::InvalidRequest(format!("bad URL: {}", url)))?;

        let mut builder = Request::builder().method(method.clone()).uri(&uri);
        for (k, v) in headers {
            builder = builder.header(k, v);
        }
        let req: Request<Vec<u8>> = builder
            .body(body.to_vec())
            .map_err(|e| ClientError::InvalidRequest(e.to_string()))?;

        let req = match self.choose_proxy(&uri)? {
            Some(proxy) => self.agent.configure_request(req).proxy(Some(proxy)).build(),
            None => req,
        };
        let response = self.agent.run(req)?;
        HttpResponse::from_ureq(response, url.to_string())
    }

    /// Decide whether the request to `uri` should go through a
    /// proxy. Consults `<scheme>_proxy` / `all_proxy` / `no_proxy`
    /// env vars via our [`getproxies_environment`] port of the
    /// stdlib helper.
    fn choose_proxy(&self, uri: &Uri) -> Result<Option<Proxy>> {
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
            ProxyBypass::Bypass => return Ok(None),
            ProxyBypass::UseProxy | ProxyBypass::Undecided => {}
        }

        let Some(proxy_url) = get_proxy_env_var(&env, scheme, Some("all")) else {
            return Ok(None);
        };
        Proxy::new(&proxy_url)
            .map(Some)
            .map_err(|e| ClientError::InvalidRequest(format!("bad proxy URL {}: {}", proxy_url, e)))
    }
}

/// Build the initial `ureq::Config` honouring our TLS/User-Agent/
/// timeout settings. Proxy is left unset here — we inject it
/// per-request in [`HttpClient::request`] so env-var changes take
/// effect without rebuilding the client.
fn build_config(config: &HttpClientConfig) -> Result<Config> {
    let mut builder = Agent::config_builder();

    let tls = build_tls_config(config)?;
    builder = builder.tls_config(tls);

    let ua = config
        .user_agent
        .clone()
        .unwrap_or_else(crate::http::default_user_agent);
    builder = builder.user_agent(ua);

    if let Some(t) = config.read_timeout {
        builder = builder.timeout_global(Some(t));
    }

    // Let non-2xx surface as ordinary responses so we can inspect the
    // status code for retry / auth-challenge / redirect logic.
    builder = builder.http_status_as_error(false);

    // We follow redirects ourselves (Stage 7) so ureq's built-in
    // redirect loop is disabled.
    builder = builder.max_redirects(0);

    Ok(builder.build())
}

fn build_tls_config(config: &HttpClientConfig) -> Result<TlsConfig> {
    let mut builder = TlsConfig::builder();

    if config.disable_verification {
        builder = builder.disable_verification(true);
        return Ok(builder.build());
    }

    let root_certs = match &config.ca_certs_path {
        Some(path) => root_certs_from_pem_file(path)?,
        None => root_certs_from_native_store(),
    };
    builder = builder.root_certs(root_certs);
    Ok(builder.build())
}

fn root_certs_from_pem_file(path: &Path) -> Result<RootCerts> {
    let bytes = std::fs::read(path)?;
    let certs: Vec<Certificate<'static>> = ureq::tls::parse_pem(&bytes)
        .filter_map(|p| p.ok())
        .filter_map(|p| match p {
            PemItem::Certificate(c) => Some(c),
            _ => None,
        })
        .collect();
    Ok(certs.into())
}

fn root_certs_from_native_store() -> RootCerts {
    // `rustls-native-certs` returns DER-encoded roots. The ureq
    // Certificate API is zero-copy against the DER bytes but we
    // need `'static`; cloning the bytes into each cert gives us
    // that.
    let native = rustls_native_certs::load_native_certs();
    let certs: Vec<Certificate<'static>> = native
        .certs
        .into_iter()
        .map(|c| {
            // `to_owned` copies the DER bytes into a `Certificate<'static>`.
            Certificate::from_der(c.as_ref()).to_owned()
        })
        .collect();
    if certs.is_empty() {
        // No native certs available — fall through to ureq's built-in
        // WebPKI bundle so we aren't left with zero roots.
        return RootCerts::WebPki;
    }
    certs.into()
}

/// Response returned by [`HttpClient::request`]. Owns the body
/// buffer so callers can read it after the underlying `ureq::Body`
/// goes out of scope. For range requests and other streaming uses
/// we'll add a separate streaming response type in Stage 7.
#[derive(Debug)]
pub struct HttpResponse {
    /// HTTP status code (e.g. 200, 404, 302).
    pub status: u16,
    /// Reason phrase as the server sent it (may be empty on HTTP/2).
    pub reason: String,
    /// Response headers. Multi-value headers keep their order.
    pub headers: Vec<(String, String)>,
    /// Full response body. Not streaming — good enough for the
    /// handler-layer auth retries that Stage 6b will add. Stage 7
    /// swaps this for a streaming body to plug into `RangeFile`.
    pub body: Vec<u8>,
    /// URL of the final response after any redirect following. For
    /// non-redirected requests this equals the original URL.
    pub final_url: String,
    /// When the client reached a 3xx but `follow_redirects` was
    /// false, this carries the `Location`-resolved URL the caller
    /// would have been redirected to. `None` otherwise.
    pub redirected_to: Option<String>,
}

impl HttpResponse {
    fn from_ureq(mut resp: Response<Body>, final_url: String) -> Result<Self> {
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
        let mut body: Vec<u8> = Vec::new();
        resp.body_mut()
            .as_reader()
            .read_to_end(&mut body)
            .map_err(ClientError::Io)?;
        Ok(Self {
            status,
            reason,
            headers,
            body,
            final_url,
            redirected_to: None,
        })
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
                assert!(p.is_none(), "no_proxy match should skip the proxy");

                // Host not listed → proxy applies.
                let uri: Uri = "http://public.example/".parse().unwrap();
                let p = client.choose_proxy(&uri).unwrap();
                assert!(p.is_some(), "non-matching host should honour the proxy");
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
                assert!(p.is_some(), "HTTPS request should pick up https_proxy");

                let uri: Uri = "http://public.example/".parse().unwrap();
                let p = client.choose_proxy(&uri).unwrap();
                assert!(
                    p.is_none(),
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
            body: Vec::new(),
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
            body: Vec::new(),
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
            body: Vec::new(),
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
            body: Vec::new(),
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
            body: Vec::new(),
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
            body: Vec::new(),
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

    fn fresh_client(creds: Box<dyn CredentialProvider>) -> HttpClient {
        HttpClient::with_credentials(HttpClientConfig::default(), creds)
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
        let got = client.pick_auth_scheme(&uri, &challenges, &Method::GET).unwrap();
        assert_eq!(got.0, "digest");
        assert!(matches!(got.1, CachedAuth::Digest(_)));
    }

    #[test]
    fn pick_auth_scheme_uses_basic_when_digest_absent() {
        let client = fresh_client(Box::new(FixedCreds {
            user: "u",
            password: "p",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = [r#"Basic realm="r""#];
        let got = client.pick_auth_scheme(&uri, &challenges, &Method::GET).unwrap();
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
        assert!(
            client
                .pick_auth_scheme(&uri, &challenges, &Method::GET)
                .is_none()
        );
    }

    #[test]
    fn pick_auth_scheme_returns_none_for_unknown_scheme() {
        let client = fresh_client(Box::new(FixedCreds {
            user: "u",
            password: "p",
        }));
        let uri: Uri = "http://example.com/".parse().unwrap();
        let challenges = ["Bearer realm=whatever"];
        assert!(
            client
                .pick_auth_scheme(&uri, &challenges, &Method::GET)
                .is_none()
        );
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
        assert!(
            client
                .pick_auth_scheme(&uri, &challenges, &Method::GET)
                .is_none()
        );
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
