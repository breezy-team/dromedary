//! HTTP support helpers.
//!
//! These are environment/filesystem lookups that don't need any HTTP client
//! to be wired in: locating the CA certificate bundle and the User-Agent
//! default. The Python wrapper in `dromedary.http` delegates to these.

pub mod response;
pub use response::{handle_response, InFile, RangeFile, ResponseError, ResponseFile, ResponseKind};

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use lazy_static::lazy_static;

/// Known locations for CA certificate bundles on common Unix platforms.
///
/// The first existing path wins. Note for packagers: if there is no package
/// providing certs for your platform, the curl project produces
/// <http://curl.haxx.se/ca/cacert.pem> weekly.
pub const SSL_CA_CERTS_KNOWN_LOCATIONS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt",     // Ubuntu/Debian/Gentoo
    "/etc/pki/tls/certs/ca-bundle.crt",       // Fedora/CentOS/RH
    "/etc/ssl/ca-bundle.pem",                 // OpenSUSE
    "/etc/ssl/cert.pem",                      // OpenSUSE
    "/usr/local/share/certs/ca-root-nss.crt", // FreeBSD
    "/etc/openssl/certs/ca-certificates.crt", // Solaris (unchecked)
];

lazy_static! {
    static ref CA_PATH_CACHE: Mutex<Option<String>> = Mutex::new(None);
    /// Current User-Agent prefix used by the HTTP client. Starts as
    /// `"Dromedary/<version>"`; breezy overrides this via
    /// [`set_user_agent`] at module load.
    static ref USER_AGENT_PREFIX: Mutex<String> =
        Mutex::new(format!("Dromedary/{}", env!("CARGO_PKG_VERSION")));
    /// Path to the PEM bundle we materialised from the platform's
    /// native certificate store. Cached for the process lifetime so
    /// repeated calls don't re-read the keychain / registry.
    static ref NATIVE_CA_BUNDLE_PATH: Mutex<Option<String>> = Mutex::new(None);
}

/// Replace the current User-Agent prefix.
pub fn set_user_agent(prefix: String) {
    *USER_AGENT_PREFIX.lock().unwrap() = prefix;
}

/// Return the current User-Agent prefix.
pub fn default_user_agent() -> String {
    USER_AGENT_PREFIX.lock().unwrap().clone()
}

/// Certificate verification requirement. The integer representation
/// matches the Python `ssl.CERT_*` constants so the Rust and Python
/// sides can interchange values without a translation table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CertReqs {
    /// `ssl.CERT_NONE` — no verification.
    None = 0,
    /// `ssl.CERT_REQUIRED` — verify the peer certificate.
    Required = 2,
}

impl CertReqs {
    pub fn to_int(self) -> u8 {
        self as u8
    }
}

/// Path to a PEM bundle materialised from the platform's native
/// certificate store (macOS keychain, Windows cert store, or the
/// Linux `ca-certificates` bundle by way of `SSL_CERT_FILE` /
/// `SSL_CERT_DIR` env vars).
///
/// Returns `None` if nothing could be loaded — that includes the case
/// where the platform has no native store at all, or where loading
/// failed for any reason (we treat failure as "no certs" rather than
/// poisoning the Python side with an exception).
///
/// The file is written once per process and kept on disk so Python's
/// `ssl.load_verify_locations(cafile=...)` has a stable path to
/// reference. Subsequent calls return the cached path.
///
/// Tests may invalidate the cache via [`clear_native_ca_bundle_cache`].
pub fn native_ca_bundle_path() -> Option<String> {
    if let Some(cached) = NATIVE_CA_BUNDLE_PATH.lock().unwrap().as_ref() {
        return Some(cached.clone());
    }

    let certs = match rustls_native_certs::load_native_certs() {
        result if result.errors.is_empty() && !result.certs.is_empty() => result.certs,
        _ => return None,
    };

    // Serialise to PEM. Writing "-----BEGIN CERTIFICATE-----" wrappers
    // around base64-encoded DER by hand keeps us off the `pem` crate.
    let mut pem = String::with_capacity(certs.len() * 2000);
    for der in &certs {
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD.encode(der);
        pem.push_str("-----BEGIN CERTIFICATE-----\n");
        // PEM wraps at 64 chars.
        for chunk in encoded.as_bytes().chunks(64) {
            pem.push_str(std::str::from_utf8(chunk).unwrap());
            pem.push('\n');
        }
        pem.push_str("-----END CERTIFICATE-----\n");
    }

    let mut tmp = match tempfile::Builder::new()
        .prefix("dromedary-native-ca-")
        .suffix(".pem")
        .tempfile()
    {
        Ok(t) => t,
        Err(_) => return None,
    };
    use std::io::Write;
    if tmp.write_all(pem.as_bytes()).is_err() {
        return None;
    }
    let path = match tmp.into_temp_path().keep() {
        Ok(p) => p,
        Err(_) => return None,
    };
    let path_str = path.to_string_lossy().into_owned();
    *NATIVE_CA_BUNDLE_PATH.lock().unwrap() = Some(path_str.clone());
    Some(path_str)
}

/// Invalidate the cached native CA bundle path (for tests).
pub fn clear_native_ca_bundle_cache() {
    *NATIVE_CA_BUNDLE_PATH.lock().unwrap() = None;
}

/// Platform-default certificate verification requirement.
///
/// Windows and macOS historically had no native access to root
/// certificates from Python's `ssl`, so Breezy chose `CERT_NONE`
/// there to avoid false negatives. Everywhere else `CERT_REQUIRED`
/// is the safe default. With the native-certs branch in
/// [`default_ca_certs`] we could tighten this later, but for now we
/// preserve the historical behaviour.
pub fn default_cert_reqs() -> CertReqs {
    if cfg!(any(target_os = "windows", target_os = "macos")) {
        CertReqs::None
    } else {
        CertReqs::Required
    }
}

/// Clear the cached CA bundle path.
///
/// Primarily useful in tests that mutate `CURL_CA_BUNDLE`.
pub fn clear_ca_path_cache() {
    *CA_PATH_CACHE.lock().unwrap() = None;
}

/// Locate the CA bundle to use for SSL connections.
///
/// Mirrors the behaviour of curl's `CURL_CA_BUNDLE` lookup:
///
/// 1. If `CURL_CA_BUNDLE` is set, use it.
/// 2. On Windows, search the application directory and `PATH` entries for
///    `curl-ca-bundle.crt` (the current working directory is deliberately
///    excluded).
/// 3. Otherwise return an empty string.
///
/// When `use_cache` is true the result is memoised in a process-global
/// cache; subsequent calls return the cached value regardless of environment
/// changes. Call [`clear_ca_path_cache`] to invalidate it.
pub fn get_ca_path(use_cache: bool) -> String {
    if use_cache {
        if let Some(cached) = CA_PATH_CACHE.lock().unwrap().as_ref() {
            return cached.clone();
        }
    }

    let mut path = std::env::var("CURL_CA_BUNDLE").unwrap_or_default();

    if path.is_empty() && cfg!(target_os = "windows") {
        path = find_windows_ca_bundle().unwrap_or_default();
    }

    if !path.is_empty() {
        log::debug!("using CA bundle: {:?}", path);
    }

    if use_cache {
        *CA_PATH_CACHE.lock().unwrap() = Some(path.clone());
    }

    path
}

/// Search the application directory and `PATH` for `curl-ca-bundle.crt`.
///
/// Kept separate from [`get_ca_path`] so it can be unit-tested without an
/// actual Windows host. The cwd is intentionally not searched — see the
/// comments in the original Python implementation.
fn find_windows_ca_bundle() -> Option<String> {
    let mut dirs: Vec<PathBuf> = Vec::new();

    if let Some(argv0) = std::env::args_os().next() {
        if let Ok(canon) = Path::new(&argv0).canonicalize() {
            if let Some(parent) = canon.parent() {
                dirs.push(parent.to_path_buf());
            }
        }
    }

    if let Some(paths) = std::env::var_os("PATH") {
        for entry in std::env::split_paths(&paths) {
            let s = entry.as_os_str();
            if s.is_empty() || s == std::ffi::OsStr::new(".") {
                continue;
            }
            dirs.push(entry);
        }
    }

    for d in dirs {
        let candidate = d.join("curl-ca-bundle.crt");
        if candidate.is_file() {
            return Some(candidate.to_string_lossy().into_owned());
        }
    }
    None
}

/// Return the default CA certificates path for the running platform.
///
/// Precedence:
///
/// 1. On Linux, scan [`SSL_CA_CERTS_KNOWN_LOCATIONS`] first — the
///    system bundle there is what most TLS libraries read anyway, and
///    keeping it means we pass the *real* path (not a materialised
///    copy) to Python's `ssl.load_verify_locations`.
/// 2. Otherwise materialise the native certificate store to a PEM
///    tempfile (via [`native_ca_bundle_path`]) and return that path.
///    This is the main win on Windows and macOS where the Python
///    `ssl` module otherwise can't see the native root CAs.
/// 3. On Linux with nothing installed, return the first known
///    location as a breadcrumb so error messages point at a plausible
///    path. On Windows, fall back to looking for `cacert.pem` next to
///    the executable (the historical default Breezy used).
pub fn default_ca_certs() -> String {
    // Linux first: prefer the real system bundle over a
    // materialisation of it.
    if !cfg!(any(target_os = "windows", target_os = "macos")) {
        for path in SSL_CA_CERTS_KNOWN_LOCATIONS {
            if Path::new(path).exists() {
                return (*path).to_string();
            }
        }
    }

    if let Some(native) = native_ca_bundle_path() {
        return native;
    }

    if cfg!(target_os = "windows") {
        if let Some(argv0) = std::env::args_os().next() {
            if let Ok(canon) = Path::new(&argv0).canonicalize() {
                if let Some(parent) = canon.parent() {
                    return parent.join("cacert.pem").to_string_lossy().into_owned();
                }
            }
        }
        return "cacert.pem".to_string();
    }

    // Linux no-bundle fallback (Unix with no known location on disk).
    SSL_CA_CERTS_KNOWN_LOCATIONS[0].to_string()
}

/// Format a User-Agent prefix from a product name and version.
pub fn format_user_agent(product: &str, version: &str) -> String {
    format!("{}/{}", product, version)
}

/// Split a `host[:port]` string into its two parts.
///
/// Mirrors the Python helper in `dromedary/http/urllib.py`: the port is
/// the digits after the *last* colon (so IPv6 literals like `"::1"` parse
/// as host `":"` with port `"1"`, matching the regex). An empty port
/// (`"host:"`) is returned as `None` instead of an empty string. If no
/// `:` is present, port is `None` and the whole input is returned as the
/// host.
pub fn splitport(host: &str) -> (&str, Option<&str>) {
    if let Some(idx) = host.rfind(':') {
        let port = &host[idx + 1..];
        if port.is_empty() {
            return (&host[..idx], None);
        }
        if port.bytes().all(|b| b.is_ascii_digit()) {
            return (&host[..idx], Some(port));
        }
    }
    (host, None)
}

/// Split a WWW-Authenticate / Proxy-Authenticate header into `(scheme,
/// remainder)`.
///
/// The scheme is always lowercased. The remainder is whatever follows
/// the first whitespace run, trimmed of leading whitespace (preserving
/// internal spaces and quoting). If the header has no whitespace, the
/// whole header is the scheme and the remainder is `None`.
pub fn parse_auth_header(server_header: &str) -> (String, Option<&str>) {
    if let Some(idx) = server_header.find(|c: char| c.is_ascii_whitespace()) {
        let (scheme, rest) = server_header.split_at(idx);
        let remainder = rest.trim_start();
        (scheme.to_ascii_lowercase(), Some(remainder))
    } else {
        (server_header.to_ascii_lowercase(), None)
    }
}

/// Split an RFC 2068 §2 comma-separated list while honouring quoted
/// strings and backslash escapes. Matches the behaviour of
/// `urllib.request.parse_http_list`.
///
/// Commas inside `"..."` don't split; a `\` inside a quoted string
/// escapes the next character (typically `\"` or `\\`). Each element is
/// trimmed of surrounding whitespace, but inner whitespace and the
/// surrounding quotes are preserved. An empty input yields an empty
/// list.
pub fn parse_http_list(s: &str) -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();
    let mut part = String::new();
    let mut quote = false;
    let mut escape = false;

    for cur in s.chars() {
        if escape {
            part.push(cur);
            escape = false;
            continue;
        }
        if quote {
            if cur == '\\' {
                escape = true;
                continue;
            } else if cur == '"' {
                quote = false;
            }
            part.push(cur);
            continue;
        }
        if cur == ',' {
            parts.push(std::mem::take(&mut part));
            continue;
        }
        if cur == '"' {
            quote = true;
        }
        part.push(cur);
    }
    if !part.is_empty() {
        parts.push(part);
    }
    parts.into_iter().map(|p| p.trim().to_string()).collect()
}

/// HTTP Digest authentication hash algorithm as named in the
/// `algorithm=` parameter of a `WWW-Authenticate: Digest` header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// RFC 2617 `MD5` — the default and still the most commonly seen.
    Md5,
    /// RFC 2617 `SHA` — SHA-1 based digest. RFC 7616's SHA-256 family is
    /// *not* yet supported (the Python side never accepted it either).
    Sha1,
}

impl DigestAlgorithm {
    /// Parse the `algorithm=` value. Returns `None` for unsupported
    /// algorithms, matching the Python behaviour of failing the
    /// `auth_match` check.
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "MD5" => Some(Self::Md5),
            "SHA" => Some(Self::Sha1),
            _ => None,
        }
    }

    /// The digest function `H(x)` from RFC 2617 §3.2.1: hex-encoded
    /// digest of the raw input bytes.
    pub fn h(self, data: &[u8]) -> String {
        match self {
            Self::Md5 => {
                use md5::{Digest, Md5};
                hex::encode(Md5::digest(data))
            }
            Self::Sha1 => {
                use sha1::{Digest, Sha1};
                hex::encode(Sha1::digest(data))
            }
        }
    }

    /// The keyed-digest function `KD(secret, data) = H(secret ":" data)`.
    pub fn kd(self, secret: &str, data: &str) -> String {
        let mut buf = String::with_capacity(secret.len() + 1 + data.len());
        buf.push_str(secret);
        buf.push(':');
        buf.push_str(data);
        self.h(buf.as_bytes())
    }
}

/// Generate a client nonce for HTTP Digest authentication.
///
/// Builds `"<nonce>:<nonce_count>:<timestamp>:<random>"` and returns
/// the first 16 hex characters of its SHA-1 digest, matching the
/// Python `get_new_cnonce`. Uniqueness is what the cnonce needs; the
/// exact bit-mixing is not security-critical beyond collision
/// resistance.
pub fn new_cnonce(nonce: &str, nonce_count: u64) -> String {
    use rand::Rng;
    use sha1::{Digest, Sha1};
    use std::time::{SystemTime, UNIX_EPOCH};

    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);

    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                           abcdefghijklmnopqrstuvwxyz\
                           0123456789";
    let mut rng = rand::thread_rng();
    let rand_suffix: String = (0..8)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect();

    let raw = format!("{}:{}:{}:{}", nonce, nonce_count, ts, rand_suffix);
    let digest = Sha1::digest(raw.as_bytes());
    hex::encode(digest)[..16].to_string()
}

/// Parse a list of `key=value` pairs into a map. Matches
/// `urllib.request.parse_keqv_list`.
///
/// Values wrapped in a single pair of double quotes are unquoted
/// verbatim (no escape processing — [`parse_http_list`] already
/// consumed any `\"`). Duplicated keys follow Python semantics: the
/// last one wins. Entries without `=` are silently dropped, matching
/// stdlib behaviour when the caller feeds it through
/// [`parse_http_list`] first.
pub fn parse_keqv_list(items: &[String]) -> std::collections::HashMap<String, String> {
    let mut parsed = std::collections::HashMap::new();
    for elt in items {
        if let Some((k, v)) = elt.split_once('=') {
            let v = if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
                &v[1..v.len() - 1]
            } else {
                v
            };
            parsed.insert(k.to_string(), v.to_string());
        }
    }
    parsed
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests in this module mutate the shared `CURL_CA_BUNDLE` environment
    // variable and the module-level cache, so they must not run in parallel
    // with each other.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn ca_path_honours_env_var() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_ca_path_cache();
        let sentinel = "dromedary-test-ca-bundle.pem";
        // SAFETY: serialised against the other tests in this module via
        // `ENV_LOCK`; std::env::set_var is unsafe only under concurrent access.
        unsafe { std::env::set_var("CURL_CA_BUNDLE", sentinel) };
        let got = get_ca_path(false);
        unsafe { std::env::remove_var("CURL_CA_BUNDLE") };
        assert_eq!(got, sentinel);
    }

    #[test]
    fn ca_path_caches_when_requested() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_ca_path_cache();
        // SAFETY: serialised against the other tests in this module via
        // `ENV_LOCK`.
        unsafe { std::env::set_var("CURL_CA_BUNDLE", "first-sentinel") };
        let first = get_ca_path(true);
        unsafe { std::env::set_var("CURL_CA_BUNDLE", "second-sentinel") };
        let second = get_ca_path(true);
        unsafe { std::env::remove_var("CURL_CA_BUNDLE") };
        assert_eq!(first, "first-sentinel");
        assert_eq!(second, "first-sentinel");
        clear_ca_path_cache();
    }

    #[test]
    fn default_ca_certs_returns_known_fallback() {
        // We don't know which path exists on the test host, but it must be
        // one of the known locations (or the first one as a last resort).
        let result = default_ca_certs();
        let allowed = || SSL_CA_CERTS_KNOWN_LOCATIONS.contains(&result.as_str());
        if cfg!(target_os = "windows") {
            assert!(result.ends_with("cacert.pem"));
        } else {
            assert!(allowed(), "unexpected CA path: {}", result);
        }
    }

    #[test]
    fn user_agent_format() {
        assert_eq!(format_user_agent("Dromedary", "0.1.0"), "Dromedary/0.1.0");
    }

    #[test]
    fn default_cert_reqs_matches_ssl_constants() {
        // `ssl.CERT_NONE == 0` and `ssl.CERT_REQUIRED == 2` are load-
        // bearing: the Python side compares this integer against those
        // constants. If the enum ever grows a new variant, it must
        // reuse the corresponding stdlib integer.
        let v = default_cert_reqs().to_int();
        assert!(matches!(v, 0 | 2));
    }

    #[test]
    fn user_agent_setter_roundtrips() {
        // The User-Agent prefix is process-global state, so other
        // tests may have mutated it. Save and restore around this
        // test to keep the suite self-contained.
        let prev = default_user_agent();
        set_user_agent("Test-Agent/1.0".into());
        assert_eq!(default_user_agent(), "Test-Agent/1.0");
        set_user_agent(prev);
    }

    #[test]
    fn splitport_splits_trailing_port() {
        assert_eq!(splitport("example.com:443"), ("example.com", Some("443")));
    }

    #[test]
    fn splitport_no_port() {
        assert_eq!(splitport("example.com"), ("example.com", None));
    }

    #[test]
    fn splitport_empty_port_is_none() {
        // "host:" matches the Python regex with an empty port group; the
        // Python helper normalises that to `None` via `port or None`.
        assert_eq!(splitport("example.com:"), ("example.com", None));
    }

    #[test]
    fn splitport_non_numeric_port_keeps_whole_host() {
        // Python's regex only matches digits, so everything after the last
        // ':' has to be all-digits for the split to happen. Anything else
        // falls through to `return host, None`.
        assert_eq!(splitport("example.com:http"), ("example.com:http", None));
    }

    #[test]
    fn splitport_ipv6_like_rightmost_split() {
        // The Python regex is greedy from the left, so `"::1"` splits into
        // host `":"` and port `"1"`. Our rfind-based version reproduces that.
        assert_eq!(splitport("::1"), (":", Some("1")));
    }

    #[test]
    fn parse_auth_header_basic() {
        let (scheme, rest) = parse_auth_header("Basic realm=\"secure area\"");
        assert_eq!(scheme, "basic");
        assert_eq!(rest, Some("realm=\"secure area\""));
    }

    #[test]
    fn parse_auth_header_no_remainder() {
        let (scheme, rest) = parse_auth_header("Negotiate");
        assert_eq!(scheme, "negotiate");
        assert_eq!(rest, None);
    }

    #[test]
    fn parse_http_list_simple() {
        assert_eq!(parse_http_list("a, b, c"), vec!["a", "b", "c"]);
    }

    #[test]
    fn parse_http_list_quoted_commas() {
        assert_eq!(
            parse_http_list(r#"a="hello, world", b=42"#),
            vec![r#"a="hello, world""#, "b=42"]
        );
    }

    #[test]
    fn parse_http_list_escaped_quote() {
        // Matches stdlib `urllib.request.parse_http_list`: the backslash
        // is consumed, the following character is appended verbatim. So
        // `\"` inside a quoted string contributes a bare `"` to the
        // output and does *not* terminate the quoted region.
        assert_eq!(
            parse_http_list(r#"a="he said \"hi\"", b=1"#),
            vec![r#"a="he said "hi"""#, "b=1"]
        );
    }

    #[test]
    fn parse_http_list_empty() {
        assert_eq!(parse_http_list(""), Vec::<String>::new());
    }

    #[test]
    fn parse_keqv_list_unquotes_values() {
        let items = vec![
            r#"realm="secure""#.to_string(),
            "nonce=abc".to_string(),
            "qop=auth".to_string(),
        ];
        let m = parse_keqv_list(&items);
        assert_eq!(m.get("realm").map(String::as_str), Some("secure"));
        assert_eq!(m.get("nonce").map(String::as_str), Some("abc"));
        assert_eq!(m.get("qop").map(String::as_str), Some("auth"));
    }

    #[test]
    fn parse_keqv_list_preserves_inner_quotes() {
        // Only a matched outer pair is stripped; inner quotes (rare but
        // possible when `\"` was in the original header) stay put.
        let items = vec![r#"k="a""b""#.to_string()];
        assert_eq!(
            parse_keqv_list(&items).get("k").map(String::as_str),
            Some(r#"a""b"#)
        );
    }

    #[test]
    fn parse_keqv_list_drops_items_without_eq() {
        // Mirrors the Python impl when called via `parse_http_list`: the
        // stdlib would raise on a missing `=`; we choose to drop silently
        // so the Rust side never panics on a malformed header.
        let items = vec!["bare".to_string(), "k=v".to_string()];
        let m = parse_keqv_list(&items);
        assert_eq!(m.len(), 1);
        assert_eq!(m.get("k").map(String::as_str), Some("v"));
    }

    #[test]
    fn digest_md5_vector() {
        // "abc" -> well-known MD5 digest.
        assert_eq!(
            DigestAlgorithm::Md5.h(b"abc"),
            "900150983cd24fb0d6963f7d28e17f72"
        );
    }

    #[test]
    fn digest_sha1_vector() {
        // "abc" -> well-known SHA-1 digest.
        assert_eq!(
            DigestAlgorithm::Sha1.h(b"abc"),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
    }

    #[test]
    fn digest_kd_prepends_colon_separator() {
        // KD("secret", "data") == H("secret:data").
        let kd = DigestAlgorithm::Md5.kd("secret", "data");
        let h = DigestAlgorithm::Md5.h(b"secret:data");
        assert_eq!(kd, h);
    }

    #[test]
    fn digest_algorithm_parse() {
        assert_eq!(DigestAlgorithm::parse("MD5"), Some(DigestAlgorithm::Md5));
        assert_eq!(DigestAlgorithm::parse("SHA"), Some(DigestAlgorithm::Sha1));
        assert_eq!(DigestAlgorithm::parse("SHA-256"), None);
    }

    #[test]
    fn new_cnonce_is_16_hex_chars() {
        let c = new_cnonce("servernonce", 1);
        assert_eq!(c.len(), 16);
        assert!(c.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn new_cnonce_varies() {
        // Two calls back-to-back should differ (timestamp nanos + random).
        let a = new_cnonce("nonce", 1);
        let b = new_cnonce("nonce", 1);
        assert_ne!(a, b);
    }
}
