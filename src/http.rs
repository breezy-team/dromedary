//! HTTP support helpers.
//!
//! These are environment/filesystem lookups that don't need any HTTP client
//! to be wired in: locating the CA certificate bundle and the User-Agent
//! default. The Python wrapper in `dromedary.http` delegates to these.

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
/// On non-Windows, non-macOS systems, scans [`SSL_CA_CERTS_KNOWN_LOCATIONS`]
/// and returns the first entry that exists on disk. If nothing is found the
/// first known location is returned as a fallback so that any error message
/// surfaced to the user at least points at a plausible path.
///
/// On Windows the convention is to look for `cacert.pem` next to the
/// executable. On macOS there is no sensible default (tracked upstream); we
/// fall back to the same placeholder as when nothing is found on Linux.
pub fn default_ca_certs() -> String {
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

    if cfg!(target_os = "macos") {
        // TODO: No sensible default for macOS yet; upstream is still waiting
        // on installer-team feedback (see Python source comments).
        return SSL_CA_CERTS_KNOWN_LOCATIONS[0].to_string();
    }

    for path in SSL_CA_CERTS_KNOWN_LOCATIONS {
        if Path::new(path).exists() {
            return (*path).to_string();
        }
    }
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
