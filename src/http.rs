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
}
