//! Python bindings for the HTTP helper functions in `dromedary::http`.

pub(crate) mod client;
mod response;
pub(crate) mod transport;

use std::sync::Mutex;

use lazy_static::lazy_static;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use pyo3::IntoPyObjectExt;

// ---------------------------------------------------------------------------
// Credential-lookup callback. Breezy registers a Python callable that
// maps (protocol, host, port, path, realm) to (user, password). We
// store the Py<PyAny> here so the hot-path auth code in urllib.py (and
// eventually the Rust HTTP client) can call into it without round-
// tripping through module-attribute lookup.
// ---------------------------------------------------------------------------

lazy_static! {
    /// Registered credential-lookup callback. `None` means no
    /// callback has been set and `get_credentials` should return
    /// `(None, None)`.
    static ref CREDENTIAL_LOOKUP: Mutex<Option<Py<PyAny>>> = Mutex::new(None);
    /// Registered Negotiate (Kerberos) initial-token callback.
    /// Called as `cb(host) -> Optional[str]`; the returned string
    /// goes after `Negotiate ` in the Authorization header.
    static ref NEGOTIATE_PROVIDER: Mutex<Option<Py<PyAny>>> = Mutex::new(None);
    /// Registered auth-header-sent callback. The Rust client calls
    /// this just before sending a request carrying an Authorization
    /// or Proxy-Authorization header; breezy uses it to emit a
    /// `trace.mutter("> %s: <masked>", header_name)` line when the
    /// `http` debug flag is on, so users can confirm auth happened
    /// without leaking the credential value into logs.
    static ref AUTH_HEADER_TRACE: Mutex<Option<Py<PyAny>>> = Mutex::new(None);
}

/// Invoke the registered auth-header-trace callback. No-op if no
/// callback is set. Errors from the callback are swallowed — this
/// is a tracing hook, not a control-flow one, so a broken logger
/// mustn't break HTTP auth.
pub(crate) fn invoke_auth_header_trace(header_name: &str) {
    Python::attach(|py| {
        let cb = {
            let guard = AUTH_HEADER_TRACE.lock().unwrap();
            guard.as_ref().map(|p| p.clone_ref(py))
        };
        if let Some(cb) = cb {
            let _ = cb.bind(py).call1((header_name,));
        }
    });
}

/// Invoke the registered Negotiate callback. Returns `None` if no
/// callback is set, the callback returned a non-string, or it
/// raised. Matches the behaviour of the old Python
/// `_auth_match_kerberos` which quietly returned `None` on any
/// GSSAPI error.
pub(super) fn invoke_negotiate_provider(host: &str) -> Option<String> {
    Python::attach(|py| {
        let cb = {
            let guard = NEGOTIATE_PROVIDER.lock().unwrap();
            guard.as_ref().map(|p| p.clone_ref(py))
        };
        let cb = cb?;
        let result = cb.bind(py).call1((host,)).ok()?;
        if result.is_none() {
            return None;
        }
        result.extract::<String>().ok()
    })
}

/// Invoke the registered credential-lookup callback with the given
/// arguments. Returns `(None, None)` if no callback is set, or if
/// the callback raises — we don't surface those errors because the
/// auth layer treats them as "no credentials available".
pub(super) fn invoke_credential_lookup(
    protocol: &str,
    host: &str,
    port: Option<u16>,
    realm: Option<&str>,
    user: Option<&str>,
    is_proxy: bool,
) -> (Option<String>, Option<String>) {
    Python::attach(|py| {
        let cb = {
            let guard = CREDENTIAL_LOOKUP.lock().unwrap();
            guard.as_ref().map(|p| p.clone_ref(py))
        };
        let Some(cb) = cb else {
            return (None, None);
        };
        let kwargs = pyo3::types::PyDict::new(py);
        // The Python callback signature is
        // `(protocol, host, port=None, path=None, realm=None, user=None,
        //   is_proxy=False)`;
        // we leave `path` as None because the Rust client doesn't track
        // it per-request (breezy's urllib version did, but the value was
        // rarely used by downstream credential stores). `user` is the
        // URL-embedded username hint — breezy's AuthenticationConfig
        // uses it to skip its own user prompt when the URL already
        // names one. `is_proxy` tells the callback that the credentials
        // are for a proxy (407) rather than the origin (401), so it can
        // label interactive prompts accordingly.
        let _ = kwargs.set_item("port", port);
        let _ = kwargs.set_item("path", py.None());
        let _ = kwargs.set_item("realm", realm);
        if let Some(u) = user {
            let _ = kwargs.set_item("user", u);
        }
        if is_proxy {
            let _ = kwargs.set_item("is_proxy", true);
        }
        let mut result = cb.bind(py).call((protocol, host), Some(&kwargs));
        // Older callbacks may not accept the `user` / `is_proxy` kwargs.
        // If that's the cause of a TypeError, drop them progressively so
        // we don't regress on callers that haven't been updated.
        if result.is_err() && is_proxy {
            let _ = kwargs.del_item("is_proxy");
            result = cb.bind(py).call((protocol, host), Some(&kwargs));
        }
        if result.is_err() && user.is_some() {
            let _ = kwargs.del_item("user");
            result = cb.bind(py).call((protocol, host), Some(&kwargs));
        }
        match result {
            Ok(obj) => {
                let tup = match obj.cast::<PyTuple>() {
                    Ok(t) => t,
                    Err(_) => return (None, None),
                };
                if tup.len() != 2 {
                    return (None, None);
                }
                let user = tup
                    .get_item(0)
                    .ok()
                    .and_then(|v| v.extract::<Option<String>>().ok())
                    .flatten();
                let password = tup
                    .get_item(1)
                    .ok()
                    .and_then(|v| v.extract::<Option<String>>().ok())
                    .flatten();
                (user, password)
            }
            Err(_) => (None, None),
        }
    })
}

#[pyfunction]
#[pyo3(signature = (use_cache=true))]
fn get_ca_path(use_cache: bool) -> String {
    dromedary::http::get_ca_path(use_cache)
}

#[pyfunction]
fn clear_ca_path_cache() {
    dromedary::http::clear_ca_path_cache();
}

#[pyfunction]
fn default_ca_certs() -> String {
    dromedary::http::default_ca_certs()
}

/// Split a `host[:port]` string. Returns `(host, port_or_none)`.
#[pyfunction]
fn splitport(py: Python, host: &str) -> PyResult<Py<PyAny>> {
    let (h, p) = dromedary::http::splitport(host);
    let tup = PyTuple::new(py, [h.into_py_any(py)?, p.into_py_any(py)?])?;
    Ok(tup.into())
}

/// Split a WWW-Authenticate header into `(scheme_lower, remainder_or_none)`.
#[pyfunction]
fn parse_auth_header(py: Python, header: &str) -> PyResult<Py<PyAny>> {
    let (scheme, rest) = dromedary::http::parse_auth_header(header);
    let tup = PyTuple::new(py, [scheme.into_py_any(py)?, rest.into_py_any(py)?])?;
    Ok(tup.into())
}

/// Parse an RFC 2068 §2 comma-separated list honouring quoted strings.
#[pyfunction]
fn parse_http_list(s: &str) -> Vec<String> {
    dromedary::http::parse_http_list(s)
}

/// Parse a list of `key=value` pairs (typically produced by
/// [`parse_http_list`]) into a dict.
#[pyfunction]
fn parse_keqv_list(items: Vec<String>) -> std::collections::HashMap<String, String> {
    dromedary::http::parse_keqv_list(&items)
}

/// Compute the HTTP Digest `H(x)` function for the given algorithm. The
/// algorithm name is the value of the server's `algorithm=` parameter
/// (`"MD5"` or `"SHA"`). Raises `ValueError` for unsupported algorithms
/// so callers get a clear error rather than a silent mismatch.
#[pyfunction]
fn digest_h(algorithm: &str, data: &[u8]) -> PyResult<String> {
    let algo = dromedary::http::DigestAlgorithm::parse(algorithm)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported algorithm: {}", algorithm)))?;
    Ok(algo.h(data))
}

/// Compute the HTTP Digest `KD(secret, data) = H(secret ":" data)`.
#[pyfunction]
fn digest_kd(algorithm: &str, secret: &str, data: &str) -> PyResult<String> {
    let algo = dromedary::http::DigestAlgorithm::parse(algorithm)
        .ok_or_else(|| PyValueError::new_err(format!("unsupported algorithm: {}", algorithm)))?;
    Ok(algo.kd(secret, data))
}

/// Check whether an `algorithm=` name is one we can compute.
#[pyfunction]
fn digest_algorithm_supported(algorithm: &str) -> bool {
    dromedary::http::DigestAlgorithm::parse(algorithm).is_some()
}

/// Generate a client nonce for HTTP Digest authentication.
#[pyfunction]
fn get_new_cnonce(nonce: &str, nonce_count: u64) -> String {
    dromedary::http::new_cnonce(nonce, nonce_count)
}

/// Check a host against a `no_proxy` list. Returns `True` to bypass
/// the proxy, `False` to use it, or `None` if the caller should fall
/// back to the platform-specific proxy-bypass logic (Python's
/// `urllib.request.proxy_bypass`).
///
/// This preserves the Python `ProxyHandler.evaluate_proxy_bypass`
/// contract byte-for-byte, including the surprising prefix-only
/// match that lets `example.com` in `no_proxy` match
/// `example.com.evil.com`.
#[pyfunction]
#[pyo3(signature = (host, no_proxy))]
fn evaluate_proxy_bypass(py: Python, host: &str, no_proxy: Option<&str>) -> Py<PyAny> {
    use dromedary::http::ProxyBypass;
    match dromedary::http::evaluate_proxy_bypass(host, no_proxy) {
        ProxyBypass::Bypass => true.into_py_any(py).unwrap(),
        ProxyBypass::UseProxy => false.into_py_any(py).unwrap(),
        ProxyBypass::Undecided => py.None(),
    }
}

/// Replace the global User-Agent prefix.
#[pyfunction]
fn set_user_agent(prefix: String) {
    dromedary::http::set_user_agent(prefix);
}

/// Return the current User-Agent prefix.
#[pyfunction]
fn default_user_agent() -> String {
    dromedary::http::default_user_agent()
}

/// Platform-default certificate verification requirement. Returns an
/// integer matching `ssl.CERT_NONE` / `ssl.CERT_REQUIRED` so the
/// Python side can compare against `ssl.*` constants directly.
#[pyfunction]
fn default_cert_reqs() -> u8 {
    dromedary::http::default_cert_reqs().to_int()
}

/// Register a credential-lookup callable. The callable is invoked as
/// `func(protocol, host, port=None, path=None, realm=None)` and
/// should return `(user, password)` (either may be `None`).
///
/// Passing `None` clears any previously-registered callback so
/// subsequent [`get_credentials`] calls fall back to the `(None,
/// None)` default.
#[pyfunction]
fn set_credential_lookup(py: Python, func: Py<PyAny>) {
    let mut slot = CREDENTIAL_LOOKUP.lock().unwrap();
    *slot = if func.bind(py).is_none() {
        None
    } else {
        Some(func)
    };
}

/// Return the currently-registered credential-lookup callable, or
/// `None` if none is set. Mainly useful for tests that want to save
/// and restore the callback around assertions.
#[pyfunction]
fn get_credential_lookup(py: Python) -> Py<PyAny> {
    CREDENTIAL_LOOKUP
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| p.clone_ref(py))
        .unwrap_or_else(|| py.None())
}

/// Register a Negotiate (Kerberos) initial-token callback. The
/// callable is invoked as `func(host)` and should return the
/// base64-encoded token to send after `Negotiate ` in the
/// Authorization header, or `None` if no token is available (no
/// ticket / library missing / wrong realm).
///
/// Passing `None` clears any previously-registered callback.
#[pyfunction]
fn set_negotiate_provider(py: Python, func: Py<PyAny>) {
    let mut slot = NEGOTIATE_PROVIDER.lock().unwrap();
    *slot = if func.bind(py).is_none() {
        None
    } else {
        Some(func)
    };
}

/// Register a callback invoked when the HTTP client is about to
/// send an Authorization or Proxy-Authorization header. The
/// callable is invoked as `func(header_name)` — breezy uses this
/// for debug tracing so users can confirm auth credentials were
/// sent without exposing the values themselves in logs.
///
/// Passing `None` clears any previously-registered callback.
#[pyfunction]
fn set_auth_header_trace(py: Python, func: Py<PyAny>) {
    let mut slot = AUTH_HEADER_TRACE.lock().unwrap();
    *slot = if func.bind(py).is_none() {
        None
    } else {
        Some(func)
    };
}

/// Return the currently-registered Negotiate callback, or `None`.
#[pyfunction]
fn get_negotiate_provider(py: Python) -> Py<PyAny> {
    NEGOTIATE_PROVIDER
        .lock()
        .unwrap()
        .as_ref()
        .map(|p| p.clone_ref(py))
        .unwrap_or_else(|| py.None())
}

/// Look up credentials via the registered callback. Returns
/// `(None, None)` if no callback is set (the historical default).
#[pyfunction]
#[pyo3(signature = (protocol, host, port=None, path=None, realm=None))]
fn get_credentials(
    py: Python,
    protocol: &str,
    host: &str,
    port: Option<Py<PyAny>>,
    path: Option<Py<PyAny>>,
    realm: Option<Py<PyAny>>,
) -> PyResult<Py<PyAny>> {
    let cb = {
        let guard = CREDENTIAL_LOOKUP.lock().unwrap();
        guard.as_ref().map(|p| p.clone_ref(py))
    };
    match cb {
        Some(cb) => {
            let kwargs = pyo3::types::PyDict::new(py);
            kwargs.set_item("port", port.unwrap_or_else(|| py.None()))?;
            kwargs.set_item("path", path.unwrap_or_else(|| py.None()))?;
            kwargs.set_item("realm", realm.unwrap_or_else(|| py.None()))?;
            let result = cb.bind(py).call((protocol, host), Some(&kwargs))?;
            Ok(result.unbind())
        }
        None => {
            let tup = PyTuple::new(py, [py.None(), py.None()])?;
            Ok(tup.into())
        }
    }
}

pub(crate) fn register(py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(get_ca_path, m)?)?;
    m.add_function(wrap_pyfunction!(clear_ca_path_cache, m)?)?;
    m.add_function(wrap_pyfunction!(default_ca_certs, m)?)?;
    m.add_function(wrap_pyfunction!(splitport, m)?)?;
    m.add_function(wrap_pyfunction!(parse_auth_header, m)?)?;
    m.add_function(wrap_pyfunction!(parse_http_list, m)?)?;
    m.add_function(wrap_pyfunction!(parse_keqv_list, m)?)?;
    m.add_function(wrap_pyfunction!(digest_h, m)?)?;
    m.add_function(wrap_pyfunction!(digest_kd, m)?)?;
    m.add_function(wrap_pyfunction!(digest_algorithm_supported, m)?)?;
    m.add_function(wrap_pyfunction!(get_new_cnonce, m)?)?;
    m.add_function(wrap_pyfunction!(set_user_agent, m)?)?;
    m.add_function(wrap_pyfunction!(default_user_agent, m)?)?;
    m.add_function(wrap_pyfunction!(default_cert_reqs, m)?)?;
    m.add_function(wrap_pyfunction!(set_credential_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(get_credential_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(get_credentials, m)?)?;
    m.add_function(wrap_pyfunction!(set_negotiate_provider, m)?)?;
    m.add_function(wrap_pyfunction!(get_negotiate_provider, m)?)?;
    m.add_function(wrap_pyfunction!(set_auth_header_trace, m)?)?;
    m.add_function(wrap_pyfunction!(evaluate_proxy_bypass, m)?)?;

    client::register(m)?;
    response::register(m)?;
    transport::register(m)?;

    let locations = PyList::new(py, dromedary::http::SSL_CA_CERTS_KNOWN_LOCATIONS)?;
    m.add("SSL_CA_CERTS_KNOWN_LOCATIONS", locations)?;

    Ok(())
}
