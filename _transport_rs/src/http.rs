//! Python bindings for the HTTP helper functions in `dromedary::http`.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyList, PyTuple};
use pyo3::IntoPyObjectExt;

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

    let locations = PyList::new(py, dromedary::http::SSL_CA_CERTS_KNOWN_LOCATIONS)?;
    m.add("SSL_CA_CERTS_KNOWN_LOCATIONS", locations)?;

    Ok(())
}
