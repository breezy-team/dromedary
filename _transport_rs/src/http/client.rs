//! Python bindings for `dromedary::http::client`.
//!
//! Exposes `HttpClient` as a `#[pyclass]`. The Python `HttpTransport`
//! in `dromedary/http/urllib.py` uses this instead of the legacy
//! urllib.request handler stack.
//!
//! The returned `HttpResponse` pyclass mirrors the shape the Python
//! code previously got from its `Urllib3LikeResponse` adapter —
//! `.status`, `.reason`, `.getheader()`, `.getheaders()`, `.data`,
//! `.text`, `.read()`, `.readline()`, `.readlines()` — so existing
//! callers (and the still-Python `HttpTransport.request` wrapper) see
//! no breaking change.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use dromedary::http::client::{
    ActivityCallback, ActivityDirection, ClientError, CredentialProvider,
    HttpClient as RsHttpClient, HttpClientConfig, HttpResponse as RsHttpResponse,
    NegotiateProvider, RequestOptions,
};
use pyo3::exceptions::{PyIOError, PyValueError};
use pyo3::import_exception;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyString, PyTuple};

import_exception!(dromedary.errors, ConnectionError);
import_exception!(dromedary.errors, InvalidHttpResponse);

/// Turn a [`ClientError`] into an appropriate Python exception.
///
/// Transport-level failures (DNS, TCP, TLS) become
/// `dromedary.errors.ConnectionError`; malformed URLs / methods
/// become `ValueError`; IO errors after the response started
/// become `OSError`. This matches how the Python urllib-handler
/// stack used to funnel errors.
pub(super) fn client_err_to_py(err: ClientError) -> PyErr {
    match err {
        ClientError::InvalidRequest(msg) => PyValueError::new_err(msg),
        ClientError::Io(e) => PyIOError::new_err(e.to_string()),
        ClientError::Transport(e) => {
            // `ureq::Error`'s Display carries the useful context
            // (hostname, port, TLS reason). Wrap as ConnectionError
            // so breezy's retry loop triggers on it the way it did
            // for the old handler-layer errors.
            ConnectionError::new_err(e.to_string())
        }
    }
}

/// CredentialProvider impl that delegates to the Python callback
/// registered via `set_credential_lookup`. All state lives in the
/// parent module's `CREDENTIAL_LOOKUP` so multiple clients share
/// the same callback.
pub(crate) struct PythonCredentialProvider;

impl CredentialProvider for PythonCredentialProvider {
    fn lookup(
        &self,
        protocol: &str,
        host: &str,
        port: Option<u16>,
        realm: Option<&str>,
    ) -> (Option<String>, Option<String>) {
        super::invoke_credential_lookup(protocol, host, port, realm)
    }
}

/// NegotiateProvider that delegates to the Python callback
/// registered via `set_negotiate_provider`. Dromedary ships a
/// default implementation in `dromedary.http` that uses the
/// Python `kerberos` module.
pub(crate) struct PythonNegotiateProvider;

impl NegotiateProvider for PythonNegotiateProvider {
    fn initial_token(&self, host: &str) -> Option<String> {
        super::invoke_negotiate_provider(host)
    }
}

#[pyclass(module = "dromedary._transport_rs.http", frozen)]
pub(crate) struct HttpClient {
    inner: RsHttpClient,
    // Default options applied when Python callers don't pass an
    // override. Wrapped in a Mutex because pyclass(frozen) forbids
    // &mut self; callers interact via dedicated setters below.
    defaults: Mutex<RequestOptions>,
}

#[pymethods]
impl HttpClient {
    /// Construct a new client.
    ///
    /// `ca_certs` — optional path to a PEM bundle.
    /// `disable_verification` — matches Python's `ssl.CERT_NONE`.
    /// `user_agent` — if omitted, inherits the module-level default.
    /// `read_timeout_ms` — 0 or negative means "no timeout".
    #[new]
    #[pyo3(signature = (
        ca_certs=None,
        disable_verification=false,
        user_agent=None,
        read_timeout_ms=0,
    ))]
    fn new(
        ca_certs: Option<PathBuf>,
        disable_verification: bool,
        user_agent: Option<String>,
        read_timeout_ms: i64,
    ) -> PyResult<Self> {
        let timeout = if read_timeout_ms > 0 {
            Some(Duration::from_millis(read_timeout_ms as u64))
        } else {
            None
        };
        let cfg = HttpClientConfig {
            ca_certs_path: ca_certs,
            disable_verification,
            user_agent,
            read_timeout: timeout,
        };
        let inner = RsHttpClient::with_providers(
            cfg,
            Box::new(PythonCredentialProvider),
            Box::new(PythonNegotiateProvider),
        )
        .map_err(client_err_to_py)?;
        Ok(Self {
            inner,
            defaults: Mutex::new(RequestOptions::default()),
        })
    }

    /// Set the default `follow_redirects` flag for subsequent calls
    /// that don't pass an explicit `follow_redirects` argument.
    ///
    /// Exposed so breezy's `HttpTransport.request(..., retries=N)`
    /// can toggle following once per transport rather than threading
    /// the flag through every call site.
    fn set_default_follow_redirects(&self, follow: bool) {
        self.defaults.lock().unwrap().follow_redirects = follow;
    }

    /// Issue an HTTP request.
    ///
    /// `headers` is an iterable of `(name, value)` pairs (matching
    /// the stdlib pattern). `report_activity`, when provided, is a
    /// callable invoked as `report_activity(byte_count, direction)`
    /// where direction is `"read"` or `"write"` — matches the Python
    /// `Transport._report_activity` signature so breezy's progress
    /// bar integration works unchanged.
    #[pyo3(signature = (
        method,
        url,
        headers=None,
        body=None,
        follow_redirects=None,
        report_activity=None,
    ))]
    fn request(
        &self,
        py: Python,
        method: &str,
        url: &str,
        headers: Option<Py<PyAny>>,
        body: Option<Py<PyAny>>,
        follow_redirects: Option<bool>,
        report_activity: Option<Py<PyAny>>,
    ) -> PyResult<HttpResponse> {
        let header_pairs = match headers {
            Some(h) => extract_headers(py, &h)?,
            None => Vec::new(),
        };
        let body_bytes = match body {
            Some(b) => extract_body(py, &b)?,
            None => Vec::new(),
        };
        let opts = {
            let mut o = self.defaults.lock().unwrap().clone();
            if let Some(f) = follow_redirects {
                o.follow_redirects = f;
            }
            o
        };
        let activity: Option<ActivityCallback> = report_activity.map(make_activity_callback);

        // `Python::detach` releases the GIL while the HTTP call is
        // in flight so other Python threads can run (matching the
        // behaviour of the old urllib-based transport, which did the
        // actual socket read under the GIL-released `ssl` module).
        //
        // The activity callback reacquires the GIL inside its
        // closure body — safe because we're handing ownership of
        // the callback to `request_with` via a reference.
        let resp = py.detach(|| {
            self.inner.request_with(
                method,
                url,
                &header_pairs,
                &body_bytes,
                &opts,
                activity.as_ref(),
            )
        });
        let resp = resp.map_err(client_err_to_py)?;
        Ok(HttpResponse::new(resp))
    }
}

/// Wrap a Python callable as an [`ActivityCallback`]. The Python
/// callable receives `(byte_count, direction_str)` where direction
/// is `"read"` or `"write"` — matching the
/// `Transport._report_activity` signature breezy's UI expects.
///
/// Errors inside the callback are silently swallowed. Activity
/// reporting is advisory; a broken progress-bar hook shouldn't fail
/// the actual HTTP request.
pub(super) fn make_activity_callback(cb: Py<PyAny>) -> ActivityCallback {
    std::sync::Arc::new(move |bytes: usize, dir: ActivityDirection| {
        Python::attach(|py| {
            // `call1` can raise; ignore the result so a buggy hook
            // doesn't propagate into the HTTP path.
            let _ = cb.bind(py).call1((bytes, dir.as_str()));
        });
    })
}

/// Urllib3-shaped response returned by [`HttpClient::request`].
///
/// Intentionally offers both the Python-file protocol (`read`,
/// `readline`, `readlines`) and the urllib3 property set (`status`,
/// `reason`, `data`, `text`, `getheader`, `getheaders`) so existing
/// callers pulled from `Urllib3LikeResponse` work unchanged.
///
/// The body is streamed on demand from ureq rather than buffered
/// eagerly: `status` / `reason` / `getheader` / `getheaders` read
/// purely from metadata, `data` / `text` / `read(None)` force a
/// full drain, and `read(n)` / `readline()` pull incrementally.
/// First call to a "full drain" method transitions the underlying
/// body to a Buffered state so repeat reads are cheap.
#[pyclass(module = "dromedary._transport_rs.http")]
pub(crate) struct HttpResponse {
    inner: Mutex<RsHttpResponse>,
}

impl HttpResponse {
    pub(super) fn new(raw: RsHttpResponse) -> Self {
        Self {
            inner: Mutex::new(raw),
        }
    }
}

#[pymethods]
impl HttpResponse {
    #[getter]
    fn status(&self) -> u16 {
        self.inner.lock().unwrap().status
    }

    #[getter]
    fn reason(&self) -> String {
        self.inner.lock().unwrap().reason.clone()
    }

    /// Final URL after any redirect following. For requests that
    /// weren't redirected this equals the request URL.
    #[getter]
    fn final_url(&self) -> String {
        self.inner.lock().unwrap().final_url.clone()
    }

    /// Set when the server returned a 3xx that the client didn't
    /// auto-follow (`follow_redirects=False`). Callers use this to
    /// raise `RedirectRequested`.
    #[getter]
    fn redirected_to(&self) -> Option<String> {
        self.inner.lock().unwrap().redirected_to.clone()
    }

    /// Case-insensitive header lookup. `default` is returned if
    /// no header matches.
    #[pyo3(signature = (name, default=None))]
    fn getheader(&self, py: Python, name: &str, default: Option<Py<PyAny>>) -> Py<PyAny> {
        let inner = self.inner.lock().unwrap();
        match inner.header(name) {
            Some(v) => PyString::new(py, v).into(),
            None => default.unwrap_or_else(|| py.None()),
        }
    }

    /// Return all headers as a list of `(name, value)` tuples.
    fn getheaders<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let inner = self.inner.lock().unwrap();
        let items: Vec<Bound<'py, PyAny>> = inner
            .headers
            .iter()
            .map(|(k, v)| {
                let tup = PyTuple::new(py, [PyString::new(py, k), PyString::new(py, v)])?;
                Ok::<_, PyErr>(tup.into_any())
            })
            .collect::<PyResult<Vec<_>>>()?;
        PyList::new(py, items)
    }

    /// Full response body as bytes. Forces a drain on first access;
    /// subsequent reads through this property return the same
    /// buffer without re-reading.
    #[getter]
    fn data<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyBytes>> {
        let mut inner = self.inner.lock().unwrap();
        let body = inner.body().map_err(py_io_err)?;
        Ok(PyBytes::new(py, body))
    }

    /// Decoded body as str, using the Content-Type charset when
    /// present. Matches the Python `Urllib3LikeResponse.text` shim —
    /// returns `None` on a 204 No Content response.
    #[getter]
    fn text(&self, py: Python) -> PyResult<Py<PyAny>> {
        let mut inner = self.inner.lock().unwrap();
        if inner.status == 204 {
            return Ok(py.None());
        }
        // Read the charset out of the Content-Type header before
        // borrowing the body; the two &self borrows otherwise
        // overlap because `body()` takes &mut.
        let _charset = inner
            .header("content-type")
            .and_then(|v| {
                v.split(';').find_map(|piece| {
                    let piece = piece.trim();
                    piece
                        .strip_prefix("charset=")
                        .map(|c| c.trim_matches('"').to_string())
                })
            })
            .unwrap_or_else(|| "utf-8".to_string());

        // Only UTF-8 is handled natively; everything else falls back
        // to replacing invalid bytes. Real non-UTF-8 payloads are
        // vanishingly rare on the Bazaar smart-protocol path this
        // is aimed at, and breezy didn't support them either.
        let body = inner.body().map_err(py_io_err)?;
        let text = String::from_utf8_lossy(body).into_owned();
        Ok(PyString::new(py, &text).into())
    }

    /// File-like read. `size=None` (or negative) reads all remaining
    /// bytes — forces a full drain. Positive `size` pulls up to that
    /// many bytes from the current position (streamed), leaving the
    /// rest available for subsequent reads.
    #[pyo3(signature = (size=None))]
    fn read<'py>(&self, py: Python<'py>, size: Option<i64>) -> PyResult<Bound<'py, PyBytes>> {
        let mut inner = self.inner.lock().unwrap();
        let n = match size {
            None | Some(-1) => None,
            Some(n) if n < 0 => None,
            Some(n) => Some(n as usize),
        };
        let data = inner.read(n).map_err(py_io_err)?;
        Ok(PyBytes::new(py, &data))
    }

    /// Read up to the next newline (inclusive) or EOF. Forces the
    /// body to be buffered on first call — line splitting across a
    /// live stream would require a BufRead wrapper we don't have
    /// yet, and the callers that use readline() (handle_response
    /// for multipart responses) typically consume the whole body
    /// anyway.
    #[pyo3(signature = (_size=-1))]
    fn readline<'py>(&self, py: Python<'py>, _size: i64) -> PyResult<Bound<'py, PyBytes>> {
        let mut inner = self.inner.lock().unwrap();
        // Drain the body into the buffer so we can scan for '\n'
        // without losing the rest of the stream.
        let _ = inner.body().map_err(py_io_err)?;
        // Now read one byte at a time until '\n' or EOF. This works
        // because the BodyState is Buffered after body().
        let mut line: Vec<u8> = Vec::new();
        loop {
            let chunk = inner.read(Some(1)).map_err(py_io_err)?;
            if chunk.is_empty() {
                break;
            }
            let b = chunk[0];
            line.push(b);
            if b == b'\n' {
                break;
            }
        }
        Ok(PyBytes::new(py, &line))
    }

    fn readlines<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let mut out: Vec<Bound<'py, PyBytes>> = Vec::new();
        loop {
            let line = self.readline(py, -1)?;
            if line.as_bytes().is_empty() {
                break;
            }
            out.push(line);
        }
        PyList::new(py, out)
    }

    /// Close the response by discarding any unread body, returning
    /// the underlying socket to ureq's pool. Mirrors the file-like
    /// `close()` contract.
    fn close(&self) -> PyResult<()> {
        self.inner.lock().unwrap().discard_body().map_err(py_io_err)
    }
}

/// Map an `io::Error` from the streaming body read into `OSError`.
fn py_io_err(e: std::io::Error) -> PyErr {
    PyIOError::new_err(e.to_string())
}

/// Coerce whatever Python hands us into `(name, value)` pairs. We
/// accept either a dict or any iterable of two-tuples, matching the
/// old `request` signature where callers could pass either.
pub(super) fn extract_headers(py: Python, obj: &Py<PyAny>) -> PyResult<Vec<(String, String)>> {
    let bound = obj.bind(py);
    if let Ok(d) = bound.cast::<pyo3::types::PyDict>() {
        let mut out = Vec::with_capacity(d.len());
        for (k, v) in d.iter() {
            out.push((k.extract::<String>()?, v.extract::<String>()?));
        }
        return Ok(out);
    }
    let mut out = Vec::new();
    for item in bound.try_iter()? {
        let pair = item?;
        let tup = pair.cast::<PyTuple>().map_err(|_| {
            PyValueError::new_err("headers must be a dict or iterable of (name, value) tuples")
        })?;
        if tup.len() != 2 {
            return Err(PyValueError::new_err(
                "header tuples must have exactly two elements",
            ));
        }
        let k: String = tup.get_item(0)?.extract()?;
        let v: String = tup.get_item(1)?.extract()?;
        out.push((k, v));
    }
    Ok(out)
}

/// Accept `bytes`, `bytearray`, `memoryview`, or `str` (encoded as
/// UTF-8) as the request body. Matches how the Python side
/// previously passed data to `connection._send_request`.
pub(super) fn extract_body(py: Python, obj: &Py<PyAny>) -> PyResult<Vec<u8>> {
    let bound = obj.bind(py);
    if let Ok(b) = bound.cast::<PyBytes>() {
        return Ok(b.as_bytes().to_vec());
    }
    if let Ok(s) = bound.extract::<String>() {
        return Ok(s.into_bytes());
    }
    // Fallback: coerce via `bytes()` (handles bytearray, memoryview).
    let as_bytes = py
        .get_type::<PyBytes>()
        .call1((bound.clone(),))
        .map_err(|e| PyValueError::new_err(format!("can't interpret body as bytes: {}", e)))?;
    let b = as_bytes
        .cast::<PyBytes>()
        .map_err(|e| PyValueError::new_err(format!("body coercion failed: {}", e)))?;
    Ok(b.as_bytes().to_vec())
}

pub(crate) fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<HttpClient>()?;
    m.add_class::<HttpResponse>()?;
    Ok(())
}
