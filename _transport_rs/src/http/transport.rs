//! Python bindings for `dromedary::http::transport::HttpTransport`.
//!
//! Exposes the Rust HTTP transport as
//! `dromedary._transport_rs.http.HttpTransport`, a pyclass that
//! extends `Transport`. The Python `HttpTransport` in
//! `dromedary/http/urllib.py` becomes a thin subclass that adds
//! breezy-side hooks (`_medium`, `_report_activity` override)
//! without re-implementing the transport itself.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dromedary::http::client::{HttpClientConfig, NegotiateProvider};
use dromedary::http::{HttpClient, HttpTransport as RsHttpTransport};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::map_transport_err_to_py_err;
use crate::Transport;

use super::client::{PythonCredentialProvider, PythonNegotiateProvider};

/// Python-bound Rust HTTP transport.
///
/// Constructor: `HttpTransport(base, ca_certs=None,
/// disable_verification=False, user_agent=None,
/// read_timeout_ms=0)`. Each construction builds a fresh
/// `HttpClient`; call `clone()` to get a sibling transport that
/// shares the underlying agent and auth cache.
///
/// We stash a concrete `Arc<RsHttpTransport>` alongside the base
/// `Transport` so helper methods like `_post` can reach the
/// HttpTransport-specific API without going through a
/// `dyn Transport` downcast.
#[pyclass(extends=Transport, subclass, module = "dromedary._transport_rs.http")]
pub(crate) struct HttpTransport {
    inner: Arc<RsHttpTransport>,
}

#[pymethods]
impl HttpTransport {
    #[new]
    #[pyo3(signature = (
        base,
        ca_certs=None,
        disable_verification=false,
        user_agent=None,
        read_timeout_ms=0,
    ))]
    fn new(
        base: &str,
        ca_certs: Option<PathBuf>,
        disable_verification: bool,
        user_agent: Option<String>,
        read_timeout_ms: i64,
    ) -> PyResult<(Self, Transport)> {
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
        let client = HttpClient::with_providers(
            cfg,
            Box::new(PythonCredentialProvider),
            Box::new(PythonNegotiateProvider) as Box<dyn NegotiateProvider>,
        )
        .map_err(|e| {
            map_transport_err_to_py_err(
                dromedary::Error::Io(std::io::Error::other(format!("{}", e))),
                None,
                Some(base),
            )
        })?;
        let rust = RsHttpTransport::new(base, Arc::new(client))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(base)))?;
        let inner = Arc::new(rust);
        let base_box: Box<dyn dromedary::Transport> = Box::new((*inner).clone());
        Ok((Self { inner }, Transport(base_box)))
    }

    /// Clone this transport at an optional offset, sharing the
    /// underlying HttpClient.
    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<&str>,
    ) -> PyResult<Bound<'a, HttpTransport>> {
        // Use the concrete Rust transport's clone to preserve the
        // HttpTransport-specific behaviour (range-hint sharing etc.)
        // rather than going through the dyn Transport vtable.
        let cloned = slf
            .inner
            .clone_concrete(offset)
            .map_err(|e| map_transport_err_to_py_err(e, None, offset))?;
        let inner = Arc::new(cloned);
        let base_box: Box<dyn dromedary::Transport> = Box::new((*inner).clone());
        let init = PyClassInitializer::from(Transport(base_box)).add_subclass(Self { inner });
        Bound::new(py, init)
    }

    /// POST `body` to `relpath` and return `(status, response_body)`.
    /// Mirrors the Python `HttpTransport._post` used by breezy's
    /// smart HTTP medium.
    fn _post<'py>(
        &self,
        py: Python<'py>,
        relpath: &str,
        body: &[u8],
    ) -> PyResult<(u16, Bound<'py, PyBytes>)> {
        let (status, mut rf) = self
            .inner
            .post(relpath, body)
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        // The smart-protocol medium reads the whole response body
        // sequentially, so eager-read here matches the shape it
        // would do anyway.
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut rf, &mut buf).map_err(|e| {
            map_transport_err_to_py_err(dromedary::Error::Io(e), None, Some(relpath))
        })?;
        Ok((status, PyBytes::new(py, &buf)))
    }
}

pub(crate) fn register(m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<HttpTransport>()?;
    Ok(())
}
