//! Python bindings for `dromedary::webdav::HttpDavTransport`.
//!
//! Exposes `dromedary._transport_rs.webdav.HttpDavTransport` as a
//! pyclass that extends `_transport_rs.http.HttpTransport`. The
//! Python `dromedary.webdav.webdav.HttpDavTransport` becomes a
//! thin subclass over this, same pattern as HTTP.
//!
//! Inheritance rationale: WebDAV is "HTTP plus write verbs". By
//! extending the HttpTransport pyclass we inherit all its Python
//! methods (`request`, `_post`, `_head`, `_range_hint`, etc.)
//! unchanged, and only have to implement the DAV-specific verbs.
//! The HttpTransport parent holds the underlying HttpTransport
//! pointer in its `inner` field; the DAV subclass holds the full
//! HttpDavTransport, and the two share the same underlying
//! `HttpClient` through `Arc` clones — so auth cache, connection
//! pool, and range-hint state are consistent across both layers.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use dromedary::http::client::{HttpClientConfig, NegotiateProvider};
use dromedary::http::HttpClient;
use dromedary::webdav::HttpDavTransport as RsHttpDavTransport;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use crate::http::client::{PythonCredentialProvider, PythonNegotiateProvider};
use crate::http::transport::{http_transport_initializer, HttpTransport as PyHttpTransport};
use crate::map_transport_err_to_py_err;

/// Python-bound Rust WebDAV transport.
///
/// Constructor mirrors the HTTP pyclass: `HttpDavTransport(base,
/// ca_certs=None, disable_verification=False, user_agent=None,
/// read_timeout_ms=0)`. The `+webdav` / `+urllib` scheme suffix is
/// accepted and stripped.
#[pyclass(
    extends=PyHttpTransport,
    subclass,
    module = "dromedary._transport_rs.webdav",
)]
pub(crate) struct HttpDavTransport {
    inner: Arc<RsHttpDavTransport>,
}

#[pymethods]
impl HttpDavTransport {
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
    ) -> PyResult<PyClassInitializer<Self>> {
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
        let mut client = HttpClient::with_providers(
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
        client.set_auth_trace(Some(std::sync::Arc::new(|header: &str| {
            crate::http::invoke_auth_header_trace(header);
        })));
        let rust = RsHttpDavTransport::new(base, Arc::new(client))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(base)))?;
        Ok(dav_transport_initializer(Arc::new(rust)))
    }

    /// Clone this transport at an optional offset, sharing the
    /// underlying HttpClient. Returns an instance of the Rust-level
    /// HttpDavTransport pyclass; Python subclasses override
    /// `clone()` to rebrand via `_rust_replace_inner_from` (the
    /// HttpTransport-inherited helper).
    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<&str>,
    ) -> PyResult<Bound<'a, HttpDavTransport>> {
        let cloned = slf
            .inner
            .clone_concrete(offset)
            .map_err(|e| map_transport_err_to_py_err(e, None, offset))?;
        Bound::new(py, dav_transport_initializer(Arc::new(cloned)))
    }

    /// Replace this transport's inner state with a clone of
    /// `source`. Mirrors `HttpTransport._rust_replace_inner_from`
    /// but cascades down to refresh the DAV layer too, so the
    /// Python subclass's `clone()` preserves subclass identity
    /// while still sharing the HttpClient across siblings.
    fn _rust_replace_inner_from(
        mut slf: PyRefMut<Self>,
        py: Python,
        source: PyRef<HttpDavTransport>,
        offset: Option<&str>,
    ) -> PyResult<()> {
        let cloned = source
            .inner
            .clone_concrete(offset)
            .map_err(|e| map_transport_err_to_py_err(e, None, offset))?;
        let new_inner = Arc::new(cloned);
        // Refresh every layer's dyn-Transport pointer so calls
        // through each inheritance level see the cloned state.
        let dav_box: Box<dyn dromedary::Transport> = Box::new((*new_inner).clone());
        let http_layer = slf.as_super();
        // Update the HttpTransport parent's own HTTP-transport
        // pointer so inherited methods (`request`, `_post`, ...) see
        // the grafted state.
        http_layer.inner = Arc::new(new_inner.http().clone());
        let connected_layer = http_layer.as_super();
        connected_layer.as_super().0 = dav_box;
        slf.inner = new_inner;
        let _ = py;
        Ok(())
    }

    /// Eagerly-drained GET — returns the full response body as a
    /// bytes object. Used by the Python subclass's `get()` override
    /// (the DAV transport uses the inherited `request()` machinery
    /// and wants the body materialised in one shot).
    fn _get_bytes<'py>(&self, py: Python<'py>, relpath: &str) -> PyResult<Bound<'py, PyBytes>> {
        let buf = py
            .detach(|| -> Result<Vec<u8>, dromedary::Error> {
                use dromedary::Transport as _;
                let mut rf = self.inner.get(relpath)?;
                let mut buf = Vec::new();
                std::io::Read::read_to_end(&mut rf, &mut buf).map_err(dromedary::Error::Io)?;
                Ok(buf)
            })
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        Ok(PyBytes::new(py, &buf))
    }

    fn has(&self, py: Python, relpath: &str) -> PyResult<bool> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.has(relpath))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    fn mkdir(&self, py: Python, relpath: &str) -> PyResult<()> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.mkdir(relpath, None))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    fn rmdir(&self, py: Python, relpath: &str) -> PyResult<()> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.rmdir(relpath))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    fn rename(&self, py: Python, rel_from: &str, rel_to: &str) -> PyResult<()> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.rename(rel_from, rel_to))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(rel_from)))
    }

    fn delete(&self, py: Python, relpath: &str) -> PyResult<()> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.delete(relpath))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    fn copy(&self, py: Python, rel_from: &str, rel_to: &str) -> PyResult<()> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.copy(rel_from, rel_to))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(rel_from)))
    }

    /// PUT with the atomic temp+MOVE dance; returns `len(bytes)`.
    fn put_bytes(&self, py: Python, relpath: &str, bytes: &[u8]) -> PyResult<u64> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.put_bytes(relpath, bytes, None))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        Ok(bytes.len() as u64)
    }

    /// Non-atomic PUT (bare, no temp-file dance). `create_parent_dir`
    /// causes a 404/403/409 to retry after creating the missing
    /// parent directory via MKCOL.
    #[pyo3(signature = (relpath, bytes, create_parent_dir=false))]
    fn put_bytes_non_atomic(
        &self,
        py: Python,
        relpath: &str,
        bytes: &[u8],
        create_parent_dir: bool,
    ) -> PyResult<()> {
        use dromedary::Transport as _;
        py.detach(|| {
            self.inner
                .put_bytes_non_atomic(relpath, bytes, None, Some(create_parent_dir), None)
        })
        .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    /// Append `bytes` to the file at `relpath`, returning the file
    /// size before the append. Picks between HEAD+ranged-PUT and
    /// GET+modify+PUT based on the inherited range-hint state.
    fn append_bytes(&self, py: Python, relpath: &str, bytes: &[u8]) -> PyResult<u64> {
        use dromedary::Transport as _;
        py.detach(|| self.inner.append_bytes(relpath, bytes, None))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    /// `stat(relpath)` — returns a Python object with `st_size` and
    /// `st_mode` attributes, matching the shape the Python
    /// `_DAVStat` had. Directories get `st_size=0` and a dir mode
    /// (040644); regular files get their PROPFIND-reported size
    /// and 100644 or 100755 depending on the `executable` flag.
    fn stat<'py>(&self, py: Python<'py>, relpath: &str) -> PyResult<Bound<'py, PyAny>> {
        use dromedary::Transport as _;
        let stat = py
            .detach(|| self.inner.stat(relpath))
            .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))?;
        let dict = pyo3::types::PyDict::new(py);
        dict.set_item("st_size", stat.size)?;
        #[cfg(unix)]
        dict.set_item("st_mode", stat.mode)?;
        // Return a SimpleNamespace so callers use dotted access
        // (bzr reads `st.st_mode`, not `st['st_mode']`).
        let types = py.import("types")?;
        let ns = types.getattr("SimpleNamespace")?.call((), Some(&dict))?;
        Ok(ns)
    }

    /// List immediate children of `relpath`. Names are relative to
    /// `relpath` (with any trailing slash stripped). Errors from
    /// PROPFIND surface as Python exceptions on the caller's first
    /// iteration; we materialise the list eagerly so `list_dir()`
    /// behaves like a Python list rather than a lazy iterator.
    fn list_dir(&self, py: Python, relpath: &str) -> PyResult<Vec<String>> {
        use dromedary::Transport as _;
        py.detach(|| -> Result<Vec<String>, dromedary::Error> {
            let iter = self.inner.list_dir(relpath);
            iter.collect::<Result<Vec<_>, _>>()
        })
        .map_err(|e| map_transport_err_to_py_err(e, None, Some(relpath)))
    }

    fn iter_files_recursive(&self, py: Python) -> PyResult<Vec<String>> {
        use dromedary::Transport as _;
        py.detach(|| -> Result<Vec<String>, dromedary::Error> {
            let iter = self.inner.iter_files_recursive();
            iter.collect::<Result<Vec<_>, _>>()
        })
        .map_err(|e| map_transport_err_to_py_err(e, None, None))
    }
}

/// Build the four-layer `Transport → ConnectedTransport →
/// HttpTransport → HttpDavTransport` initializer.
///
/// Design note on what the `dyn Transport` at the base points to:
/// we construct the HttpTransport parent normally (its inner points
/// at the HTTP transport embedded inside the DAV transport), which
/// means the `Transport` pyclass's own `dyn Transport` box also
/// points at the HTTP transport. Python-visible behaviour that
/// differs between HTTP and DAV (is_readonly, listable, write
/// verbs) is exposed via DAV-specific pymethods on this subclass,
/// so the Python caller sees DAV semantics; the base pyclass's
/// inherited methods like `get` / `has` / `readv` work either way
/// because DAV delegates them to the HTTP layer anyway.
fn dav_transport_initializer(
    inner: Arc<RsHttpDavTransport>,
) -> PyClassInitializer<HttpDavTransport> {
    let http_inner = Arc::new(inner.http().clone());
    http_transport_initializer(http_inner).add_subclass(HttpDavTransport { inner })
}
