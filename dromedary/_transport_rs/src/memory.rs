use crate::{map_transport_err_to_py_err, Transport};
use dromedary::memory::{MemoryStore, MemoryTransport as RustMemoryTransport};
use pyo3::prelude::*;
use std::sync::{Arc, Mutex};

/// Opaque handle to a shared `MemoryStore`. Used by `MemoryServer` (in Python)
/// to ensure every `MemoryTransport` it hands out shares the same backing
/// store, matching the semantics of the original Python implementation where
/// the server re-assigned `_dirs`/`_files`/... on each constructed transport.
#[pyclass]
pub(crate) struct MemoryStoreHandle {
    inner: Arc<Mutex<MemoryStore>>,
}

#[pymethods]
impl MemoryStoreHandle {
    #[new]
    fn new() -> Self {
        // Construct a throwaway transport just to get a fresh MemoryStore Arc.
        let t = RustMemoryTransport::new("memory:///").expect("fresh memory transport");
        MemoryStoreHandle {
            inner: t.shared_store(),
        }
    }
}

#[pyclass(extends=Transport, subclass)]
pub(crate) struct MemoryTransport {
    #[pyo3(get)]
    _scheme: String,
    #[pyo3(get)]
    _cwd: String,
}

fn split_url(url: &str) -> (String, String, String) {
    let mut normalised = if url.is_empty() {
        "memory:///".to_string()
    } else {
        url.to_string()
    };
    if !normalised.ends_with('/') {
        normalised.push('/');
    }
    let split = normalised
        .find(':')
        .map(|i| i + 3)
        .unwrap_or(normalised.len());
    let scheme = normalised[..split].to_string();
    let cwd = normalised[split..].to_string();
    (normalised, scheme, cwd)
}

#[pymethods]
impl MemoryTransport {
    #[new]
    #[pyo3(signature = (url="", _shared_store=None))]
    fn new(url: &str, _shared_store: Option<Py<MemoryStoreHandle>>) -> PyResult<(Self, Transport)> {
        let (normalised, scheme, cwd) = split_url(url);

        let rust = match _shared_store {
            Some(handle) => {
                let arc = Python::attach(|py| handle.borrow(py).inner.clone());
                RustMemoryTransport::with_shared_store(&normalised, arc)
                    .map_err(|e| map_transport_err_to_py_err(e, None, None))?
            }
            None => RustMemoryTransport::new(&normalised)
                .map_err(|e| map_transport_err_to_py_err(e, None, None))?,
        };

        Ok((
            MemoryTransport {
                _scheme: scheme,
                _cwd: cwd,
            },
            Transport(Box::new(rust)),
        ))
    }

    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<String>,
    ) -> PyResult<Bound<'a, MemoryTransport>> {
        let super_ = slf.as_ref();
        let inner = super_
            .0
            .clone(offset.as_deref())
            .map_err(|e| map_transport_err_to_py_err(e, None, None))?;
        let new_base = inner.base().to_string();
        let (_n, scheme, cwd) = split_url(&new_base);
        let init = PyClassInitializer::from(Transport(inner)).add_subclass(MemoryTransport {
            _scheme: scheme,
            _cwd: cwd,
        });
        Bound::new(py, init)
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<MemoryStoreHandle>()?;
    m.add_class::<MemoryTransport>()?;
    Ok(())
}
