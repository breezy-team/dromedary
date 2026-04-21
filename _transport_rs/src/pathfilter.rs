use crate::{map_transport_err_to_py_err, Transport};
use dromedary::pathfilter::FilterFunc;
use dromedary::pyo3::PyTransport;
use pyo3::prelude::*;
use std::sync::Arc;

fn make_filter_func(filter_py: Option<Py<PyAny>>) -> Option<FilterFunc> {
    let f = filter_py?;
    Some(Arc::new(move |p: &str| -> dromedary::Result<String> {
        Python::attach(|py| match f.call1(py, (p,)) {
            Ok(r) => r
                .extract::<String>(py)
                .map_err(|e| dromedary::Error::from(e)),
            Err(e) => Err(dromedary::Error::from(e)),
        })
    }))
}

fn build_rust_transport(
    py: Python,
    server: &Py<PyAny>,
    base: &str,
) -> PyResult<dromedary::pathfilter::PathFilteringTransport> {
    let backing = server.getattr(py, "backing_transport")?;
    let scheme: String = server.getattr(py, "scheme")?.extract(py)?;
    let filter_func_py: Option<Py<PyAny>> = {
        let obj = server.getattr(py, "filter_func")?;
        if obj.is_none(py) {
            None
        } else {
            Some(obj)
        }
    };

    let mut full_base = base.to_string();
    if !full_base.ends_with('/') {
        full_base.push('/');
    }
    // base_path is the path portion of the base URL, derived the same way
    // Python does: self.base[len(self.server.scheme) - 1:]
    let base_path = if full_base.len() + 1 >= scheme.len() {
        full_base[scheme.len() - 1..].to_string()
    } else {
        "/".to_string()
    };

    let backing_rust: Box<dyn dromedary::Transport + Send + Sync> =
        Box::new(PyTransport::from(backing));
    let filter = make_filter_func(filter_func_py);
    dromedary::pathfilter::PathFilteringTransport::new(backing_rust, scheme, base_path, filter)
        .map_err(|e| map_transport_err_to_py_err(e, None, None))
}

#[pyclass(extends=Transport, subclass)]
pub(crate) struct PathFilteringTransport {
    server: Py<PyAny>,
    base: String,
}

#[pymethods]
impl PathFilteringTransport {
    #[new]
    fn new(py: Python, server: Py<PyAny>, base: String) -> PyResult<(Self, Transport)> {
        let rust = build_rust_transport(py, &server, &base)?;
        let mut stored_base = base.clone();
        if !stored_base.ends_with('/') {
            stored_base.push('/');
        }
        Ok((
            PathFilteringTransport {
                server,
                base: stored_base,
            },
            Transport(Box::new(rust)),
        ))
    }

    #[getter]
    fn server(&self, py: Python) -> Py<PyAny> {
        self.server.clone_ref(py)
    }

    #[getter]
    fn scheme(&self, py: Python) -> PyResult<String> {
        self.server.getattr(py, "scheme")?.extract(py)
    }

    #[getter]
    fn base_path(&self, py: Python) -> PyResult<String> {
        let scheme: String = self.server.getattr(py, "scheme")?.extract(py)?;
        if self.base.len() + 1 >= scheme.len() {
            Ok(self.base[scheme.len() - 1..].to_string())
        } else {
            Ok("/".to_string())
        }
    }

    fn _relpath_from_server_root(&self, py: Python, relpath: &str) -> PyResult<String> {
        let base_path = self.base_path(py)?;
        let urlutils = py.import("dromedary.urlutils")?;
        let combined: String = urlutils
            .call_method1("combine_paths", (base_path, relpath))?
            .extract()?;
        if !combined.starts_with('/') {
            return Err(pyo3::exceptions::PyValueError::new_err(combined));
        }
        Ok(combined[1..].to_string())
    }

    fn _filter(&self, py: Python, relpath: &str) -> PyResult<String> {
        let rebased = self._relpath_from_server_root(py, relpath)?;
        let filter_func = self.server.getattr(py, "filter_func")?;
        if filter_func.is_none(py) {
            return Ok(rebased);
        }
        filter_func.call1(py, (rebased,))?.extract(py)
    }

    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'a, PathFilteringTransport>> {
        let super_ = slf.as_ref();
        let new_base_url = match offset {
            Some(o) => {
                let o_str: String = o.extract(py)?;
                super_
                    .0
                    .abspath(&o_str)
                    .map_err(|e| map_transport_err_to_py_err(e, None, Some(&o_str)))?
                    .to_string()
            }
            None => super_.0.base().to_string(),
        };
        let server = slf.server.clone_ref(py);
        let rust = build_rust_transport(py, &server, &new_base_url)?;
        let mut stored_base = new_base_url;
        if !stored_base.ends_with('/') {
            stored_base.push('/');
        }
        let init = PyClassInitializer::from(Transport(Box::new(rust))).add_subclass(
            PathFilteringTransport {
                server,
                base: stored_base,
            },
        );
        Bound::new(py, init)
    }
}

#[pyclass(extends=PathFilteringTransport, subclass)]
pub(crate) struct ChrootTransport {}

#[pymethods]
impl ChrootTransport {
    #[new]
    fn new(py: Python, server: Py<PyAny>, base: String) -> PyResult<PyClassInitializer<Self>> {
        let (parent, t) = PathFilteringTransport::new(py, server, base)?;
        let init = PyClassInitializer::from(t)
            .add_subclass(parent)
            .add_subclass(ChrootTransport {});
        Ok(init)
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<PathFilteringTransport>()?;
    m.add_class::<ChrootTransport>()?;
    Ok(())
}
