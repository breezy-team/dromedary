use crate::Transport;
use dromedary::pyo3::PyTransport;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

const PREFIX: &str = "unlistable+";

fn resolve_inner(py: Python, url: &str, decorated: Option<Py<PyAny>>) -> PyResult<Py<PyAny>> {
    if let Some(d) = decorated {
        return Ok(d);
    }
    if !url.starts_with(PREFIX) {
        return Err(PyValueError::new_err(format!(
            "url {:?} doesn't start with decorator prefix {:?}",
            url, PREFIX
        )));
    }
    let rest = &url[PREFIX.len()..];
    let dromedary = py.import("dromedary")?;
    let urlutils = py.import("dromedary.urlutils")?;
    let is_url: bool = urlutils.call_method1("is_url", (rest,))?.extract()?;
    let func = if is_url {
        dromedary.getattr("get_transport_from_url")?
    } else {
        dromedary.getattr("get_transport_from_path")?
    };
    Ok(func.call1((rest,))?.unbind())
}

#[pyclass(extends=Transport, subclass)]
pub(crate) struct UnlistableTransportDecorator {
    decorated: Py<PyAny>,
}

#[pymethods]
impl UnlistableTransportDecorator {
    #[new]
    #[pyo3(signature = (url, _decorated=None, _from_transport=None))]
    fn new(
        py: Python,
        url: &str,
        _decorated: Option<Py<PyAny>>,
        _from_transport: Option<Py<PyAny>>,
    ) -> PyResult<(Self, Transport)> {
        let _ = _from_transport;
        let decorated = resolve_inner(py, url, _decorated)?;
        let py_inner: Box<dyn dromedary::Transport + Send + Sync> =
            Box::new(PyTransport::from(decorated.clone_ref(py)));
        let wrapped = dromedary::unlistable::UnlistableTransport::new(py_inner);
        Ok((
            UnlistableTransportDecorator { decorated },
            Transport(Box::new(wrapped)),
        ))
    }

    #[getter]
    fn _decorated(&self, py: Python) -> Py<PyAny> {
        self.decorated.clone_ref(py)
    }

    #[classmethod]
    fn _get_url_prefix(_cls: &Bound<'_, pyo3::types::PyType>) -> &'static str {
        PREFIX
    }

    #[pyo3(signature = (offset=None))]
    fn clone<'a>(
        slf: PyRef<'a, Self>,
        py: Python<'a>,
        offset: Option<Py<PyAny>>,
    ) -> PyResult<Bound<'a, UnlistableTransportDecorator>> {
        let decorated = slf.decorated.clone_ref(py);
        let decorated_clone = match offset {
            Some(o) => decorated.call_method1(py, "clone", (o,))?,
            None => decorated.call_method0(py, "clone")?,
        };
        let base: String = decorated_clone.getattr(py, "base")?.extract(py)?;
        let url = format!("{}{}", PREFIX, base);

        let py_inner: Box<dyn dromedary::Transport + Send + Sync> =
            Box::new(PyTransport::from(decorated_clone.clone_ref(py)));
        let wrapped = dromedary::unlistable::UnlistableTransport::new(py_inner);
        let _ = url;
        let init = PyClassInitializer::from(Transport(Box::new(wrapped))).add_subclass(
            UnlistableTransportDecorator {
                decorated: decorated_clone,
            },
        );
        Bound::new(py, init)
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<UnlistableTransportDecorator>()?;
    Ok(())
}
