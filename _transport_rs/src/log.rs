//! PyO3 bindings for `dromedary::log::LogTransport`.

use crate::Transport;
use dromedary::log::{LogSink, LogTransport};
use dromedary::pyo3::PyTransport;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use std::sync::Arc;

const PREFIX: &str = "log+";

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

/// Build a sink that forwards formatted messages to the named Python logger
/// at DEBUG level. Wrapped in `Arc` so the sink can be cheaply cloned — each
/// LogTransport instance keeps its own handle but they share the underlying
/// Python object.
fn python_debug_sink(py: Python, logger_name: &str) -> PyResult<LogSink> {
    let logging = py.import("logging")?;
    let logger = logging.call_method1("getLogger", (logger_name,))?.unbind();
    let logger = Arc::new(logger);
    Ok(Box::new(move |msg: &str| {
        Python::attach(|py| {
            // Ignore errors — logging failures should not propagate and break
            // the transport method. If the logger is gone we silently drop
            // the message, matching Python's best-effort logging semantics.
            let _ = logger.bind(py).call_method1("debug", (msg,));
        });
    }))
}

#[pyclass(extends=Transport, subclass)]
pub(crate) struct TransportLogDecorator {
    decorated: Py<PyAny>,
}

#[pymethods]
impl TransportLogDecorator {
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
        let sink = python_debug_sink(py, "dromedary.log")?;
        let wrapped = LogTransport::new(py_inner, sink);
        Ok((
            TransportLogDecorator { decorated },
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
    ) -> PyResult<Bound<'a, TransportLogDecorator>> {
        let decorated = slf.decorated.clone_ref(py);
        let decorated_clone = match offset {
            Some(o) => decorated.call_method1(py, "clone", (o,))?,
            None => decorated.call_method0(py, "clone")?,
        };
        let py_inner: Box<dyn dromedary::Transport + Send + Sync> =
            Box::new(PyTransport::from(decorated_clone.clone_ref(py)));
        let sink = python_debug_sink(py, "dromedary.log")?;
        let wrapped = LogTransport::new(py_inner, sink);
        let init = PyClassInitializer::from(Transport(Box::new(wrapped))).add_subclass(
            TransportLogDecorator {
                decorated: decorated_clone,
            },
        );
        Bound::new(py, init)
    }
}

pub(crate) fn register(_py: Python, m: &Bound<PyModule>) -> PyResult<()> {
    m.add_class::<TransportLogDecorator>()?;
    Ok(())
}
