use crate::{Error, ErrorCode, binding as b};
use ::pyo3::{exceptions::PyRuntimeError, prelude::*, types::PyBytes};
use std::sync::Arc;

fn err(error: Error) -> PyErr {
    Python::attach(|py| {
        let exception = PyRuntimeError::new_err(error.message);
        let value = exception.value(py);
        let _ = value.setattr("code", error.code.as_str());
        let _ = value.setattr("protocol_code", error.protocol_code);
        exception
    })
}
fn producer(error: PyErr) -> Error {
    Error::new(ErrorCode::Producer, error.to_string())
}
fn bytes(py: Python<'_>, data: Vec<u8>) -> Py<PyBytes> {
    PyBytes::new(py, &data).unbind()
}
fn fields(py: Python<'_>, headers: b::Fields) -> Vec<(String, Py<PyBytes>)> {
    headers
        .into_iter()
        .map(|(name, value)| (name, bytes(py, value)))
        .collect()
}

#[pyclass(frozen, skip_from_py_object)]
pub struct Authority {
    inner: b::Authority,
}
#[pymethods]
impl Authority {
    fn verify(&self, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
        b::verify(self.inner.public_key.clone(), data, signature).map_err(err)
    }
    #[getter]
    fn name(&self) -> String {
        self.inner.name.clone()
    }
    #[getter]
    fn owner_hash(&self) -> String {
        self.inner.owner_hash.clone()
    }
    #[getter]
    fn certificates(&self, py: Python<'_>) -> Vec<Py<PyBytes>> {
        self.inner
            .certificates
            .iter()
            .map(|value| bytes(py, value.clone()))
            .collect()
    }
    #[getter]
    fn public_key(&self, py: Python<'_>) -> Py<PyBytes> {
        bytes(py, self.inner.public_key.clone())
    }
    #[getter]
    fn subject_key_identifier(&self, py: Python<'_>) -> Py<PyBytes> {
        bytes(py, self.inner.subject_key_identifier.clone())
    }
}

#[pyfunction]
#[pyo3(signature=(peers,root_certificates=None))]
fn init<'py>(
    py: Python<'py>,
    peers: Vec<(String, String)>,
    root_certificates: Option<Vec<u8>>,
) -> PyResult<Bound<'py, PyAny>> {
    pyo3_async_runtimes::tokio::future_into_py(py, async move {
        b::init(peers, root_certificates).await.map_err(err)
    })
}
#[pyfunction]
fn addresses() -> Vec<String> {
    b::addresses()
}

#[pyclass(frozen)]
pub struct NativeClient {
    inner: crate::Client,
}
#[pymethods]
impl NativeClient {
    #[staticmethod]
    fn anonymous() -> Self {
        Self {
            inner: crate::Client::anonymous(),
        }
    }
    #[staticmethod]
    fn load(py: Python<'_>, name: String) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            crate::Client::load(name)
                .await
                .map(|inner| Self { inner })
                .map_err(err)
        })
    }
    #[staticmethod]
    fn load_from(py: Python<'_>, path: String) -> PyResult<Bound<'_, PyAny>> {
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            crate::Client::load_from(path)
                .await
                .map(|inner| Self { inner })
                .map_err(err)
        })
    }
    fn name<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move { Ok(client.name().await) })
    }
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client.close().await;
            Ok(())
        })
    }
    fn sign<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let signature = b::sign(&client, data).await.map_err(err)?;
            Ok(Python::attach(|py| bytes(py, signature)))
        })
    }
    fn reload<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(
            py,
            async move { client.reload().await.map_err(err) },
        )
    }
    fn local_authority<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            client
                .local_authority()
                .await
                .map_err(err)?
                .as_ref()
                .map(b::Authority::local)
                .transpose()
                .map(|a| a.map(|inner| Authority { inner }))
                .map_err(err)
        })
    }
    #[allow(clippy::too_many_arguments)]
    fn start<'py>(
        &self,
        py: Python<'py>,
        method: String,
        url: String,
        headers: b::Fields,
        has_body: bool,
        timeout_ms: Option<u32>,
        owner_hash: Option<String>,
        trailers: b::Fields,
    ) -> PyResult<Bound<'py, PyAny>> {
        let client = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            b::init(Vec::new(), None).await.map_err(err)?;
            b::Exchange::start(
                &client, method, url, headers, has_body, timeout_ms, owner_hash, trailers,
            )
            .await
            .map(|inner| NativeExchange {
                inner: Arc::new(inner),
            })
            .map_err(err)
        })
    }
    fn listen<'py>(
        &self,
        py: Python<'py>,
        scopes: Vec<String>,
        handler: Py<PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let locals = pyo3_async_runtimes::tokio::get_current_locals(py)?;
        let client = self.inner.clone();
        let handler = Arc::new(handler);
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            b::init(Vec::new(), None).await.map_err(err)?;
            let listener = client
                .listen(b::scopes(scopes).map_err(err)?, move |request| {
                    let handler = handler.clone();
                    let locals = locals.clone();
                    async move {
                        let (incoming, response) = b::Incoming::new(request);
                        let future = Python::attach(|py| {
                            let request = Py::new(
                                py,
                                NativeIncoming {
                                    inner: Arc::new(incoming),
                                },
                            )?;
                            let result = handler.call1(py, (request,))?;
                            pyo3_async_runtimes::into_future_with_locals(
                                &locals,
                                result.into_bound(py),
                            )
                        })
                        .map_err(producer)?;
                        future.await.map_err(producer)?;
                        response.await.map_err(|_| {
                            Error::new(ErrorCode::Producer, "handler did not return a response")
                        })
                    }
                })
                .await
                .map_err(err)?;
            Ok(NativeListener { inner: listener })
        })
    }
}
#[pyclass(frozen)]
pub struct NativeExchange {
    inner: Arc<b::Exchange>,
}
#[pymethods]
impl NativeExchange {
    fn response<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let exchange = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            exchange
                .response()
                .await
                .map(|inner| NativeResponse {
                    inner: Arc::new(inner),
                })
                .map_err(err)
        })
    }
    fn write<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let exchange = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            exchange
                .writer()
                .map_err(err)?
                .send(data)
                .await
                .map_err(err)
        })
    }
    fn finish<'py>(&self, py: Python<'py>, trailers: b::Fields) -> PyResult<Bound<'py, PyAny>> {
        let exchange = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            exchange
                .writer()
                .map_err(err)?
                .finish(b::headers(trailers).map_err(err)?)
                .await
                .map_err(err)
        })
    }
    fn fail(&self, message: String) {
        if let Some(upload) = &self.inner.upload {
            upload.fail(Error::new(ErrorCode::Producer, message));
        }
    }
    fn cancel(&self) {
        self.inner.cancellation.cancel();
    }
    fn closed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let exchange = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            if let Some(upload) = &exchange.upload {
                upload.closed().await;
            }
            Ok(())
        })
    }
}
#[pyclass(frozen)]
pub struct NativeResponse {
    inner: Arc<crate::ClientResponse>,
}
#[pymethods]
impl NativeResponse {
    #[getter]
    fn status(&self) -> u16 {
        self.inner.status().as_u16()
    }
    #[getter]
    fn headers(&self, py: Python<'_>) -> Vec<(String, Py<PyBytes>)> {
        fields(py, b::fields(self.inner.headers()))
    }
    fn authority(&self) -> PyResult<Option<Authority>> {
        self.inner
            .extensions()
            .get::<dhttp::RemoteAuthority>()
            .map(b::Authority::remote)
            .transpose()
            .map(|a| a.map(|inner| Authority { inner }))
            .map_err(err)
    }
    fn read<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let response = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let data = response.body().next().await.map_err(err)?;
            Ok(Python::attach(|py| {
                data.map(|data| bytes(py, data.to_vec()))
            }))
        })
    }
    fn trailers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let response = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let data = response.body().trailers().await.map_err(err)?;
            Ok(Python::attach(|py| fields(py, b::fields(&data))))
        })
    }
    fn cancel(&self) {
        self.inner.body().cancel();
    }
}
#[pyclass(frozen)]
pub struct NativeIncoming {
    inner: Arc<b::Incoming>,
}
#[pymethods]
impl NativeIncoming {
    fn local_authority(&self) -> PyResult<Authority> {
        b::Authority::local(self.inner.local_authority().map_err(err)?)
            .map(|inner| Authority { inner })
            .map_err(err)
    }
    fn sign<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let incoming = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let signature =
                b::sign_authority(incoming.local_authority().map_err(err)?, &data).map_err(err)?;
            Ok(Python::attach(|py| bytes(py, signature)))
        })
    }
    #[getter]
    fn method(&self) -> String {
        self.inner.request.method().to_string()
    }
    #[getter]
    fn url(&self) -> String {
        self.inner.request.uri().to_string()
    }
    #[getter]
    fn headers(&self, py: Python<'_>) -> Vec<(String, Py<PyBytes>)> {
        fields(py, b::fields(self.inner.request.headers()))
    }
    fn authority(&self) -> PyResult<Option<Authority>> {
        self.inner
            .request
            .extensions()
            .get::<dhttp::HandshakeSummary>()
            .and_then(|h| h.remote.as_ref())
            .map(b::Authority::remote)
            .transpose()
            .map(|a| a.map(|inner| Authority { inner }))
            .map_err(err)
    }
    fn read<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let incoming = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let data = incoming.request.body().next().await.map_err(err)?;
            Ok(Python::attach(|py| {
                data.map(|data| bytes(py, data.to_vec()))
            }))
        })
    }
    fn trailers<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let incoming = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            let data = incoming.request.body().trailers().await.map_err(err)?;
            Ok(Python::attach(|py| fields(py, b::fields(&data))))
        })
    }
    fn cancel(&self) {
        self.inner.request.body().cancel();
    }
    fn closed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let incoming = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            incoming.request.body().closed().await;
            Ok(())
        })
    }
    fn respond(&self, status: u16, headers: b::Fields) -> PyResult<NativeUpload> {
        self.inner
            .respond(status, headers)
            .map(|inner| NativeUpload {
                inner: Arc::new(inner),
            })
            .map_err(err)
    }
}
#[pyclass(frozen)]
pub struct NativeUpload {
    inner: Arc<crate::UploadWriter>,
}
#[pymethods]
impl NativeUpload {
    fn write<'py>(&self, py: Python<'py>, data: Vec<u8>) -> PyResult<Bound<'py, PyAny>> {
        let upload = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            upload.send(data).await.map_err(err)
        })
    }
    fn finish<'py>(&self, py: Python<'py>, trailers: b::Fields) -> PyResult<Bound<'py, PyAny>> {
        let upload = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            upload
                .finish(b::headers(trailers).map_err(err)?)
                .await
                .map_err(err)
        })
    }
    fn fail(&self, message: String) {
        self.inner.fail(Error::new(ErrorCode::Producer, message));
    }
    fn closed<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let upload = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            upload.closed().await;
            Ok(())
        })
    }
}
#[pyclass(frozen)]
pub struct NativeListener {
    inner: crate::Listener,
}
#[pymethods]
impl NativeListener {
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let listener = self.inner.clone();
        pyo3_async_runtimes::tokio::future_into_py(py, async move {
            listener.close().await;
            Ok(())
        })
    }
}

#[pymodule]
fn _native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(init, module)?)?;
    module.add_function(wrap_pyfunction!(addresses, module)?)?;
    module.add_function(wrap_pyfunction!(verify_signature, module)?)?;
    module.add_class::<NativeClient>()?;
    module.add_class::<NativeExchange>()?;
    module.add_class::<NativeResponse>()?;
    module.add_class::<NativeIncoming>()?;
    module.add_class::<NativeUpload>()?;
    module.add_class::<NativeListener>()?;
    module.add_class::<Authority>()?;
    Ok(())
}

#[pyfunction]
fn verify_signature(public_key: Vec<u8>, data: Vec<u8>, signature: Vec<u8>) -> PyResult<bool> {
    b::verify(public_key, data, signature).map_err(err)
}
