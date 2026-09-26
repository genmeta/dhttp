impl Endpoint {
    pub async fn load(name: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            name: Arc::from(dhttp_home::normalize_name(name.as_ref()).ok_or_else(|| {
                Error::InvalidName {
                    name: name.as_ref().to_owned(),
                }
            })?),
        })
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn get(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::GET, uri)
    }
    pub fn head(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::HEAD, uri)
    }
    pub fn post(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::POST, uri)
    }
    pub fn put(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::PUT, uri)
    }
    pub fn patch(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::PATCH, uri)
    }
    pub fn delete(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::DELETE, uri)
    }
    pub fn options(&self, uri: http::Uri) -> Request<EmptyBody> {
        self.request(http::Method::OPTIONS, uri)
    }
    pub fn request(&self, method: http::Method, uri: http::Uri) -> Request<EmptyBody> {
        let mut message = http::Request::new(EmptyBody::new());
        *message.method_mut() = method;
        *message.uri_mut() = uri;
        self.from_request(message)
    }
    pub fn from_request<B>(&self, request: http::Request<B>) -> Request<B> {
        Request {
            endpoint: self.clone(),
            message: request,
        }
    }

    pub async fn listen<S, B>(&self, scopes: Scopes, service: S) -> Result<()>
    where
        S: tower_service::Service<http::Request<Body>, Response = http::Response<B>>
            + Clone
            + Send
            + 'static,
        S::Future: Send + 'static,
        S::Error: Into<BoxError>,
        B: http_body::Body<Data = Bytes> + Send + 'static,
        B::Error: Into<BoxError>,
    {
        let network = DhttpNetwork::global()?;
        for scope in [Scope::Loopback, Scope::Internal, Scope::External] {
            if scopes.contains(scope)
                && !network.config.listen.iter().any(|rule| match rule {
                    ListenConfig::Scope(allowed)
                    | ListenConfig::Interface {
                        scopes: allowed, ..
                    } => allowed.contains(scope),
                })
            {
                return Err(Error::InvalidNetworkConfig {
                    message:
                        "listener scope exceeds startup network configuration; restart is required"
                            .into(),
                });
            }
        }
        let quic = quic_endpoint(&self.name).await?;
        let (lifetime, dropped) = tokio::sync::oneshot::channel::<()>();
        let owner = endpoint_connections(network, &self.name);
        let stop = owner.stop.child_token();
        let (accepted, receiving) = tokio::sync::mpsc::channel(ACCEPT_QUEUE_CAPACITY);
        let service = service
            .map_err(Into::into)
            .map_response(|response| response.map(|body| body.map_err(Into::into).boxed_unsync()))
            .boxed_clone();
        let supervisor = {
            let _connections = owner.connections.lock().unwrap();
            let mut listeners = network.listeners.lock().unwrap();
            check_open(network, &owner)?;
            if listeners.contains_key(&self.name) {
                return Err(Error::AlreadyListening);
            }
            if qconn::ServerRegistry::global().get(&self.name).is_some() {
                return Err(Error::NameInUse {
                    name: self.name.to_string(),
                });
            }
            let callback_stop = stop.clone();
            let callback_owner = owner.clone();
            let callback_name = self.name.clone();
            quic.listen(scopes, move |result| {
                // Capture the actual identity and listening lifetime at registration time.
                let _connections = callback_owner.connections.lock().unwrap();
                let listeners = network.listeners.lock().unwrap();
                if callback_stop.is_cancelled()
                    || check_open(network, &callback_owner).is_err()
                    || !listeners.contains_key(&callback_name)
                {
                    if let Ok((_, _, connection)) = result {
                        connection.close(qbase::varint::VarInt::from_u32(0), "listener stopped");
                    }
                    return;
                }
                if let Err(rejected) = accepted.try_send(result) {
                    if let Ok((_, _, connection)) = rejected.into_inner() {
                        connection.close(
                            qbase::varint::VarInt::from_u32(0),
                            "accept queue unavailable",
                        );
                    }
                }
            })
            .map_err(quic_error)?;
            let qconn_owner = qconn::ServerRegistry::global()
                .get(&self.name)
                .ok_or(Error::NetworkUnavailable)?;
            let registration = Arc::new(ListenerRegistration {
                service: Mutex::new(service),
                stop,
                qconn_owner,
            });
            listeners.insert(self.name.clone(), registration.clone());
            tokio::spawn(listen_supervisor(
                network,
                self.name.clone(),
                owner.clone(),
                registration,
                receiving,
                dropped,
            ))
        };
        // This Sender must stay alive across the await. Dropping the public future
        // closes the channel, leaving the supervisor responsible for withdrawal.
        let result = supervisor.await.map_err(io_error)?;
        drop(lifetime);
        result
    }

    pub fn stop_listening(&self) -> Result<()> {
        let network = DhttpNetwork::global()?;
        let owner = endpoint_connections(network, &self.name);
        let _connections = owner.connections.lock().unwrap();
        let mut listeners = network.listeners.lock().unwrap();
        if let Some(registration) = listeners.remove(&self.name) {
            registration.stop.cancel();
            withdraw_listener(&self.name, &registration);
        }
        Ok(())
    }

    pub fn close(&self) -> Result<()> {
        let network = DhttpNetwork::global()?;
        close_endpoint(network, &self.name)
    }
}
