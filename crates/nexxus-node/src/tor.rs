//! Tor transport via arti-client (ADR-0006).
//! Feature `tor` включён по умолчанию (`default = ["tor"]`); демон bootstrap'ит
//! arti-клиент, публикует onion v3 hidden service на P2P-порту и умеет диалить
//! чужие `.onion` адреса. NEXXUS_TOR=0 выключает Tor на рантайме.

#[cfg(feature = "tor")]
mod imp {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use arti_client::TorClient;
    use futures_util::StreamExt;
    use safelog::DisplayRedacted;
    use tor_rtcompat::PreferredRuntime as TokioRuntime;

    type TorClientType = TorClient<TokioRuntime>;

    fn io_err(e: impl std::fmt::Display) -> std::io::Error {
        std::io::Error::other(format!("{e}"))
    }

    /// Tor-сессия: bootstrapped arti-клиент + опубликованный onion v3 сервис.
    pub struct TorSession {
        client: Arc<TorClientType>,
        our_onion: Option<String>,
        /// F3: второй onion v3 сервис на локальный API-порт (NEXXUS_API_ONION=1).
        api_onion: Option<String>,
    }

    impl TorSession {
        /// Bootstrap Tor-клиента; state/cache живут в ~/.nexxus/tor.
        pub async fn new() -> std::io::Result<Self> {
            let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
            let base = std::path::Path::new(&home).join(".nexxus").join("tor");
            std::fs::create_dir_all(&base)?;
            let config = arti_client::config::TorClientConfigBuilder::from_directories(
                base.join("state"),
                base.join("cache"),
            )
            .build()
            .map_err(io_err)?;
            let client = TorClient::create_bootstrapped(config)
                .await
                .map_err(io_err)?;
            Ok(Self {
                client,
                our_onion: None,
                api_onion: None,
            })
        }

        /// Опубликовать onion v3 hidden service, форвардящий на локальный порт.
        /// Возвращает адрес вида `<56 base32>.onion`.
        pub async fn publish_onion(&mut self, local_addr: SocketAddr) -> std::io::Result<String> {
            self.publish_onion_as(local_addr, None, "nexxus").await
        }

        /// Опубликовать главный onion-сервис с маршрутизацией по виртуальному
        /// порту: порт API (если Some) форвардится на `api_addr`, все остальные
        /// порты — на P2P `p2p_addr`. В Tor v3 порты не входят в адрес сервиса
        /// и не требуют перезагрузки дескриптора, поэтому один и тот же onion
        /// может сразу раздавать и P2P (4001), и WS-API (4010).
        pub async fn publish_onion_with_api(
            &mut self,
            p2p_addr: SocketAddr,
            api_addr: Option<SocketAddr>,
        ) -> std::io::Result<String> {
            self.publish_onion_as(p2p_addr, api_addr, "nexxus").await
        }

        /// То же с произвольным nickname сервиса (нужен второй сервис для API).
        pub async fn publish_onion_as(
            &mut self,
            local_addr: SocketAddr,
            api_addr: Option<SocketAddr>,
            nickname: &str,
        ) -> std::io::Result<String> {
            if nickname.is_empty() || nickname.len() > 16 || !nickname.chars().all(|c| c.is_ascii_alphanumeric()) {
                return Err(io_err("onion nickname must be 1-16 ascii alnum"));
            }
            let svc_cfg = tor_hsservice::config::OnionServiceConfigBuilder::default()
                .nickname(
                    tor_hsservice::HsNickname::new(nickname.to_string()).map_err(io_err)?,
                )
                .build()
                .map_err(io_err)?;
            let launched = self.client.launch_onion_service(svc_cfg).map_err(io_err)?;
            let (running, requests) =
                launched.ok_or_else(|| io_err("onion service disabled in config"))?;
            let onion = running
                .onion_address()
                .ok_or_else(|| io_err("onion service has no address"))?
                .display_unredacted()
                .to_string();
            // Accept loop: входящие onion-стримы форвардим на локальный порт.
            // При включённом API (api_addr = Some) виртуальный порт API идёт на
            // WS-API, все остальные — на P2P. Порты не меняют адрес сервиса.
            // Задача держит Arc сервиса, пока жива TorSession.
            tokio::spawn(async move {
                let mut requests = tor_hsservice::handle_rend_requests(requests);
                while let Some(sr) = requests.next().await {
                    tokio::spawn(async move {
                        let requested_port = match sr.request() {
                            tor_proto::stream::IncomingStreamRequest::Begin(b) => Some(b.port()),
                            _ => None,
                        };
                        let target = match (api_addr, requested_port) {
                            (Some(api), Some(p)) if p == api.port() => api,
                            _ => local_addr,
                        };
                        // Ошибки раньше проглатывались через `if let Ok(..)`, из-за
                        // чего клиент получал END/MISC без единой записи в логе.
                        // Теперь каждая ветка логируется.
                        match sr.accept(tor_cell::relaycell::msg::Connected::new_empty()).await {
                            Ok(mut onion_stream) => {
                                match tokio::net::TcpStream::connect(target).await {
                                    Ok(mut local) => {
                                        let _ = tokio::io::copy_bidirectional(
                                            &mut onion_stream,
                                            &mut local,
                                        )
                                        .await;
                                    }
                                    Err(e) => {
                                        eprintln!(
                                            "nexxusd: onion forward failed: connect {target}: {e}"
                                        );
                                    }
                                }
                            }
                            Err(e) => {
                                eprintln!("nexxusd: onion accept failed: {e}");
                            }
                        }
                    });
                }
                drop(running);
            });
            self.our_onion = Some(onion.clone());
            Ok(onion)
        }

        /// F3: опубликовать второй onion v3 сервис на локальный API-порт
        /// (только при NEXXUS_API_ONION=1 — API наружу по умолчанию закрыт).
        pub async fn publish_api_onion(&mut self, api_addr: SocketAddr) -> std::io::Result<String> {
            let onion = self.publish_onion_as(api_addr, None, "nexxusapi").await?;
            self.api_onion = Some(onion.clone());
            Ok(onion)
        }

        /// Подключиться к onion v3 адресу (например, "<id>.onion:4001").
        /// Используется в `P2pNetwork::dial_onion` для P2P-соединений через Tor.
        pub async fn connect_onion(
            &self,
            onion_addr: &str,
        ) -> std::io::Result<arti_client::DataStream> {
            self.client.connect(onion_addr).await.map_err(io_err)
        }

        /// Наш onion v3 адрес, если сервис опубликован.
        pub fn our_onion(&self) -> Option<&str> {
            self.our_onion.as_deref()
        }

        /// F3: onion v3 адрес API-сервиса, если опубликован.
        pub fn api_onion(&self) -> Option<&str> {
            self.api_onion.as_deref()
        }
    }
}

#[cfg(feature = "tor")]
pub use imp::TorSession;

#[cfg(all(test, feature = "tor"))]
mod tor_integration {
    //! E5: opt-in integration test — реальный bootstrap arti и публикация
    //! onion v3 сервиса. Не входит в обычный `cargo test` (#[ignore]),
    //! гоняется отдельным CI job: `cargo test -p nexxus-node --features tor -- --ignored`.
    use super::*;

    #[tokio::test]
    #[ignore = "требует сети Tor; запускается только в CI job tor-integration"]
    async fn bootstrap_and_publish_onion_v3() {
        let mut sess = TorSession::new().await.expect("tor bootstrap");
        let onion = sess
            .publish_onion("127.0.0.1:4001".parse().unwrap())
            .await
            .expect("publish onion");
        assert!(onion.ends_with(".onion"), "bad onion addr: {onion}");
        assert_eq!(onion.len(), 56 + 6, "v3 onion = 56 base32 + .onion");
        assert_eq!(sess.our_onion(), Some(onion.as_str()));
    }
}
