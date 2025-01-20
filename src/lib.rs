use std::collections::BTreeMap;
use std::sync::Arc;

use anyhow::Result;
use async_channel::{Receiver, Sender};
use futures_lite::future::Boxed as BoxedFuture;
use iroh::endpoint::{Connection, VarInt};
use iroh::protocol::ProtocolHandler;
use rtp::packet::Packet as RtpPacket;
use tokio::sync::RwLock;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

/// The ALPN used.
pub const ALPN: &[u8] = b"/iroh/roq/1";

mod varint;

#[derive(Debug)]
pub struct Protocol {
    cancel_token: CancellationToken,
    sessions: RwLock<BTreeMap<VarInt, Session>>,
}

#[derive(Debug, Clone)]
pub struct Session {
    session_id: Option<VarInt>,
    cancel_token: CancellationToken,
    packet_buffer_reader: Receiver<RtpPacket>,
    packet_buffer_writer: Sender<RtpPacket>,
}

impl Session {
    async fn accept(&self, conn: Connection) -> Result<()> {
        let mut tasks = JoinSet::new();

        loop {
            tokio::select! {
                biased;

                _ = self.cancel_token.cancelled() => {
                    debug!("shutting down");
                    break;
                }
                res = tasks.join_next(), if !tasks.is_empty() => {
                    // TODO:
                }
                uni_stream = conn.accept_uni() => {
                    let token = self.cancel_token.child_token();
                    tasks.spawn(async move {
                        token.run_until_cancelled(async move {
                            // TODO: handle conn
                        }).await;
                    });
                }
                datagram = conn.read_datagram() => {
                    // handle datagram
                    match datagram {
                        Ok(mut bytes) => {
                            debug!("received datagram: {} bytes", bytes.len());
                            let Ok(flow_id) = varint::decode(&mut bytes) else {
                                warn!("invalid flow id");
                                continue;
                            };



                        }
                        Err(err) => {
                            warn!("failed to read datagram: {:?}", err);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

impl Protocol {
    pub fn new() -> Self {
        let cancel_token = CancellationToken::new();
        Self {
            cancel_token,
            sessions: Default::default(),
        }
    }
}

impl ProtocolHandler for Protocol {
    fn accept(self: Arc<Self>, conn: iroh::endpoint::Connecting) -> BoxedFuture<Result<()>> {
        Box::pin(async move {
            let conn = match conn.await {
                Ok(conn) => conn,
                Err(err) => {
                    debug!("failed to accept connection: {:?}", err);
                    return Ok(());
                }
            };
            let session = Session {
                cancel_token: self.cancel_token.child_token(),
            };
            self.sessions.write().await.push(session.clone());
            session.accept(conn).await?;

            Ok(())
        })
    }

    fn shutdown(self: Arc<Self>) -> BoxedFuture<()> {
        Box::pin(async move {
            self.cancel_token.cancel();
        })
    }
}
