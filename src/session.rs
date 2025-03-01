use std::{collections::HashMap, sync::Arc};

use anyhow::{bail, Result};
use iroh::endpoint::{Connection, VarInt};
use iroh_quinn_proto::coding::Codec;
use n0_future::task::{self, AbortOnDropHandle, JoinSet};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    sync::{mpsc, Mutex},
};
use tokio_util::{
    bytes::{Bytes, BytesMut},
    sync::CancellationToken,
};
use tracing::{debug, error, trace, warn};

use crate::{receive_flow::ReceiveFlow, send_flow::SendFlow};

/// A RoQ session.
#[derive(Debug, Clone)]
pub struct Session {
    conn: Connection,
    cancel_token: CancellationToken,
    send_flows: Arc<Mutex<HashMap<VarInt, SendFlow>>>,
    receive_flows: Arc<Mutex<HashMap<VarInt, ReceiveFlowSender>>>,
    _task: Arc<AbortOnDropHandle<()>>,
}

#[derive(Debug)]
struct ReceiveFlowSender {
    sender: mpsc::Sender<Bytes>,
    /// Set to `Some` if this is a discovered flow.
    incoming_flow: Option<ReceiveFlow>,
    cancel_token: CancellationToken,
}

/// Buffer size of the receive flow channel.
const RECV_FLOW_BUFFER: usize = 64;

impl Session {
    /// Creates a new session, based on an existing `Connection`.
    pub fn new(conn: Connection) -> Self {
        let receive_flows = Arc::new(Mutex::new(HashMap::new()));
        let cancel_token = CancellationToken::new();
        let fut = run(conn.clone(), cancel_token.clone(), receive_flows.clone());
        let task = AbortOnDropHandle::new(task::spawn(fut));

        Self {
            conn,
            cancel_token,
            send_flows: Default::default(),
            receive_flows,
            _task: Arc::new(task),
        }
    }

    /// Create a new `SendFlow`.
    pub async fn new_send_flow(&self, id: VarInt) -> Result<SendFlow> {
        let mut send_flows = self.send_flows.lock().await;
        if send_flows.contains_key(&id) {
            bail!("duplicated flow ID: {}", id);
        }

        let flow = SendFlow::new(self.conn.clone(), id, self.cancel_token.child_token());
        send_flows.insert(id, flow.clone());

        Ok(flow)
    }

    /// Creates a new receive flow.
    ///
    /// If a message has already been received on a flow will return that flow.
    pub async fn new_receive_flow(&self, id: VarInt) -> Result<ReceiveFlow> {
        let mut receive_flows = self.receive_flows.lock().await;
        if let Some(flow) = receive_flows.get_mut(&id) {
            if let Some(receiver) = flow.incoming_flow.take() {
                debug!(flow_id = %id, "found incoming flow");
                return Ok(receiver);
            } else {
                bail!("duplicated flow ID: {}", id);
            }
        }

        let (s, r) = mpsc::channel(RECV_FLOW_BUFFER);
        let cancel_token = self.cancel_token.child_token();
        let flow = ReceiveFlow::new(id, r, cancel_token.clone());
        receive_flows.insert(
            id,
            ReceiveFlowSender {
                sender: s,
                incoming_flow: None,
                cancel_token,
            },
        );

        Ok(flow)
    }
}

async fn run(
    conn: Connection,
    cancel_token: CancellationToken,
    receive_flows: Arc<Mutex<HashMap<VarInt, ReceiveFlowSender>>>,
) {
    let mut tasks = JoinSet::new();

    loop {
        tokio::select! {
            biased;

            _ = cancel_token.cancelled() => {
                debug!("shutting down");
                break;
            }
            Some(res) = tasks.join_next() => {
                match res {
                    Err(outer) => {
                        if outer.is_panic() {
                            error!("Task panicked: {outer:?}");
                            break;
                        } else if outer.is_cancelled() {
                            trace!("Task cancelled: {outer:?}");
                        } else {
                            error!("Task failed: {outer:?}");
                            break;
                        }
                    }
                    Ok(()) => {
                        trace!("Task finished");
                    }
                }
            },

            uni_stream = conn.accept_uni() => {
                match uni_stream {
                    Ok(mut recv) =>  {
                        let token = cancel_token.child_token();
                        let rf = receive_flows.clone();
                        tasks.spawn(async move {
                            let sub_token = token.child_token();
                            token.run_until_cancelled(async move {
                                // Read flow id
                                let Ok(flow_id) = read_varint(&mut recv).await else {
                                    warn!("failed to read from stream");
                                    return;
                                };
                                debug!(%flow_id, "incoming send flow");

                                let mut flows = rf.lock().await;
                                let sender = if let Some(flow) = flows.get(&flow_id) {
                                    debug!(%flow_id, "found existing recv flow");
                                    if flow.cancel_token.is_cancelled() {
                                        flows.remove(&flow_id);
                                        debug!(%flow_id, "cleaning up closed recv flow");
                                        return;
                                    } else {
                                        flow.sender.clone()
                                    }
                                } else {
                                    // Store incoming flow to be retrieved by the user
                                    debug!(%flow_id, "creating new recv flow");
                                    let (s, r) = mpsc::channel(RECV_FLOW_BUFFER);
                                    let cancel_token = sub_token.child_token();
                                    let flow = ReceiveFlow::new(flow_id, r, cancel_token.clone());
                                    flows.insert(flow_id, ReceiveFlowSender {
                                        sender: s.clone(),
                                        incoming_flow: Some(flow),
                                        cancel_token,
                                    });
                                    s
                                };
                                drop(flows);

                                const MAX_PACKET_SIZE: u64 = 1024 * 1024 * 64; // TODO: what should this be?
                                loop {
                                    let len = match read_varint(&mut recv).await {
                                        Ok(len) => len.into_inner(),
                                        Err(err) => {
                                            warn!("failed to read: {:?}", err);
                                            break;
                                        }
                                    };
                                    if len > MAX_PACKET_SIZE {
                                        warn!("packet too large {}", len);
                                        break;
                                    }
                                    let mut buffer = BytesMut::zeroed(len as usize);
                                    match recv.read_exact(&mut buffer).await {
                                        Ok(()) => {
                                            sender.send(buffer.freeze()).await.ok();
                                        }
                                        Err(err) => {
                                            warn!("failed to read: {:?}", err);
                                            break;
                                        }
                                    }
                                }
                            }).await;
                        });
                    }
                    Err(err) => {
                        warn!("connection terminated: {:?}", err);
                        break;
                    }
                }
            }
            datagram = conn.read_datagram() => {
                // handle datagram
                match datagram {
                    Ok(mut bytes) => {
                        debug!("received datagram: {} bytes", bytes.len());
                        let Ok(flow_id) = VarInt::decode(&mut bytes) else {
                            warn!("invalid flow id");
                            continue;
                        };
                        let mut flows = receive_flows.lock().await;
                        if let Some(flow) = flows.get(&flow_id) {
                            debug!(%flow_id, "found existing recv flow");
                            if flow.cancel_token.is_cancelled() {

                                flows.remove(&flow_id);
                                debug!(%flow_id, "cleaning up closed recv flow");
                            } else if let Err(err) = flow.sender.send(bytes).await {
                                warn!(%flow_id, "failed to send to receiver: {:?}", err);
                            }
                        } else {
                            // Store incoming flow to be retrieved by the user
                            debug!(%flow_id, "creating new recv flow");
                            let (s, r) = mpsc::channel(RECV_FLOW_BUFFER);
                            let cancel_token = cancel_token.child_token();
                            let flow = ReceiveFlow::new(flow_id, r, cancel_token.clone());
                            // store the newly received datagram
                            s.send(bytes).await.expect("just created");
                            flows.insert(flow_id, ReceiveFlowSender {
                                sender: s,
                                incoming_flow: Some(flow),
                                cancel_token,
                            });
                        }
                    }
                    Err(err) => {
                        warn!("connection terminated: {:?}", err);
                        break;
                    }
                }
            }
        }
    }
}

/// Async read based reading of a `VarInt`.
async fn read_varint<R: AsyncRead + Unpin>(conn: &mut R) -> Result<VarInt> {
    let mut buf = [0u8; VarInt::MAX_SIZE];

    conn.read_exact(&mut buf[..1]).await?;
    let tag = buf[0] >> 6;
    buf[0] &= 0b0011_1111;

    let x = match tag {
        0b00 => u64::from(buf[0]),
        0b01 => {
            conn.read_exact(&mut buf[1..2]).await?;
            u64::from(u16::from_be_bytes(buf[..2].try_into().unwrap()))
        }
        0b10 => {
            conn.read_exact(&mut buf[1..4]).await?;
            u64::from(u32::from_be_bytes(buf[..4].try_into().unwrap()))
        }
        0b11 => {
            conn.read_exact(&mut buf[1..8]).await?;
            u64::from_be_bytes(buf)
        }
        _ => unreachable!(),
    };

    let x = VarInt::from_u64(x)?;
    Ok(x)
}

#[cfg(test)]
mod tests {
    use iroh::Endpoint;
    use rtp::packet::Packet as RtpPacket;

    use super::*;
    use crate::ALPN;

    #[tokio::test]
    async fn test_datagram_flow() -> Result<()> {
        let ep1 = Endpoint::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        let ep2 = Endpoint::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;

        let flow_id = VarInt::from_u32(0);

        let ep2_addr = ep2.node_addr().await?;

        let _handle = task::spawn(async move {
            while let Some(incoming) = ep2.accept().await {
                if let Ok(connection) = incoming.await {
                    assert_eq!(connection.alpn().unwrap(), ALPN, "invalid ALPN");

                    let session = Session::new(connection);
                    let send_flow = session.new_send_flow(flow_id).await.unwrap();
                    let mut recv_flow = session.new_receive_flow(flow_id).await.unwrap();

                    // echo
                    while let Ok(packet) = recv_flow.read_rtp().await {
                        send_flow.send_rtp(&packet).unwrap();
                    }
                }
            }
        });

        let conn = ep1.connect(ep2_addr, ALPN).await?;

        let session = Session::new(conn);
        let send_flow = session.new_send_flow(flow_id).await.unwrap();
        let mut recv_flow = session.new_receive_flow(flow_id).await.unwrap();

        for i in 0u8..10 {
            let packet = RtpPacket {
                header: rtp::header::Header::default(),
                payload: vec![i; 10].into(),
            };

            send_flow.send_rtp(&packet)?;
            let incoming = recv_flow.read_rtp().await?;
            assert_eq!(packet, incoming);
        }

        Ok(())
    }

    #[tokio::test]
    async fn test_session_flow() -> Result<()> {
        let ep1 = Endpoint::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;
        let ep2 = Endpoint::builder()
            .bind_addr_v4("127.0.0.1:0".parse().unwrap())
            .alpns(vec![ALPN.to_vec()])
            .bind()
            .await?;

        let flow_id = VarInt::from_u32(0);

        let ep2_addr = ep2.node_addr().await?;

        let _handle = task::spawn(async move {
            while let Some(incoming) = ep2.accept().await {
                if let Ok(connection) = incoming.await {
                    assert_eq!(connection.alpn().unwrap(), ALPN, "invalid ALPN");

                    let session = Session::new(connection);
                    let send_flow = session.new_send_flow(flow_id).await.unwrap();
                    let mut recv_flow = session.new_receive_flow(flow_id).await.unwrap();

                    // echo
                    while let Ok(packet) = recv_flow.read_rtp().await {
                        send_flow.send_rtp(&packet).unwrap();
                    }
                }
            }
        });

        let conn = ep1.connect(ep2_addr, ALPN).await?;

        let session = Session::new(conn);
        let send_flow = session.new_send_flow(flow_id).await.unwrap();
        let mut send_stream = send_flow.new_send_stream().await?;
        let mut recv_flow = session.new_receive_flow(flow_id).await.unwrap();

        for i in 0u8..10 {
            let packet = RtpPacket {
                header: rtp::header::Header::default(),
                payload: vec![i; 10].into(),
            };

            send_stream.send_rtp(&packet).await?;
            let incoming = recv_flow.read_rtp().await?;
            assert_eq!(packet, incoming);
        }

        Ok(())
    }
}
