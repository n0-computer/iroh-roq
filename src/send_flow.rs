use std::{
    future::Future,
    pin::pin,
    task::{Context, Poll, Waker},
};

use anyhow::{bail, ensure, Result};
use bytes::BytesMut;
use iroh::endpoint::{Connection, SendDatagramError, VarInt};
use noq_proto::coding::Encodable;
use rtp::packet::Packet as RtpPacket;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use webrtc_util::marshal::{Marshal, MarshalSize};

use crate::SendStream;

fn poll_once<F: Future>(fut: F) -> Option<F::Output> {
    let mut fut = pin!(fut);
    let waker = Waker::noop();
    match fut.as_mut().poll(&mut Context::from_waker(waker)) {
        Poll::Ready(v) => Some(v),
        Poll::Pending => None,
    }
}

/// The sending side of an RTP flow.
#[derive(Clone, Debug)]
pub struct SendFlow {
    id: VarInt,
    conn: Connection,
    cancel_token: CancellationToken,
}

impl SendFlow {
    pub(crate) fn new(conn: Connection, id: VarInt, cancel_token: CancellationToken) -> Self {
        Self {
            id,
            conn,
            cancel_token,
        }
    }

    /// Returns the flow ID for this `SendFlow`.
    pub fn flow_id(&self) -> VarInt {
        self.id
    }

    /// Maximum QUIC datagram payload size currently advertised for this connection.
    pub fn max_datagram_size(&self) -> Option<usize> {
        self.conn.max_datagram_size()
    }

    fn ensure_datagram_fits(&self, len: usize) -> Result<()> {
        match self.conn.max_datagram_size() {
            Some(limit) if len > limit => {
                bail!("datagram TooLarge: need {len}, max_datagram_size {limit}");
            }
            None => bail!("datagrams unsupported or disabled"),
            Some(_) => Ok(()),
        }
    }

    fn map_send_err(err: SendDatagramError) -> anyhow::Error {
        match err {
            SendDatagramError::TooLarge => {
                anyhow::anyhow!("datagram TooLarge: exceeds peer max_datagram_size")
            }
            other => other.into(),
        }
    }

    /// Send the given RTP packet.
    ///
    /// This will use the datagram based path.
    pub fn send_rtp(&self, packet: &RtpPacket) -> Result<()> {
        ensure!(!self.cancel_token.is_cancelled(), "flow is closed");

        debug!(flow_id = %self.id, "send datagram RTP packet");

        let mut buf = BytesMut::new();
        self.id.encode(&mut buf);
        let marshal_size = packet.marshal_size();
        let id_len = buf.len();
        buf.resize(id_len + marshal_size, 0);
        let n = packet.marshal_to(&mut buf[id_len..])?;
        ensure!(n == marshal_size, "inconsistent packet marshal");

        self.ensure_datagram_fits(buf.len())?;
        self.conn
            .send_datagram(buf.freeze())
            .map_err(Self::map_send_err)?;

        Ok(())
    }

    /// Send an RTP packet, waiting for datagram buffer space if needed.
    ///
    /// Prefer this for bursty media tests. Live media should use
    /// [`Self::try_send_payload`] (drop on congestion — late audio is worse than loss).
    pub async fn send_rtp_wait(&self, packet: &RtpPacket) -> Result<()> {
        ensure!(!self.cancel_token.is_cancelled(), "flow is closed");

        debug!(flow_id = %self.id, "send datagram RTP packet (wait)");

        let mut buf = BytesMut::new();
        self.id.encode(&mut buf);
        let marshal_size = packet.marshal_size();
        let id_len = buf.len();
        buf.resize(id_len + marshal_size, 0);
        let n = packet.marshal_to(&mut buf[id_len..])?;
        ensure!(n == marshal_size, "inconsistent packet marshal");

        self.ensure_datagram_fits(buf.len())?;
        self.conn
            .send_datagram_wait(buf.freeze())
            .await
            .map_err(Self::map_send_err)?;

        Ok(())
    }

    /// Non-blocking send of an opaque payload after the flow id.
    ///
    /// Returns `Ok(true)` if the datagram was queued, `Ok(false)` if the send
    /// buffer is full (this packet was **not** queued — caller should count a
    /// drop). Unlike [`Self::send_rtp`], this does not discard older queued
    /// datagrams to make space.
    ///
    /// Oversized payloads return an error containing `TooLarge` (checked against
    /// [`Self::max_datagram_size`] when known, else via the connection).
    pub fn try_send_payload(&self, payload: &[u8]) -> Result<bool> {
        ensure!(!self.cancel_token.is_cancelled(), "flow is closed");
        debug!(flow_id = %self.id, len = payload.len(), "try send datagram payload");

        let mut buf = BytesMut::new();
        self.id.encode(&mut buf);
        buf.extend_from_slice(payload);
        self.ensure_datagram_fits(buf.len())?;

        let data = buf.freeze();
        let fut = self.conn.send_datagram_wait(data);
        match poll_once(fut) {
            Some(Ok(())) => Ok(true),
            Some(Err(e)) => Err(Self::map_send_err(e)),
            None => Ok(false),
        }
    }

    /// Creates a new `SendStream`.
    ///
    /// This will use the stream based path.
    pub async fn new_send_stream(&self) -> Result<SendStream> {
        ensure!(!self.cancel_token.is_cancelled(), "flow is closed");

        let stream = self.conn.open_uni().await?;

        debug!(flow_id = %self.id, "opened send stream");

        Ok(SendStream::new(
            self.id,
            stream,
            self.cancel_token.child_token(),
        ))
    }

    /// Close this flow
    pub fn close(&self) {
        self.cancel_token.cancel();
    }

    /// Is this flow closed?
    pub fn is_closed(&self) -> bool {
        self.cancel_token.is_cancelled()
    }
}
