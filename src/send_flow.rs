use anyhow::{ensure, Result};
use iroh::endpoint::Connection;
use iroh_quinn_proto::coding::Codec;
use iroh_quinn_proto::VarInt;
use rtp::packet::Packet as RtpPacket;
use tokio_util::bytes::BytesMut;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use webrtc_util::marshal::{Marshal, MarshalSize};

use crate::SendStream;

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

        self.conn.send_datagram(buf.freeze())?;

        Ok(())
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
