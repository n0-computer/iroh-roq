use anyhow::{ensure, Result};
use iroh_quinn_proto::coding::Codec;
use iroh_quinn_proto::VarInt;
use rtp::packet::Packet as RtpPacket;
use tokio_util::bytes::BytesMut;
use tokio_util::sync::CancellationToken;
use tracing::debug;
use webrtc_util::marshal::{Marshal, MarshalSize};

/// Manages sending on a specific send flow.
#[derive(Debug)]
pub struct SendStream {
    id: VarInt,
    stream: iroh::endpoint::SendStream,
    cancel_token: CancellationToken,
    /// Did we already send the flow id?
    /// This gets sent as the very first message, but we do this lazily
    /// when sending out the first acutal packet.
    sent_flow_id: bool,
}

impl SendStream {
    pub(crate) fn new(
        id: VarInt,
        stream: iroh::endpoint::SendStream,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            id,
            stream,
            cancel_token,
            sent_flow_id: false,
        }
    }

    /// Returns the flow ID for this `SendStream`.
    pub fn flow_id(&self) -> VarInt {
        self.id
    }

    /// Send an RTP packet on this flow.
    pub async fn send_rtp(&mut self, packet: &RtpPacket) -> Result<()> {
        ensure!(!self.cancel_token.is_cancelled(), "send stream is closed");
        debug!(flow_id = %self.id, "send stream RTP packet");

        let mut buf = BytesMut::new();

        if !self.sent_flow_id {
            // send the flow ID for the first packet
            self.id.encode(&mut buf);
            self.sent_flow_id = true;
        }

        // packets are prefixed with their length as varint
        let marshal_size = packet.marshal_size();
        let packet_size = VarInt::try_from(marshal_size)?;
        packet_size.encode(&mut buf);

        // the actual packet
        let existing_len = buf.len();
        buf.resize(existing_len + marshal_size, 0);
        let n = packet.marshal_to(&mut buf[existing_len..])?;
        ensure!(n == marshal_size, "inconsistent packet marshal");

        self.stream.write_all(&buf[..]).await?;

        Ok(())
    }

    /// Close this send stream.
    pub fn close(&self) {
        self.cancel_token.cancel();
    }

    /// Is this send stream closed?
    pub fn is_closed(&self) -> bool {
        self.cancel_token.is_cancelled()
    }
}
