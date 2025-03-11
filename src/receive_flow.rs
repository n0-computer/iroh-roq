use anyhow::{ensure, Result};
use iroh_quinn_proto::VarInt;
use rtp::packet::Packet as RtpPacket;
use tokio::sync::mpsc;
use tokio_util::{bytes::Bytes, sync::CancellationToken};
use tracing::debug;
use webrtc_util::Unmarshal;

/// The receiving side of an RTP flow.
#[derive(Debug)]
pub struct ReceiveFlow {
    id: VarInt,
    cancel_token: CancellationToken,
    datagram_receiver: mpsc::Receiver<Option<Bytes>>,
}

impl ReceiveFlow {
    pub(crate) fn new(
        id: VarInt,
        receiver: mpsc::Receiver<Option<Bytes>>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            id,
            datagram_receiver: receiver,
            cancel_token,
        }
    }

    /// Returns the flow ID for this `ReceiveFlow`.
    pub fn flow_id(&self) -> VarInt {
        self.id
    }

    /// Reads the next available RTP packet.
    pub async fn read_rtp(&mut self) -> Result<RtpPacket> {
        ensure!(!self.cancel_token.is_cancelled(), "closed");
        let Some(Some(mut bytes)) = self.datagram_receiver.recv().await else {
            return Err(anyhow::anyhow!("session is closed"));
        };

        let packet = RtpPacket::unmarshal(&mut bytes)?;

        debug!(flow_id = %self.id, "received packet");

        Ok(packet)
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
