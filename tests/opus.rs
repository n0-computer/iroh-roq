use anyhow::Result;
use iroh::Endpoint;
use rtp::packet::Packet as RtpPacket;

use iroh_roq::{Session, VarInt, ALPN};
use tokio_util::bytes::BytesMut;

// 48000Hz * 1 channel * 20 ms / 1000 = 960
const MONO_20MS: usize = 48000 * 20 / 1000;

/// Sanity checks to make sure opus works as expected
#[test]
fn test_opus_decode_encode() -> Result<()> {
    let mut opus_encoder =
        opus::Encoder::new(48000, opus::Channels::Stereo, opus::Application::Voip).unwrap();
    let mut opus_decoder = opus::Decoder::new(48000, opus::Channels::Stereo).unwrap();
    let mut pcm_raw_data = vec![17_i16; MONO_20MS * 2];
    pcm_raw_data[1] = 1;

    let mut encoded_opus = vec![0; 1500];
    let size = opus_encoder
        .encode(&pcm_raw_data, &mut encoded_opus)
        .unwrap();
    let packet = &encoded_opus[..size];

    let mut output = vec![0i16; MONO_20MS * 2];
    // decode() returns the number of samples per channel.
    assert_eq!(
        MONO_20MS,
        opus_decoder.decode(packet, &mut output, false).unwrap()
    );

    Ok(())
}

#[tokio::test]
async fn test_stream_opus_packets() -> Result<()> {
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

    let _handle = tokio::task::spawn(async move {
        while let Some(incoming) = ep2.accept().await {
            if let Ok(connection) = incoming.await {
                assert_eq!(connection.alpn().unwrap(), ALPN, "invalid ALPN");

                let session = Session::new(connection);
                let send_flow = session.new_send_flow(flow_id).await.unwrap();
                let mut recv_flow = session.new_receive_flow(flow_id).await.unwrap();

                let mut opus_decoder = opus::Decoder::new(48000, opus::Channels::Stereo).unwrap();
                let mut output = vec![0i16; MONO_20MS * 2];

                // echo
                while let Ok(packet) = recv_flow.read_rtp().await {
                    println!("received packet: {:?}", packet);
                    // decode() returns the number of samples per channel.
                    assert_eq!(
                        MONO_20MS,
                        opus_decoder
                            .decode(&packet.payload, &mut output, false)
                            .unwrap()
                    );

                    send_flow.send_rtp(&packet).unwrap();
                }
            }
        }
    });

    let conn = ep1.connect(ep2_addr, ALPN).await?;

    let session = Session::new(conn.clone());
    let send_flow = session.new_send_flow(flow_id).await.unwrap();
    let mut recv_flow = session.new_receive_flow(flow_id).await.unwrap();

    let mut opus_encoder =
        opus::Encoder::new(48000, opus::Channels::Stereo, opus::Application::Voip).unwrap();

    let num_chunks = 8;

    let chunk_size = MONO_20MS * 2;
    let mut pcm_raw_data = vec![17_i16; chunk_size * num_chunks];

    for num_chunk in 0..num_chunks {
        // TODO: reuse buffer
        let mut payload = BytesMut::zeroed(1500);

        let start = num_chunk * chunk_size;
        let end = start + chunk_size;
        pcm_raw_data[start + 1] = 1;
        let size = opus_encoder
            .encode(&pcm_raw_data[start..end], &mut payload[..])
            .unwrap();

        payload.truncate(size);

        let header = rtp::header::Header {
            sequence_number: num_chunk as _,
            // TODO: figure out what this should be
            timestamp: 0,
            // The standard format of the fixed RTP data header is used (one marker bit).
            marker: true,
            ..Default::default()
        };

        let packet = RtpPacket {
            header,
            payload: payload.freeze(),
        };

        println!("sending {:?}", packet);
        send_flow.send_rtp(&packet)?;
        let incoming = recv_flow.read_rtp().await?;

        println!("received packet");
        assert_eq!(packet, incoming);
    }

    _handle.abort();

    Ok(())
}
