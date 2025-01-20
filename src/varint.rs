use anyhow::bail;
use iroh::endpoint::VarInt;
use tokio_util::bytes::{Buf, BufMut};

/// Decode varint
pub fn decode<B: Buf>(r: &mut B) -> anyhow::Result<VarInt> {
    if !r.has_remaining() {
        bail!("unexpected end");
    }
    let mut buf = [0; 8];
    buf[0] = r.get_u8();
    let tag = buf[0] >> 6;
    buf[0] &= 0b0011_1111;
    let x = match dbg!(tag) {
        0b00 => u64::from(buf[0]),
        0b01 => {
            if r.remaining() < 1 {
                bail!("unexpected end");
            }
            r.copy_to_slice(&mut buf[1..2]);
            u64::from(u16::from_be_bytes(buf[..2].try_into().unwrap()))
        }
        0b10 => {
            if r.remaining() < 3 {
                bail!("unexpected end");
            }
            r.copy_to_slice(&mut buf[1..4]);
            u64::from(u32::from_be_bytes(buf[..4].try_into().unwrap()))
        }
        0b11 => {
            if r.remaining() < 7 {
                bail!("unexpected end");
            }
            r.copy_to_slice(&mut buf[1..8]);
            u64::from_be_bytes(buf)
        }
        _ => unreachable!(),
    };

    let x = VarInt::from_u64(x)?;
    Ok(x)
}

/// Encode a varint into the given buffer
pub fn encode<B: BufMut>(n: VarInt, w: &mut B) {
    let x = n.into_inner();
    if x < 2u64.pow(6) {
        w.put_u8(x as u8);
    } else if x < 2u64.pow(14) {
        w.put_u16(0b01 << 14 | x as u16);
    } else if x < 2u64.pow(30) {
        w.put_u32(0b10 << 30 | x as u32);
    } else if x < 2u64.pow(62) {
        w.put_u64(0b11 << 62 | x);
    } else {
        unreachable!("malformed VarInt")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        for i in [0u64, 100u64, 433333u64, VarInt::MAX.into_inner()] {
            let mut buf = Vec::new();
            let x = VarInt::from_u64(i).unwrap();
            encode(x, &mut buf);
            let back = decode(&mut &buf[..]).unwrap();
            assert_eq!(x, back);
        }
    }
}
