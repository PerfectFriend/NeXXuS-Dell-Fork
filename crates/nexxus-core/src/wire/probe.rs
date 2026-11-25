//! Probe payloads (0x0E/0x0F) — измерение скорости канала между нодами.
//!
//! Probe: `bytes u32` — сколько байт вернуть.
//! ProbeResp: `bytes u32 || data` — эхо-данные (лимит 1 МиБ).

use crate::error::NexxusError;
use crate::wire::payloads::Payload;
use crate::wire::reader::{Reader, Writer};

/// Максимальный размер эхо-данных в ответе на Probe (1 МиБ).
pub const PROBE_MAX_BYTES: u32 = 1024 * 1024;

/// Probe (0x0E): запрос на эхо N байт для замера скорости.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Probe {
    pub bytes: u32,
}

impl Payload for Probe {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(self.bytes.min(PROBE_MAX_BYTES));
        w.buf
    }

    fn decode(payload: &[u8]) -> Result<Self, NexxusError> {
        let mut r = Reader::new(payload);
        let bytes = r.u32_be()?;
        if bytes > PROBE_MAX_BYTES {
            return Err(NexxusError::Io(format!(
                "probe bytes {bytes} > limit {PROBE_MAX_BYTES}"
            )));
        }
        Ok(Probe { bytes })
    }
}

/// ProbeResp (0x0F): эхо-ответ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResp {
    pub bytes: u32,
    pub data: Vec<u8>,
}

impl Payload for ProbeResp {
    fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        w.u32_be(self.data.len() as u32);
        w.bytes(&self.data);
        w.buf
    }

    fn decode(payload: &[u8]) -> Result<Self, NexxusError> {
        let mut r = Reader::new(payload);
        let bytes = r.u32_be()? as usize;
        if bytes > PROBE_MAX_BYTES as usize {
            return Err(NexxusError::Io(format!(
                "probe resp bytes {bytes} > limit {PROBE_MAX_BYTES}"
            )));
        }
        if r.remaining() < bytes {
            return Err(NexxusError::WireTruncated {
                offset: 0,
                need: bytes,
            });
        }
        let data = r.bytes(bytes)?.to_vec();
        Ok(ProbeResp {
            bytes: bytes as u32,
            data,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_roundtrip() {
        let p = Probe { bytes: 4096 };
        assert_eq!(Probe::decode(&p.encode()).unwrap(), p);
    }

    #[test]
    fn probe_rejects_oversize() {
        // Собираем raw-пайлоад вручную: encode() сам клампит значение, поэтому
        // проверяем именно защиту ДЕКОДЕРА от слишком большого lengths.
        let mut raw = Vec::new();
        raw.extend_from_slice(&(PROBE_MAX_BYTES + 1).to_be_bytes());
        assert!(Probe::decode(&raw).is_err());
    }

    #[test]
    fn probe_resp_roundtrip() {
        let data = vec![7u8; 1024];
        let p = ProbeResp { bytes: 1024, data: data.clone() };
        let got = ProbeResp::decode(&p.encode()).unwrap();
        assert_eq!(got.bytes, 1024);
        assert_eq!(got.data, data);
    }

    #[test]
    fn probe_resp_truncated() {
        // Заявляем 10 байт, присылаем 3 — декодер обязан отвергнуть.
        let mut raw = Vec::new();
        raw.extend_from_slice(&10u32.to_be_bytes());
        raw.extend_from_slice(&[1u8, 2, 3]);
        assert!(ProbeResp::decode(&raw).is_err());
    }
}
