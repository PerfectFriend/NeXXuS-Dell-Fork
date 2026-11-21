//! Media Streaming & Range Request Engine (Phase 3).
//! Enables streaming of multimedia (video, audio, reels) over 16 KiB NeXXUs chunk sequences.

use nexxus_core::chunk::CHUNK_SIZE;
use nexxus_core::error::NexxusError;

/// Byte range specification (inclusive start, exclusive end).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    pub end: u64,
}

impl ByteRange {
    pub fn new(start: u64, end: u64) -> Result<Self, NexxusError> {
        if start > end {
            return Err(NexxusError::Io(format!("invalid range: start {start} > end {end}")));
        }
        Ok(Self { start, end })
    }

    pub fn length(&self) -> u64 {
        self.end - self.start
    }

    /// Calculates which 16 KiB chunks are required to satisfy this byte range.
    /// Returns (first_chunk_index, last_chunk_index_inclusive).
    pub fn required_chunk_indices(&self) -> (usize, usize) {
        if self.length() == 0 {
            let idx = (self.start / CHUNK_SIZE as u64) as usize;
            return (idx, idx);
        }
        let first = (self.start / CHUNK_SIZE as u64) as usize;
        let last = ((self.end - 1) / CHUNK_SIZE as u64) as usize;
        (first, last)
    }
}

/// Slices the requested range from a contiguous sequence of decoded chunks.
/// `chunks`: array of decoded 16 KiB chunks corresponding to `range.required_chunk_indices()`.
pub fn slice_range_from_chunks(
    chunks: &[Vec<u8>],
    range: ByteRange,
) -> Result<Vec<u8>, NexxusError> {
    let (first_idx, last_idx) = range.required_chunk_indices();
    let expected_count = last_idx - first_idx + 1;
    if chunks.len() < expected_count {
        return Err(NexxusError::Io(format!(
            "insufficient chunks provided: expected {expected_count}, got {}",
            chunks.len()
        )));
    }

    let mut result = Vec::with_capacity(range.length() as usize);
    let chunk_size = CHUNK_SIZE as u64;

    for (i, chunk) in chunks.iter().take(expected_count).enumerate() {
        let current_chunk_idx = first_idx + i;
        let chunk_start_byte = current_chunk_idx as u64 * chunk_size;
        let chunk_end_byte = chunk_start_byte + chunk.len() as u64;

        if chunk_end_byte <= range.start || chunk_start_byte >= range.end {
            continue;
        }

        let slice_start = if range.start > chunk_start_byte {
            (range.start - chunk_start_byte) as usize
        } else {
            0
        };

        let slice_end = if range.end < chunk_end_byte {
            (range.end - chunk_start_byte) as usize
        } else {
            chunk.len()
        };

        if slice_start < chunk.len() && slice_end <= chunk.len() && slice_start < slice_end {
            result.extend_from_slice(&chunk[slice_start..slice_end]);
        }
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_indices_calculation() {
        // First 100 bytes is inside chunk 0
        let r1 = ByteRange::new(0, 100).unwrap();
        assert_eq!(r1.required_chunk_indices(), (0, 0));

        // Exactly one chunk
        let r2 = ByteRange::new(0, 16384).unwrap();
        assert_eq!(r2.required_chunk_indices(), (0, 0));

        // Spanning across boundary (byte 16383 to 16385) requires chunk 0 and 1
        let r3 = ByteRange::new(16383, 16385).unwrap();
        assert_eq!(r3.required_chunk_indices(), (0, 1));

        // Inside second chunk
        let r4 = ByteRange::new(20000, 25000).unwrap();
        assert_eq!(r4.required_chunk_indices(), (1, 1));
    }

    #[test]
    fn slice_range_extraction() {
        let chunk0 = vec![1u8; 16384];
        let chunk1 = vec![2u8; 16384];
        let chunk2 = vec![3u8; 16384];
        let chunks = vec![chunk0, chunk1, chunk2];

        // Range across chunk 0 and 1
        let range = ByteRange::new(16380, 16388).unwrap(); // 4 bytes of 1s, 4 bytes of 2s
        let sliced = slice_range_from_chunks(&chunks, range).unwrap();
        assert_eq!(sliced.len(), 8);
        assert_eq!(&sliced[..4], &[1, 1, 1, 1]);
        assert_eq!(&sliced[4..], &[2, 2, 2, 2]);
    }
}
