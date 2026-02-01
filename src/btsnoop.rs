//! BTSnoop packet logging for HCI traffic analysis.
//!
//! This module provides functionality to log HCI packets in BTSnoop format,
//! which can be post-processed into `.btsnoop` files for analysis in Wireshark.
//!
//! # Usage
//!
//! Enable the `btsnoop` feature in your `Cargo.toml`:
//!
//! ```toml
//! [dependencies]
//! bt-hci = { version = "...", features = ["btsnoop"] }
//! ```
//!
//! Then call [`log_file_header`] once at startup, and packets will be automatically
//! logged as they are sent/received through [`ExternalController`](crate::controller::ExternalController).
//!
//! Use the `btsnoop-convert.py` tool to convert defmt output to `.btsnoop` files.

use crate::PacketKind;

/// BTSnoop file identification pattern: "btsnoop\0"
pub const BTSNOOP_MAGIC: &[u8; 8] = b"btsnoop\0";

/// BTSnoop file format version (always 1)
pub const BTSNOOP_VERSION: u32 = 1;

/// Datalink type for HCI UART (H4) transport
pub const DATALINK_HCI_UART: u32 = 1002;

/// BTSnoop timestamp epoch offset from Unix epoch (in microseconds).
/// BTSnoop uses midnight January 1, 0 AD as its epoch.
/// This constant represents midnight January 1, 2000 AD in btsnoop time.
pub const BTSNOOP_EPOCH_DELTA: i64 = 0x00E03AB44A676000;

/// Packet direction for BTSnoop records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Direction {
    /// Host to Controller (sent)
    Sent = 0,
    /// Controller to Host (received)
    Received = 1,
}

/// Compute BTSnoop flags from direction and packet kind.
///
/// BTSnoop flags format:
/// - Bit 0: Direction (0 = sent, 1 = received)
/// - Bit 1: Type (0 = data, 1 = command/event)
#[inline]
pub const fn compute_flags(direction: Direction, kind: PacketKind) -> u32 {
    let dir_bit = direction as u32;
    let type_bit = match kind {
        PacketKind::Cmd | PacketKind::Event => 2,
        _ => 0,
    };
    dir_bit | type_bit
}

/// BTSnoop record header (24 bytes).
///
/// Each packet record in a btsnoop file starts with this header,
/// followed by the packet data.
#[derive(Debug, Clone, Copy)]
pub struct RecordHeader {
    /// Original length of the packet
    pub orig_len: u32,
    /// Included length (bytes captured)
    pub incl_len: u32,
    /// Packet flags (direction and type)
    pub flags: u32,
    /// Cumulative drops (always 0)
    pub cum_drops: u32,
    /// Timestamp in microseconds since btsnoop epoch
    pub timestamp: i64,
}

impl RecordHeader {
    /// Create a new record header.
    ///
    /// # Arguments
    /// * `packet_len` - Length of the packet data (including H4 type byte)
    /// * `flags` - BTSnoop flags (use [`compute_flags`])
    /// * `timestamp_us` - Timestamp in microseconds since boot
    #[inline]
    pub const fn new(packet_len: u32, flags: u32, timestamp_us: i64) -> Self {
        Self {
            orig_len: packet_len,
            incl_len: packet_len,
            flags,
            cum_drops: 0,
            // Convert from boot-relative to btsnoop epoch
            timestamp: timestamp_us + BTSNOOP_EPOCH_DELTA,
        }
    }

    /// Serialize the header to big-endian bytes.
    #[inline]
    pub const fn to_bytes(&self) -> [u8; 24] {
        let orig = self.orig_len.to_be_bytes();
        let incl = self.incl_len.to_be_bytes();
        let flags = self.flags.to_be_bytes();
        let drops = self.cum_drops.to_be_bytes();
        let ts = self.timestamp.to_be_bytes();

        [
            orig[0], orig[1], orig[2], orig[3], incl[0], incl[1], incl[2], incl[3], flags[0], flags[1], flags[2],
            flags[3], drops[0], drops[1], drops[2], drops[3], ts[0], ts[1], ts[2], ts[3], ts[4], ts[5], ts[6], ts[7],
        ]
    }
}

/// BTSnoop file header (16 bytes).
///
/// This header must be output once at the start of btsnoop logging.
pub struct FileHeader;

impl FileHeader {
    /// Serialize the file header to bytes.
    #[inline]
    pub const fn to_bytes() -> [u8; 16] {
        let ver = BTSNOOP_VERSION.to_be_bytes();
        let dl = DATALINK_HCI_UART.to_be_bytes();

        [
            // Magic: "btsnoop\0"
            b'b', b't', b's', b'n', b'o', b'o', b'p', 0, // Version: 1
            ver[0], ver[1], ver[2], ver[3], // Datalink: 1002 (HCI UART/H4)
            dl[0], dl[1], dl[2], dl[3],
        ]
    }
}

/// Log the BTSnoop file header.
///
/// Call this once at startup before any packets are logged.
/// The output can be captured and used to create a `.btsnoop` file header.
#[inline]
pub fn log_file_header() {
    let header = FileHeader::to_bytes();
    defmt::trace!("BTSNOOP:H:{=[u8]:02x}", header);
}

/// Log a BTSnoop packet record.
///
/// # Arguments
/// * `direction` - Whether the packet was sent or received
/// * `kind` - The HCI packet type
/// * `data` - The packet data (including H4 type byte for datalink 1002)
#[inline]
pub fn log_packet(direction: Direction, kind: PacketKind, data: &[u8]) {
    let timestamp_us = embassy_time::Instant::now().as_micros() as i64;
    let flags = compute_flags(direction, kind);
    let header = RecordHeader::new(data.len() as u32, flags, timestamp_us);
    let header_bytes = header.to_bytes();

    defmt::trace!("BTSNOOP:P:{=[u8]:02x}:{=[u8]:02x}", header_bytes, data);
}

/// A cursor for writing HCI data to a slice.
///
/// This is used internally to serialize packets for logging.
pub(crate) struct SliceCursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> SliceCursor<'a> {
    /// Create a new cursor wrapping the given buffer.
    #[inline]
    pub fn new(buf: &'a mut [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    /// Get the current position (number of bytes written).
    #[inline]
    pub fn position(&self) -> usize {
        self.pos
    }
}

impl embedded_io::ErrorType for SliceCursor<'_> {
    type Error = core::convert::Infallible;
}

impl embedded_io::Write for SliceCursor<'_> {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        let remaining = &mut self.buf[self.pos..];
        let len = buf.len().min(remaining.len());
        remaining[..len].copy_from_slice(&buf[..len]);
        self.pos += len;
        Ok(len)
    }

    #[inline]
    fn flush(&mut self) -> Result<(), Self::Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_header() {
        let header = FileHeader::to_bytes();
        assert_eq!(&header[0..8], b"btsnoop\0");
        assert_eq!(&header[8..12], &1u32.to_be_bytes());
        assert_eq!(&header[12..16], &1002u32.to_be_bytes());
    }

    #[test]
    fn test_record_header_serialization() {
        let header = RecordHeader::new(10, 3, 0);
        let bytes = header.to_bytes();

        // orig_len = 10
        assert_eq!(&bytes[0..4], &10u32.to_be_bytes());
        // incl_len = 10
        assert_eq!(&bytes[4..8], &10u32.to_be_bytes());
        // flags = 3
        assert_eq!(&bytes[8..12], &3u32.to_be_bytes());
        // cum_drops = 0
        assert_eq!(&bytes[12..16], &0u32.to_be_bytes());
        // timestamp = BTSNOOP_EPOCH_DELTA (since input was 0)
        assert_eq!(&bytes[16..24], &BTSNOOP_EPOCH_DELTA.to_be_bytes());
    }

    #[test]
    fn test_flag_computation() {
        // Sent command: dir=0, type=1 -> flags=2
        assert_eq!(compute_flags(Direction::Sent, PacketKind::Cmd), 2);
        // Received event: dir=1, type=1 -> flags=3
        assert_eq!(compute_flags(Direction::Received, PacketKind::Event), 3);
        // Sent ACL data: dir=0, type=0 -> flags=0
        assert_eq!(compute_flags(Direction::Sent, PacketKind::AclData), 0);
        // Received ACL data: dir=1, type=0 -> flags=1
        assert_eq!(compute_flags(Direction::Received, PacketKind::AclData), 1);
        // Sent Sync data: dir=0, type=0 -> flags=0
        assert_eq!(compute_flags(Direction::Sent, PacketKind::SyncData), 0);
        // Sent ISO data: dir=0, type=0 -> flags=0
        assert_eq!(compute_flags(Direction::Sent, PacketKind::IsoData), 0);
    }

    #[test]
    fn test_slice_cursor() {
        let mut buf = [0u8; 10];
        let mut cursor = SliceCursor::new(&mut buf);

        assert_eq!(cursor.position(), 0);

        use embedded_io::Write;
        cursor.write(&[1, 2, 3]).unwrap();
        assert_eq!(cursor.position(), 3);
        assert_eq!(&buf[0..3], &[1, 2, 3]);

        cursor.write(&[4, 5]).unwrap();
        assert_eq!(cursor.position(), 5);
        assert_eq!(&buf[0..5], &[1, 2, 3, 4, 5]);
    }
}
