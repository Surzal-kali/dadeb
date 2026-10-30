//! Streaming pcap file codec — the byte contract from reading
//! `utils/packetcraft.py`'s parse→reserialize round-trip (which is a byte
//! no-op for libpcap-format files, so the Rust writer can lay frames down
//! directly):
//!
//! - 24-byte global header (LE): magic `d4 c3 b2 a1`, version 2.4,
//!   thiszone 0, sigfigs 0, snaplen 262144 (libpcap MAXIMUM_SNAPLEN),
//!   network 1 = LINKTYPE_ETHERNET
//! - per-packet 16-byte record: ts_sec, ts_usec, incl_len, orig_len, bytes
//!
//! Reader accepts the big-endian magic too (superset), refuses pcapng
//! (different container, out of scope), sanity-caps `incl_len` at
//! MAXIMUM_SNAPLEN, and stops cleanly on a truncated tail (the classic
//! tcpdump'd-under-pressure file) instead of erroring the whole read.

use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

/// Refusal messages for a wrong magic: pcapng gets the convert-with-editcap
/// hint, garbage gets the magics we can parse (pcapng files are the common
/// "weird" capture; nanosecond pcaps are parsed, not refused).
fn bad_magic(magic: &[u8; 4]) -> PcapFormatError {
    let hex_str: String = magic.iter().map(|b| format!("{b:02x}")).collect();
    if *magic == PCAPNG_MAGIC {
        PcapFormatError::BadMagic(format!(
            "magic bytes {hex_str} — pcapng is not supported; \
             use tcpdump/tshark or convert with editcap -F pcap"
        ))
    } else {
        PcapFormatError::BadMagic(format!(
            "magic bytes {hex_str} — expected a1b2c3d4/d4c3b2a1 (pcap) or \
             a1b23c4d/4d3cb2a1 (nanosecond pcap)"
        ))
    }
}

fn short_magic(partial: &[u8], e: std::io::Error) -> PcapFormatError {
    let hex_str: String = partial.iter().map(|b| format!("{b:02x}")).collect();
    PcapFormatError::BadMagic(format!("magic bytes {hex_str} (file too short: {e})"))
}

pub const GLOBAL_HEADER_SIZE: usize = 24;
pub const RECORD_HEADER_SIZE: usize = 16;
/// libpcap MAXIMUM_SNAPLEN — also the incl_len sanity cap.
pub const MAX_SNAPLEN: u32 = 262_144;
pub const LINKTYPE_ETHERNET: u32 = 1;

const LE_MAGIC: [u8; 4] = [0xd4, 0xc3, 0xb2, 0xa1];
const BE_MAGIC: [u8; 4] = [0xa1, 0xb2, 0xc3, 0xd4];
// Nanosecond-precision siblings (ts sub-second field carries NANOSECONDS);
// same container otherwise, so they are parsed, not refused.
const NANO_LE_MAGIC: [u8; 4] = [0x4d, 0x3c, 0xb2, 0xa1];
const NANO_BE_MAGIC: [u8; 4] = [0xa1, 0xb2, 0x3c, 0x4d];
const PCAPNG_MAGIC: [u8; 4] = [0x0a, 0x0d, 0x0d, 0x0a];

/// True when the 4 magic bytes are a libpcap container we can parse
/// (microsecond or nanosecond, either byte order) — pcapng and garbage are
/// not.
fn is_pcap_magic(magic: &[u8; 4]) -> bool {
    matches!(magic, m if *m == LE_MAGIC || *m == BE_MAGIC || *m == NANO_LE_MAGIC || *m == NANO_BE_MAGIC)
}

#[derive(Debug, Clone)]
pub struct GlobalHeader {
    pub version_major: u16,
    pub version_minor: u16,
    pub thiszone: i32,
    pub sigfigs: u32,
    /// As stored (byte order normalized).
    pub snaplen: u32,
    pub network: u32,
    /// True when the file was written big-endian.
    pub big_endian: bool,
    /// Nanosecond-magic file: each record's sub-second field carried
    /// nanoseconds; the reader normalizes `ts_usec` to microseconds
    /// (truncating below the microsecond).
    pub nanosecond: bool,
}

#[derive(Debug, Clone)]
pub struct Record {
    pub ts_sec: u32,
    pub ts_usec: u32,
    pub orig_len: u32,
    pub data: Vec<u8>,
}

#[derive(Debug)]
pub enum PcapFormatError {
    Io(std::io::Error),
    /// Not a libpcap container (pcapng / garbage).
    BadMagic(String),
    /// incl_len beyond MAX_SNAPLEN.
    OversizedRecord { incl_len: u32 },
}

impl std::fmt::Display for PcapFormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "pcap io error: {e}"),
            Self::BadMagic(m) => write!(f, "not a pcap file: {m}"),
            Self::OversizedRecord { incl_len } => {
                write!(f, "corrupt pcap record: incl_len {incl_len} exceeds {MAX_SNAPLEN}")
            }
        }
    }
}
impl std::error::Error for PcapFormatError {}
impl From<std::io::Error> for PcapFormatError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

#[derive(Debug)]
pub struct PcapWriter {
    file: BufWriter<File>,
    count: usize,
}

impl PcapWriter {
    /// Ethernet-linktype capture (our crafted/saved frames).
    pub fn create<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        Self::create_with_linktype(path, LINKTYPE_ETHERNET)
    }

    /// Capture file whose frames are of `linktype` (e.g. the live capture's
    /// `pcap_datalink`: an `any`-interface sniff is LINUX_SLL, not Ethernet —
    /// stamping it Ethernet would make every reader misparse it).
    pub fn create_with_linktype<P: AsRef<Path>>(path: P, linktype: u32) -> std::io::Result<Self> {
        let mut file = BufWriter::new(File::create(path.as_ref())?);
        let mut hdr = [0u8; GLOBAL_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&LE_MAGIC);
        hdr[4..6].copy_from_slice(&2u16.to_le_bytes()); // v2.4
        hdr[6..8].copy_from_slice(&4u16.to_le_bytes());
        // [8..16): thiszone 0, sigfigs 0
        hdr[16..20].copy_from_slice(&MAX_SNAPLEN.to_le_bytes());
        hdr[20..24].copy_from_slice(&linktype.to_le_bytes());
        file.write_all(&hdr)?;
        Ok(Self { file, count: 0 })
    }

    /// incl_len == orig_len == data.len().
    pub fn write_record(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> std::io::Result<()> {
        let mut hdr = [0u8; RECORD_HEADER_SIZE];
        hdr[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        hdr[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        hdr[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes());
        self.file.write_all(&hdr)?;
        self.file.write_all(data)?;
        self.count += 1;
        Ok(())
    }

    pub fn count(&self) -> usize {
        self.count
    }

    pub fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }

    pub fn into_inner(self) -> std::io::Result<File> {
        self.file.into_inner().map_err(|e| e.into_error())
    }
}

#[derive(Debug)]
pub struct PcapReader<R: Read> {
    inner: R,
    header: GlobalHeader,
    truncated: bool,
}

impl PcapReader<BufReader<File>> {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, PcapFormatError> {
        Self::from_reader(BufReader::new(File::open(path.as_ref())?))
    }
}

impl<R: Read> PcapReader<R> {
    pub fn from_reader(mut inner: R) -> Result<Self, PcapFormatError> {
        let mut magic = [0u8; 4];
        match inner.read_exact(&mut magic) {
            Ok(()) => {}
            // empty / 1-3 byte file: not a pcap container
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                return Err(short_magic(&magic, e));
            }
            Err(e) => return Err(e.into()),
        }
        let (big_endian, nanosecond) = if magic == LE_MAGIC {
            (false, false)
        } else if magic == BE_MAGIC {
            (true, false)
        } else if magic == NANO_LE_MAGIC {
            (false, true)
        } else if magic == NANO_BE_MAGIC {
            (true, true)
        } else {
            return Err(bad_magic(&magic));
        };
        let mut buf = [0u8; GLOBAL_HEADER_SIZE - 4];
        inner.read_exact(&mut buf)?;
        let (major, minor) = if big_endian {
            (
                u16::from_be_bytes([buf[0], buf[1]]),
                u16::from_be_bytes([buf[2], buf[3]]),
            )
        } else {
            (
                u16::from_le_bytes([buf[0], buf[1]]),
                u16::from_le_bytes([buf[2], buf[3]]),
            )
        };
        let word = |start: usize, be: bool| -> u32 {
            let b: [u8; 4] = buf[start..start + 4].try_into().unwrap();
            if be { u32::from_be_bytes(b) } else { u32::from_le_bytes(b) }
        };
        // `buf` starts AFTER the 4-byte magic: [0..4) version major/minor,
        // [4..8) thiszone, [8..12) sigfigs, [12..16) snaplen, [16..20) network.
        let thiszone = word(4, big_endian) as i32;
        let sigfigs = word(8, big_endian);
        let snaplen = word(12, big_endian);
        let network = word(16, big_endian);
        Ok(Self {
            inner,
            header: GlobalHeader {
                version_major: major,
                version_minor: minor,
                thiszone,
                sigfigs,
                snaplen,
                network,
                big_endian,
                nanosecond,
            },
            truncated: false,
        })
    }

    pub fn header(&self) -> &GlobalHeader {
        &self.header
    }

/// True once a clean stop happened on a truncated record header/payload.
pub fn is_truncated(&self) -> bool {
    self.truncated
}

    /// Read as much of `buf` as the stream offers. Returns the byte count:
    /// full `buf.len()`, or fewer at stream EOF (the truncated-tail signal).
    fn read_available(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut n = 0;
        while n < buf.len() {
            match self.inner.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
        Ok(n)
    }

    /// Next record, or None at clean EOF. A partial record header or partial
    /// payload stops cleanly and flips `truncated`. Oversized incl_len is a
    /// hard error.
    pub fn next_record(&mut self) -> Result<Option<Record>, PcapFormatError> {
        let mut hdr = [0u8; RECORD_HEADER_SIZE];
        let got = self.read_available(&mut hdr)?;
        if got == 0 {
            return Ok(None); // clean EOF
        }
        if got < RECORD_HEADER_SIZE {
            self.truncated = true;
            return Ok(None);
        }
        let (ts_sec, ts_subsec, incl_len, orig_len) = if self.header.big_endian {
            (
                u32::from_be_bytes(hdr[0..4].try_into().unwrap()),
                u32::from_be_bytes(hdr[4..8].try_into().unwrap()),
                u32::from_be_bytes(hdr[8..12].try_into().unwrap()),
                u32::from_be_bytes(hdr[12..16].try_into().unwrap()),
            )
        } else {
            (
                u32::from_le_bytes(hdr[0..4].try_into().unwrap()),
                u32::from_le_bytes(hdr[4..8].try_into().unwrap()),
                u32::from_le_bytes(hdr[8..12].try_into().unwrap()),
                u32::from_le_bytes(hdr[12..16].try_into().unwrap()),
            )
        };
        if incl_len > MAX_SNAPLEN {
            return Err(PcapFormatError::OversizedRecord { incl_len });
        }
        // Nanosecond-magic files carry nanoseconds in the sub-second field;
        // normalize so Record.ts_usec stays honest microseconds.
        let ts_usec = if self.header.nanosecond {
            ts_subsec / 1_000
        } else {
            ts_subsec
        };
        let mut data = vec![0u8; incl_len as usize];
        let got = self.read_available(&mut data)?;
        if got < data.len() {
            data.truncate(got);
            self.truncated = true;
            return Ok(None);
        }
        Ok(Some(Record {
            ts_sec,
            ts_usec,
            orig_len,
            data,
        }))
    }
}

/// Frame count without materializing payload bytes (seek-walk).
pub fn count_records<P: AsRef<Path>>(path: P) -> Result<usize, PcapFormatError> {
    let mut f = File::open(path.as_ref())?;
    let mut header = [0u8; GLOBAL_HEADER_SIZE];
    f.read_exact(&mut header)?;
    let big_endian = if is_pcap_magic(&header[0..4].try_into().unwrap()) {
        header[0..4] == [0xa1, 0xb2, 0xc3, 0xd4] || header[0..4] == [0xa1, 0xb2, 0x3c, 0x4d]
    } else {
        return Err(bad_magic(&header[0..4].try_into().unwrap()));
    };
    let mut pos: u64 = GLOBAL_HEADER_SIZE as u64;
    let len = f.metadata()?.len();
    let mut count = 0usize;
    loop {
        if pos + RECORD_HEADER_SIZE as u64 > len {
            break; // truncated tail (or clean EOF)
        }
        f.seek(SeekFrom::Start(pos))?;
        let mut hdr = [0u8; RECORD_HEADER_SIZE];
        f.read_exact(&mut hdr)?;
        let incl_len = if big_endian {
            u32::from_be_bytes(hdr[8..12].try_into().unwrap())
        } else {
            u32::from_le_bytes(hdr[8..12].try_into().unwrap())
        };
        if incl_len > MAX_SNAPLEN {
            return Err(PcapFormatError::OversizedRecord { incl_len });
        }
        pos += RECORD_HEADER_SIZE as u64 + incl_len as u64;
        if pos > len {
            break; // truncated payload
        }
        count += 1;
    }
    Ok(count)
}

/// Dissect every frame per the file's linktype, preserving 0-based
/// position — the shared walk both the search pipeline and tests use.
pub fn dissected_frames<P: AsRef<Path>>(
    path: P,
) -> Result<Vec<(usize, crate::dissect::FrameView, u32, u32)>, PcapFormatError> {
    let mut reader = PcapReader::open(path)?;
    let linktype = reader.header().network;
    let mut out = Vec::new();
    let mut idx = 0usize;
    while let Some(rec) = reader.next_record()? {
        out.push((
            idx,
            crate::dissect::dissect_frame_linktype(&rec.data, linktype),
            rec.ts_sec,
            rec.ts_usec,
        ));
        idx += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    fn golden_frame(ts_sec: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&ts_sec.to_le_bytes());
        v.extend_from_slice(&42u32.to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn global_header_is_le_golden() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.pcap");
        PcapWriter::create(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            Sha256::digest(&bytes).to_vec(),
            Sha256::digest([
                0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 0, 0
            ])
            .to_vec()
        );
    }

    #[test]
    fn global_header_fields_read_back() {
        // Regression: fields were read one slot early (snaplen came back as
        // sigfigs, network as snaplen).
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("h.pcap");
        PcapWriter::create(&path).unwrap();
        let r = PcapReader::open(&path).unwrap();
        let h = r.header();
        assert_eq!((h.version_major, h.version_minor), (2, 4));
        assert_eq!(h.thiszone, 0);
        assert_eq!(h.sigfigs, 0);
        assert_eq!(h.snaplen, MAX_SNAPLEN);
        assert_eq!(h.network, LINKTYPE_ETHERNET);

        let path = dir.path().join("sll.pcap");
        PcapWriter::create_with_linktype(&path, 113).unwrap();
        assert_eq!(PcapReader::open(&path).unwrap().header().network, 113);
    }

    #[test]
    fn write_read_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("r.pcap");
        let mut w = PcapWriter::create(&path).unwrap();
        w.write_record(1700000000, 1234, &[0x01, 0x02, 0x03]).unwrap();
        w.write_record(1700000001, 4321, &[0xff; 60]).unwrap();
        w.flush().unwrap();
        std::mem::drop(w);

        assert_eq!(count_records(&path).unwrap(), 2);
        let mut r = PcapReader::open(&path).unwrap();
        let reca = r.next_record().unwrap().unwrap();
        assert_eq!((reca.ts_sec, reca.ts_usec), (1700000000, 1234));
        assert_eq!(reca.data, vec![1, 2, 3]);
        assert_eq!(reca.orig_len, 3);
        let recb = r.next_record().unwrap().unwrap();
        assert_eq!(recb.ts_sec, 1700000001);
        assert_eq!(recb.data, [0xffu8; 60].to_vec());
        assert!(r.next_record().unwrap().is_none());
        assert!(!r.is_truncated());
    }

    #[test]
    fn big_endian_magic_accepted() {
        // Hand-build a BE global header + record.
        let mut bytes = vec![0xa1, 0xb2, 0xc3, 0xd4];
        bytes.extend_from_slice(&2u16.to_be_bytes());
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&0i32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&262144u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        bytes.extend_from_slice(&1700000000u32.to_be_bytes());
        bytes.extend_from_slice(&0u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&[0xde, 0xad]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("be.pcap");
        std::fs::write(&path, &bytes).unwrap();
        let mut r = PcapReader::open(&path).unwrap();
        assert!(r.header().big_endian);
        assert_eq!(r.header().snaplen, 262_144);
        assert_eq!(r.header().network, 1);
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!(rec.data, vec![0xde, 0xad]);
    }

    #[test]
    fn truncated_tail_stops_cleanly() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.pcap");
        let mut w = PcapWriter::create(&path).unwrap();
        w.write_record(1, 0, &[0u8; 10]).unwrap();
        w.write_record(2, 0, &[0u8; 100]).unwrap();
        w.flush().unwrap();
        std::mem::drop(w);
        // Cut the file in half: header + full first record + partial second.
        let bytes = std::fs::read(&path).unwrap();
        let cut = &bytes[..(24 + 16 + 10 + 8)];
        std::fs::write(&path, cut).unwrap();

        assert_eq!(count_records(&path).unwrap(), 1);
        let mut r = PcapReader::open(&path).unwrap();
        assert!(r.next_record().unwrap().is_some());
        assert!(r.next_record().unwrap().is_none());
        assert!(r.is_truncated());
    }

    #[test]
    fn pcapng_magic_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("n.pcap");
        std::fs::write(&path, [0x0a, 0x0d, 0x0d, 0x0a, 0, 0, 0, 0]).unwrap();
        let err = PcapReader::open(&path).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("pcapng"), "{msg}");
        assert!(msg.contains("editcap"), "{msg}");
    }

    #[test]
    fn oversized_incl_len_refused() {
        let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1];
        bytes.extend_from_slice(&[2, 0, 4, 0]);
        bytes.extend_from_slice(&[0; 16]);
        // ts_sec, ts_usec, incl_len = 0x7fffffff, orig_len = 0x7fffffff
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&[2, 0, 0, 0]);
        bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
        bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0x7f]);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("o.pcap");
        std::fs::write(&path, &bytes).unwrap();
        let mut r = PcapReader::open(&path).unwrap();
        let err = r.next_record().unwrap_err();
        assert!(err.to_string().contains("exceeds 262144"), "{err}");
    }

    #[test]
    fn golden_frame_bytes_match_writer_layout() {
        // writer layout == golden_frame manual layout (record prefix)
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("l.pcap");
        let payload = [0x11u8, 0x22];
        let mut w = PcapWriter::create(&path).unwrap();
        w.write_record(77, 42, &payload).unwrap();
        std::mem::drop(w);
        let bytes = std::fs::read(&path).unwrap();
        assert_eq!(
            &bytes[24..],
            &golden_frame(77, &payload)[..],
            "record prefix must equal the hand-built golden frame"
        );
    }

    #[test]
    fn nanosecond_le_magic_parsed_and_normalized() {
        // LE nanosecond pcap: magic 4d 3c b2 a1, sub-second field = ns.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nano_le.pcap");
        let mut f = File::create(&path).unwrap();
        f.write_all(&[0x4d, 0x3c, 0xb2, 0xa1, 2, 0, 4, 0]).unwrap();
        f.write_all(&[0; 16]).unwrap(); // thiszone..network
        let magic_ts = 1_700_000_000u32;
        let nanos = [123_456_789u32, 0, 999_999_999];
        for ns in nanos {
            f.write_all(&magic_ts.to_le_bytes()).unwrap();
            f.write_all(&ns.to_le_bytes()).unwrap();
            f.write_all(&3u32.to_le_bytes()).unwrap();
            f.write_all(&3u32.to_le_bytes()).unwrap();
            f.write_all(&[0xde, 0xad, 0xbe]).unwrap();
        }
        drop(f);

        let mut r = PcapReader::open(&path).unwrap();
        assert!(r.header().nanosecond, "nano magic must set the nano flag");
        assert!(!r.header().big_endian);
        assert_eq!(r.next_record().unwrap().map(|x| (x.ts_sec, x.ts_usec)),
            Some((magic_ts, 123_456))); // truncates below the microsecond
        assert_eq!(
            r.next_record().unwrap().map(|x| x.ts_usec),
            Some(0)
        );
        assert_eq!(
            r.next_record().unwrap().map(|x| x.ts_usec),
            Some(999_999) // 999_999_999 ns → 999_999 µs, not 1_000_000
        );
        assert!(r.next_record().unwrap().is_none());
        assert_eq!(count_records(&path).unwrap(), 3, "seek-walk must accept nano magic");
    }

    #[test]
    fn nanosecond_be_magic_parsed_and_normalized() {
        // BE nanosecond pcap: magic a1 b2 3c 4d, sub-second field = ns BE.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nano_be.pcap");
        let mut f = File::create(&path).unwrap();
        f.write_all(&[0xa1, 0xb2, 0x3c, 0x4d, 0, 2, 0, 4]).unwrap();
        f.write_all(&[0; 16]).unwrap();
        f.write_all(&1_700_000_005u32.to_be_bytes()).unwrap();
        f.write_all(&1_500_000_000u32.to_be_bytes()).unwrap(); // sub-second ns
        f.write_all(&4u32.to_be_bytes()).unwrap();
        f.write_all(&4u32.to_be_bytes()).unwrap();
        f.write_all(&[0x01, 0x02, 0x03, 0x04]).unwrap();
        drop(f);

        let mut r = PcapReader::open(&path).unwrap();
        assert!(r.header().nanosecond);
        assert!(r.header().big_endian);
        let rec = r.next_record().unwrap().unwrap();
        assert_eq!((rec.ts_sec, rec.ts_usec), (1_700_000_005, 1_500_000));
    }

    #[test]
    fn garbage_magic_gets_its_own_message() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("g.pcap");
        std::fs::write(&path, [0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0]).unwrap();
        let msg = PcapReader::open(&path).unwrap_err().to_string();
        assert!(msg.contains("a1b2c3d4"), "{msg}");
        assert!(msg.contains("nanosecond"), "{msg}");
        assert!(!msg.contains("pcapng"), "{msg}");
    }
}
