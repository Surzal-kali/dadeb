//! Frame dissection — scapy-shaped summaries + flat field lists + payload
//! ascii projection. NO service-name resolution (`/etc/services` would make
//! dissection depend on the analyzing box) and no DNS answer parsing (the
//! question carries the searchable identity).
//!
//! Linktype: [`dissect_frame_linktype`] dispatches on the capture's global
//! header `network` (Ethernet, raw IP, IPv4/IPv6, Linux cooked SLL/SLL2,
//! BSD null/loopback); any other linktype is reported honestly as
//! `Raw (linktype N not dissected)` instead of being misparsed as Ethernet.
//! [`dissect_frame`] is the Ethernet entry point (our writer's linktype, and
//! the `dissect_packet`/hex lane), which may meet bare-L3 bytes (python's
//! `_packet_from_hex` discriminator). Ethernet dispatch rules:
//! recognized ethertypes (0x0800/0x0806/0x86dd/0x8100/0x88a8) go through the
//! Ethernet walk (VLAN aware); unrecognized frames with a 4 nibble (len >= 20)
//! or 6 nibble (len >= 40) parse as bare IPv4/IPv6 at offset 0 — deliberately
//! narrower than python's fallback, which also re-reads any other nibble as
//! garbage IP; everything else lands as Ether / Raw.
//!
//! Summary contract: layers join with " / " and the transport parser SETS the
//! suffix (`{src}.{sport} > {dst}.{dport} {flags}`); DNS/HTTP APPEND to the
//! suffix (never push layers) so a summary stays one push per header.
//!
//! Robustness contract: every input byte string — truncated, snapped,
//! lying length fields — produces a FrameView; nothing here may panic.
//! `prefix_sweep_never_panics` in the tests enforces it on every prefix of
//! every fixture frame.

pub const LINKTYPE_NULL: u32 = 0;
pub const LINKTYPE_ETHERNET: u32 = 1;
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_LOOP: u32 = 108;
pub const LINKTYPE_LINUX_SLL: u32 = 113;
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
pub const LINKTYPE_LINUX_SLL2: u32 = 276;

/// One parsed frame's searchable surfaces.
#[derive(Debug, Clone)]
pub struct FrameView {
    /// e.g. `Ether / IP / TCP 10.0.0.1.54000 > 10.0.0.2.22 SA`
    pub summary: String,
    /// flat ordered fields (`eth.dst`, `ip.src`, `tcp.dport`, ...).
    pub fields: Vec<(String, String)>,
    /// printable runs (>= 4 chars) over the deepest payload region, newline-joined
    pub ascii: String,
}

fn u16be(b: &[u8], off: usize) -> Option<u16> {
    if off + 2 > b.len() {
        return None;
    }
    Some(u16::from_be_bytes([b[off], b[off + 1]]))
}

fn mac(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect::<Vec<_>>().join(":")
}

fn ipv4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

pub fn hex_string(frame: &[u8]) -> String {
    let mut s = String::with_capacity(frame.len() * 2);
    for b in frame {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Whitespace-tolerant hex -> bytes (`bytes.fromhex` semantics); errors as
/// `"invalid hex"` when malformed.
pub fn hex_bytes(hex: &str) -> Result<Vec<u8>, String> {
    let clean: String = hex.chars().filter(|c| !c.is_whitespace()).collect();
    if clean.len() % 2 != 0 || !clean.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("invalid hex".to_string());
    }
    (0..clean.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&clean[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

/// Printable runs (>= 4 chars of 0x20..=0x7e) — strings(1)-style.
pub fn printable_runs(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in bytes {
        if (0x20..=0x7e).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.chars().count() >= 4 {
                out.push(std::mem::take(&mut cur));
            } else {
                cur.clear();
            }
        }
    }
    if cur.chars().count() >= 4 {
        out.push(cur);
    }
    out
}

struct Builder<'a> {
    frame: &'a [u8],
    layers: Vec<&'static str>,
    fields: Vec<(String, String)>,
    suffix: String,
    cursor: usize,
    /// deepest layer end (ascii region starts here)
    payload_start: usize,
    /// layer count after the link layer (Raw is pushed when nothing more parsed)
    l2_layers: usize,
}

impl<'a> Builder<'a> {
    fn field(&mut self, k: &str, v: impl Into<String>) {
        self.fields.push((k.to_string(), v.into()));
    }
}

impl<'a> Builder<'a> {
    fn new(frame: &'a [u8]) -> Self {
        Builder {
            frame,
            layers: Vec::new(),
            fields: Vec::new(),
            suffix: String::new(),
            cursor: 0,
            payload_start: 0,
            l2_layers: 0,
        }
    }

    /// Mark everything pushed so far as link-layer (the Raw rule's baseline).
    fn end_l2(&mut self, hdr_end: usize) {
        self.cursor = hdr_end;
        end_of(self, hdr_end);
        self.l2_layers = self.layers.len();
    }

    fn finish(mut self) -> FrameView {
        // Raw only when NOTHING parsed beyond L2 (scapy omits trailing Raw).
        if self.layers.len() == self.l2_layers && self.cursor < self.frame.len() {
            self.layers.push("Raw");
        }
        let mut summary = self.layers.join(" / ");
        if !self.suffix.is_empty() {
            summary.push(' ');
            summary.push_str(&self.suffix);
        }
        // payload_start is clamped by end_of, but slice defensively anyway:
        // a header that claims to extend past the capture just has no ascii.
        let ascii = printable_runs(self.frame.get(self.payload_start..).unwrap_or(&[])).join("\n");
        FrameView {
            summary,
            fields: self.fields,
            ascii,
        }
    }
}

/// Dissect one Ethernet-linktype frame (with the bare-L3 heuristic) — the
/// entry point for our own writer's captures and the hex/`dissect_packet`
/// lane. For frames read from a capture file, prefer
/// [`dissect_frame_linktype`] with the file header's `network`.
pub fn dissect_frame(frame: &[u8]) -> FrameView {
    dissect_frame_linktype(frame, LINKTYPE_ETHERNET)
}

/// Dissect one frame according to its capture linktype.
pub fn dissect_frame_linktype(frame: &[u8], linktype: u32) -> FrameView {
    let mut b = Builder::new(frame);
    match linktype {
        LINKTYPE_ETHERNET => dissect_ether_or_bare(&mut b),
        LINKTYPE_RAW => parse_bare_ip(&mut b, 0),
        LINKTYPE_IPV4 => parse_ipv4(&mut b, 0),
        LINKTYPE_IPV6 => parse_ipv6(&mut b, 0),
        LINKTYPE_LINUX_SLL => parse_sll(&mut b),
        LINKTYPE_LINUX_SLL2 => parse_sll2(&mut b),
        LINKTYPE_NULL | LINKTYPE_LOOP => parse_null_loop(&mut b),
        other => {
            // Unknown link layer: say so instead of misparsing it as Ether.
            b.layers.push("Raw");
            b.field("frame.linktype", other.to_string());
            b.suffix = format!("(linktype {other} not dissected)");
        }
    }
    b.finish()
}

fn dissect_ether_or_bare(b: &mut Builder) {
    let frame = b.frame;
    // L2 vs bare-L3 discrimination (python `_packet_from_hex`, narrowed):
    // a recognized ethertype pins an ether frame; an unrecognized-ethertype
    // frame whose first nibble is 4/6 and long enough to hold a full L3
    // header reinterprets as bare IP/IPv6 craft output; anything else with
    // >= 14 bytes stays an (unknown-L3) ether frame → Ether / Raw. Python
    // instead routes unrecognized-ethertype frames with ANY other nibble to
    // garbage IP() — this narrowing keeps real raw Ether frames visible.
    let etype_known = frame.len() >= 14
        && matches!(
            u16be(frame, 12).unwrap_or(0),
            0x0800 | 0x0806 | 0x86dd | 0x8100 | 0x88a8
        );
    let nib = frame.first().map(|fb| fb >> 4).unwrap_or(0);
    let bare4 = !etype_known && nib == 4 && frame.len() >= 20;
    let bare6 = !etype_known && nib == 6 && frame.len() >= 40;
    if bare4 {
        return parse_ipv4(b, 0);
    }
    if bare6 {
        return parse_ipv6(b, 0);
    }
    if frame.len() < 14 {
        return; // too short for anything: finish() renders Raw
    }

    b.layers.push("Ether");
    b.field("eth.dst", mac(&frame[0..6]));
    b.field("eth.src", mac(&frame[6..12]));
    let eth_type = u16be(frame, 12).unwrap_or(0);
    b.field("eth.type", format!("0x{eth_type:04x}"));
    let mut l3_type = eth_type;
    let mut cursor = 14;

    // VLAN stacking (0x8100 / 0x88a8): 2-byte TCI + real ethertype. A tag
    // cut off by the capture ends the walk (no L3 dispatch).
    while matches!(l3_type, 0x8100 | 0x88a8) {
        let (Some(tci), Some(inner)) = (u16be(frame, cursor), u16be(frame, cursor + 2)) else {
            l3_type = 0;
            break;
        };
        b.layers.push("802.1Q");
        b.field("vlan.id", (tci & 0x0fff).to_string());
        l3_type = inner;
        cursor += 4;
    }
    b.end_l2(cursor);
    l3_by_ethertype(b, l3_type, cursor);
}

fn l3_by_ethertype(b: &mut Builder, etype: u16, off: usize) {
    match etype {
        0x0800 => parse_ipv4(b, off),
        0x86dd => parse_ipv6(b, off),
        0x0806 => parse_arp(b, off),
        _ => {}
    }
}

/// Raw-IP linktypes: version nibble picks v4/v6.
fn parse_bare_ip(b: &mut Builder, off: usize) {
    match b.frame.get(off).map(|x| x >> 4) {
        Some(4) => parse_ipv4(b, off),
        Some(6) => parse_ipv6(b, off),
        _ => {}
    }
}

/// LINKTYPE_LINUX_SLL (`tcpdump -i any`, v1): 16-byte cooked header,
/// protocol (ethertype) in the last two bytes.
fn parse_sll(b: &mut Builder) {
    let f = b.frame;
    if f.len() < 16 {
        return;
    }
    let pkttype = u16be(f, 0).unwrap_or(0);
    let halen = (u16be(f, 4).unwrap_or(0) as usize).min(8);
    let proto = u16be(f, 14).unwrap_or(0);
    b.layers.push("SLL");
    b.field("sll.pkttype", pkttype.to_string());
    b.field("sll.src", mac(&f[6..6 + halen]));
    b.field("sll.proto", format!("0x{proto:04x}"));
    b.end_l2(16);
    l3_by_ethertype(b, proto, 16);
}

/// LINKTYPE_LINUX_SLL2 (`tcpdump -i any` on newer libpcap): 20-byte header,
/// protocol first.
fn parse_sll2(b: &mut Builder) {
    let f = b.frame;
    if f.len() < 20 {
        return;
    }
    let proto = u16be(f, 0).unwrap_or(0);
    let ifindex = u32::from_be_bytes([f[4], f[5], f[6], f[7]]);
    let pkttype = f[10];
    let halen = (f[11] as usize).min(8);
    b.layers.push("SLL2");
    b.field("sll.pkttype", pkttype.to_string());
    b.field("sll.ifindex", ifindex.to_string());
    b.field("sll.src", mac(&f[12..12 + halen]));
    b.field("sll.proto", format!("0x{proto:04x}"));
    b.end_l2(20);
    l3_by_ethertype(b, proto, 20);
}

/// LINKTYPE_NULL / LINKTYPE_LOOP (BSD/macOS loopback): 4-byte address
/// family whose byte order varies by writer — dispatch on the IP version
/// nibble instead of decoding the family.
fn parse_null_loop(b: &mut Builder) {
    if b.frame.len() < 4 {
        return;
    }
    b.layers.push("Loopback");
    b.end_l2(4);
    parse_bare_ip(b, 4);
}

fn parse_ipv4(b: &mut Builder, off: usize) {
    let f = b.frame;
    if f.get(off).map(|x| x >> 4) != Some(4) {
        return;
    }
    let ihl_words = (f[off] & 0x0f) as usize;
    if ihl_words < 5 || off + ihl_words * 4 > f.len() {
        return;
    }
    let total_len = match u16be(f, off + 2) {
        Some(0) | None => f.len() - off,
        Some(n) => (n as usize).min(f.len() - off),
    };
    end_of(b, off + ihl_words * 4); // ascii region starts after the IP header
    b.layers.push("IP");
    let src = ipv4(&f[off + 12..off + 16]);
    let dst = ipv4(&f[off + 16..off + 20]);
    let proto = f[off + 9];
    b.field("ip.src", src.clone());
    b.field("ip.dst", dst.clone());
    b.field("ip.proto", proto.to_string());
    b.field("ip.ttl", f[off + 8].to_string());
    b.field("ip.id", u16be(f, off + 4).unwrap_or(0).to_string());
    b.field("ip.len", total_len.to_string());

    let l4 = off + ihl_words * 4;
    let l4_end = off + total_len;
    match proto {
        6 => parse_tcp(b, l4, l4_end, &src, &dst),
        17 => parse_udp(b, l4, l4_end, &src, &dst),
        1 => parse_icmp(b, l4, l4_end, &src, &dst, false),
        _ => {}
    }
}

fn parse_ipv6(b: &mut Builder, off: usize) {
    let f = b.frame;
    if f.len() < off + 40 || (f[off] >> 4) != 6 {
        return;
    }
    let plen = u16be(f, off + 4).unwrap_or(0) as usize;
    let nxt = f[off + 6];
    end_of(b, off + 40); // ascii region starts after the fixed IPv6 header
    b.layers.push("IPv6");
    let src: std::net::Ipv6Addr = {
        let arr: [u8; 16] = f[off + 8..off + 24].try_into().unwrap();
        arr.into()
    };
    let dst: std::net::Ipv6Addr = {
        let arr: [u8; 16] = f[off + 24..off + 40].try_into().unwrap();
        arr.into()
    };
    b.field("ip.src", src.to_string());
    b.field("ip.dst", dst.to_string());
    b.field("ip.proto", nxt.to_string());

    let l4 = off + 40;
    // A snapped capture (or a lying header) can claim more payload than was
    // captured — clamp to what we actually have, like the IPv4 total_len path.
    // plen == 0 is a jumbogram / TSO artifact: take the rest of the frame.
    let l4_end = if plen == 0 { f.len() } else { (off + 40 + plen).min(f.len()) };
    match nxt {
        6 => parse_tcp(b, l4, l4_end, &src.to_string(), &dst.to_string()),
        17 => parse_udp(b, l4, l4_end, &src.to_string(), &dst.to_string()),
        58 => parse_icmp(b, l4, l4_end, &src.to_string(), &dst.to_string(), true),
        _ => {}
    }
}

fn parse_arp(b: &mut Builder, off: usize) {
    let f = b.frame;
    if f.len() < off + 28 {
        return;
    }
    end_of(b, off + 28);
    b.layers.push("ARP");
    let oper = u16be(f, off + 6).unwrap_or(0);
    let sha = mac(&f[off + 8..off + 14]);
    let psrc = ipv4(&f[off + 14..off + 18]);
    let tha = mac(&f[off + 18..off + 24]);
    let pdst = ipv4(&f[off + 24..off + 28]);
    b.field("arp.op", oper.to_string());
    b.field("arp.psrc", psrc.clone());
    b.field("arp.pdst", pdst.clone());
    b.field("arp.hwsrc", sha.clone());
    b.field("arp.hwdst", tha);
    b.suffix = if oper == 1 {
        format!("who has {pdst} says {psrc}")
    } else if oper == 2 {
        format!("is at {sha} says {psrc}")
    } else {
        format!("op={oper}")
    };
}

fn flag_letters(flags: u8) -> String {
    // scapy bit order: F S R P A U E C
    const L: [(u8, char); 8] = [
        (0x01, 'F'), (0x02, 'S'), (0x04, 'R'), (0x08, 'P'),
        (0x10, 'A'), (0x20, 'U'), (0x40, 'E'), (0x80, 'C'),
    ];
    let mut s = String::new();
    for (bit, c) in L {
        if flags & bit != 0 {
            s.push(c);
        }
    }
    s
}

fn parse_tcp(b: &mut Builder, off: usize, end: usize, src: &str, dst: &str) {
    let f = b.frame;
    if off + 20 > end || off + 20 > f.len() {
        return;
    }
    let sport = u16be(f, off).unwrap_or(0);
    let dport = u16be(f, off + 2).unwrap_or(0);
    let data_off = ((f[off + 12] >> 4) as usize).max(5) * 4;
    let flags = f[off + 13];
    end_of(b, off + data_off); // ascii region starts after the transport header
    b.layers.push("TCP");
    b.field("tcp.sport", sport.to_string());
    b.field("tcp.dport", dport.to_string());
    b.field("tcp.flags", flag_letters(flags));
    b.suffix = format!("{src}.{sport} > {dst}.{dport} {}", flag_letters(flags));

    let hstart = off + data_off;
    if hstart >= end {
        return;
    }
    let payload = &f[hstart..end];
    // DNS over TCP: 2-byte length prefix covering exactly the message.
    if payload.len() >= 14
        && u16be(payload, 0).map(|n| (n as usize + 2) == payload.len()).unwrap_or(false)
    {
        parse_dns(b, &payload[2..]);
        return;
    }
    parse_http(b, payload);
}

fn parse_udp(b: &mut Builder, off: usize, end: usize, src: &str, dst: &str) {
    let f = b.frame;
    if off + 8 > end || off + 8 > f.len() {
        return;
    }
    let sport = u16be(f, off).unwrap_or(0);
    let dport = u16be(f, off + 2).unwrap_or(0);
    end_of(b, off + 8); // ascii region starts after the UDP header
    b.layers.push("UDP");
    b.field("udp.sport", sport.to_string());
    b.field("udp.dport", dport.to_string());
    b.suffix = format!("{src}.{sport} > {dst}.{dport}");

    let hstart = off + 8;
    if hstart >= end {
        return;
    }
    let payload = &f[hstart..end];
    if sport == 53 || dport == 53 || sport == 5353 || dport == 5353 {
        parse_dns(b, payload);
        return;
    }
    parse_http(b, payload);
}

const DNS_QTYPES: &[(u16, &str)] = &[
    (1, "A"), (2, "NS"), (5, "CNAME"), (6, "SOA"), (12, "PTR"), (15, "MX"),
    (16, "TXT"), (28, "AAAA"), (33, "SRV"), (65, "HTTPS"), (255, "ANY"),
];

/// Parse the first question of a DNS message (compression pointers followed
/// within the message, loop-guarded).
fn parse_dns(b: &mut Builder, msg: &[u8]) {
    if msg.len() < 12 {
        return;
    }
    let qd = u16be(msg, 4).unwrap_or(0);
    b.field("dns.id", u16be(msg, 0).unwrap_or(0).to_string());
    if qd == 0 {
        return;
    }
    let mut labels: Vec<String> = Vec::new();
    let mut pos = 12usize;
    let mut jumps = 0usize;
    loop {
        if jumps > 64 || pos >= msg.len() {
            return; // malformed; keep the transport-only summary
        }
        let len = msg[pos];
        if len & 0xC0 == 0xC0 {
            // compression pointer: absolute offset into the message
            if pos + 2 > msg.len() {
                return;
            }
            let target = (((len & 0x3f) as usize) << 8 | msg[pos + 1] as usize).min(msg.len());
            if target == pos {
                return;
            }
            pos = target;
            jumps += 1;
            continue;
        }
        if len == 0 {
            pos += 1;
            break;
        }
        if pos + 1 + len as usize > msg.len() {
            return;
        }
        labels.push(String::from_utf8_lossy(&msg[pos + 1..pos + 1 + len as usize]).into_owned());
        pos += 1 + len as usize;
    }
    let qname = format!("{}.", labels.join("."));
    let qtype = u16be(msg, pos).unwrap_or(0);
    b.field("dns.qname", qname.clone());
    let qtype_name = DNS_QTYPES
        .iter()
        .find(|(n, _)| *n == qtype)
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| qtype.to_string());
    b.field("dns.qtype", qtype_name);
    b.suffix.push_str(&format!(" DNS Qry \"{qname}\""));
}

const ICMP4: &[(u8, &str)] = &[
    (0, "echo-reply"), (3, "dest-unreach"), (4, "source-quench"),
    (5, "redirect"), (8, "echo-request"), (9, "router-advertisement"),
    (10, "router-solicitation"), (11, "time-exceeded"), (12, "parameter-problem"),
    (13, "timestamp"), (14, "timestamp-reply"), (15, "info-request"),
    (16, "info-reply"), (17, "address-mask"), (18, "address-mask-reply"),
];

const ICMP6: &[(u8, &str)] = &[
    (1, "dest-unreach"), (2, "packet-too-big"), (3, "time-exceeded"),
    (4, "parameter-problem"), (128, "echo-request"), (129, "echo-reply"),
    (133, "router-solicitation"), (134, "router-advertisement"),
    (135, "neighbor-solicitation"), (136, "neighbor-advertisement"),
];

fn parse_icmp(b: &mut Builder, off: usize, end: usize, src: &str, dst: &str, v6: bool) {
    let f = b.frame;
    if off + 4 > end || off + 4 > f.len() {
        return;
    }
    let (typ, code) = (f[off], f[off + 1]);
    b.layers.push(if v6 { "ICMPv6" } else { "ICMP" });
    // echo types carry id+seq, so content starts 8 bytes in
    let echo_header = matches!(typ, 8 | 0 | 128 | 129);
    end_of(b, if echo_header { off + 8 } else { off + 4 });
    b.field("icmp.type", typ.to_string());
    b.field("icmp.code", code.to_string());
    let table = if v6 { ICMP6 } else { ICMP4 };
    let name = table
        .iter()
        .find(|(t, _)| *t == typ)
        .map(|(_, s)| s.to_string())
        .unwrap_or_else(|| typ.to_string());
    b.suffix = format!("{src} > {dst} {name} {code}");
}

const HTTP_METHODS: &[&str] = &["GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"];

fn header_value(payload: &str, name: &str) -> Option<String> {
    payload
        .lines()
        .skip(1)
        .take_while(|l| !l.trim().is_empty())
        .find_map(|l| {
            let (k, v) = l.split_once(':')?;
            if k.trim().eq_ignore_ascii_case(name) {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
}

fn parse_http(b: &mut Builder, payload: &[u8]) {
    if payload.starts_with(b"HTTP/") {
        let text = String::from_utf8_lossy(&payload[..payload.len().min(1024)]);
        let first = text.lines().next().unwrap_or("");
        let mut parts = first.split(' ');
        let version = parts.next().unwrap_or("HTTP/");
        b.suffix.push_str(" HTTPResponse");
        if let Some(code) = parts.next() {
            b.field("http.status", code.to_string());
            let reason = parts.collect::<Vec<_>>().join(" ");
            if !reason.is_empty() {
                b.field("http.reason", reason);
            }
        }
        if let Some(ct) = header_value(&text, "content-type") {
            b.field("http.content_type", ct);
        }
        b.field("http.version", version.to_string());
        return;
    }
    let first_word_end = payload
        .iter()
        .position(|&c| c == b' ')
        .unwrap_or(payload.len());
    let method = &payload[..first_word_end];
    let ok = HTTP_METHODS.iter().any(|m| m.as_bytes() == method)
        && payload.windows(9).any(|w| w == b" HTTP/1.1" || w == b" HTTP/1.0");
    if !ok {
        return;
    }
    let text = String::from_utf8_lossy(&payload[..payload.len().min(1024)]);
    let first = text.lines().next().unwrap_or("");
    let mut parts = first.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    b.suffix.push_str(" HTTPRequest");
    b.field("http.method", method.to_string());
    b.field("http.path", path.to_string());
    if let Some(host) = header_value(&text, "host") {
        b.field("http.host", host);
    }
    if let Some(ua) = header_value(&text, "user-agent") {
        b.field("http.user_agent", ua);
    }
}

/// Record the end of the deepest parsed header (ascii region anchor); only
/// moves forward.
fn end_of(b: &mut Builder, abs_end: usize) {
    // A header length field may point past the captured bytes (doff=15 on a
    // 20-byte TCP header, an 8-byte ICMP echo header on 4 bytes): the ascii
    // region then starts at the end of the frame, never beyond it.
    let abs_end = abs_end.min(b.frame.len());
    if abs_end > b.payload_start {
        b.payload_start = abs_end;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eth(payload_type: u16, body: &[u8]) -> Vec<u8> {
        let mut f = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // dst
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // src
        ];
        f.extend_from_slice(&payload_type.to_be_bytes());
        f.extend_from_slice(body);
        f
    }

    fn eth_ip4(src: [u8; 4], dst: [u8; 4], proto: u8, body: &[u8]) -> Vec<u8> {
        let mut ip = vec![0x45, 0x00, 0x00, 0x00]; // total_len patched below
        ip.extend_from_slice(&[0x00, 0x01]); // id
        ip.extend_from_slice(&[0x40, 0x00]); // flags/frag
        ip.extend_from_slice(&[0x40, proto]); // ttl, proto
        ip.extend_from_slice(&[0x00, 0x00]); // csum
        ip.extend_from_slice(&src);
        ip.extend_from_slice(&dst);
        ip.extend_from_slice(body);
        let total = ip.len() as u16;
        ip[2..4].copy_from_slice(&total.to_be_bytes());
        eth(0x0800, &ip)
    }

    fn eth_ip_proto(proto: u8, tcp_udp_icmp: &[u8]) -> Vec<u8> {
        eth_ip4([10, 0, 0, 1], [10, 0, 0, 2], proto, tcp_udp_icmp)
    }

    #[test]
    fn ether_tcp_syn() {
        let mut tcp = vec![0xd2, 0xf0, 0x00, 0x16]; // 54000 -> 22
        tcp.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 2]); // seq/ack
        tcp.extend_from_slice(&[0x50, 0x02, 0x71, 0x10]); // doff5, SYN, window
        tcp.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);
        tcp.extend_from_slice(b"hello scratch-adjacent world");
        let v = dissect_frame(&eth_ip_proto(6, &tcp));
        assert_eq!(v.summary, "Ether / IP / TCP 10.0.0.1.54000 > 10.0.0.2.22 S");
        assert!(v.fields.contains(&("ip.src".into(), "10.0.0.1".into())));
        assert!(v.fields.contains(&("tcp.flags".into(), "S".into())));
        assert!(v.fields.contains(&("tcp.dport".into(), "22".into())));
        assert_eq!(v.ascii, "hello scratch-adjacent world");
    }

    #[test]
    fn udp_dns_query() {
        let mut dns = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]; // id, rd, qd=1
        for part in ["example", "com"] {
            dns.push(part.len() as u8);
            dns.extend_from_slice(part.as_bytes());
        }
        dns.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
        let mut udp = vec![0xc3, 0x50, 0x00, 0x35, 0x00, 0x1e, 0x00, 0x00]; // 50000->53
        udp.extend_from_slice(&dns);
        let v = dissect_frame(&eth_ip_proto(17, &udp));
        assert_eq!(
            v.summary,
            "Ether / IP / UDP 10.0.0.1.50000 > 10.0.0.2.53 DNS Qry \"example.com.\""
        );
        assert!(v.fields.contains(&("dns.qname".into(), "example.com.".into())));
        assert!(v.fields.contains(&("dns.qtype".into(), "A".into())));
    }

    #[test]
    fn icmp_echo_request() {
        let icmp = vec![8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01];
        let v = dissect_frame(&eth_ip_proto(1, &icmp));
        assert_eq!(v.summary, "Ether / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0");
        assert!(v.fields.contains(&("icmp.type".into(), "8".into())));
    }

    #[test]
    fn arp_who_has() {
        let mut arp = vec![0x00, 0x01, 0x08, 0x00]; // htype, ptype
        arp.extend_from_slice(&[6, 4, 0x00, 0x01]); // hlen, plen, op=request
        arp.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]); // sha
        arp.extend_from_slice(&[192, 168, 56, 101]); // spa
        arp.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // tha
        arp.extend_from_slice(&[192, 168, 56, 102]); // tpa
        let v = dissect_frame(&eth(0x0806, &arp));
        assert_eq!(v.summary, "Ether / ARP who has 192.168.56.102 says 192.168.56.101");
        assert!(v.fields.contains(&("arp.op".into(), "1".into())));
    }

    #[test]
    fn arp_reply_is_at() {
        let mut arp = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x02];
        arp.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        arp.extend_from_slice(&[192, 168, 56, 102]);
        arp.extend_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        arp.extend_from_slice(&[192, 168, 56, 101]);
        let v = dissect_frame(&eth(0x0806, &arp));
        assert!(v.summary.starts_with("Ether / ARP is at 66:77:88:99:aa:bb says 192.168.56.102"));
    }

    #[test]
    fn vlan_tagged() {
        let mut body = vec![0x00, 0x0a, 0x08, 0x00]; // vid 10, inner ethertype IP
        body.extend_from_slice(&eth_ip_proto(1, &vec![8, 0, 0, 0, 0, 0, 0, 1])[14..]);
        let mut tagged = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            0x81, 0x00,
        ];
        tagged.extend_from_slice(&body);
        let v = dissect_frame(&tagged);
        assert_eq!(
            v.summary,
            "Ether / 802.1Q / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0"
        );
        assert!(v.fields.contains(&("vlan.id".into(), "10".into())));
    }

    #[test]
    fn ipv6_neighbor_solicitation_shape() {
        // minimal IPv6 + ICMPv6 echo-request over ether
        let mut ip6 = vec![0x60, 0x00, 0x00, 0x00, 0x00, 0x08, 58, 0x40];
        ip6.extend_from_slice(&[0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20]);
        ip6.extend_from_slice(&[0x30, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x30]);
        ip6.extend_from_slice(&[128, 0, 0, 0, 0, 0, 0, 1]);
        let v = dissect_frame(&eth(0x86dd, &ip6));
        assert!(v.summary.starts_with("Ether / IPv6 / ICMPv6"));
        assert!(v.summary.contains("2000::20 > 3000::30 echo-request 0"));
    }

    #[test]
    fn bare_ipv4_detected() {
        // classic python _packet_from_hex case: no ether header, IP at 0
        let mut ip = vec![0x45, 0x00, 0x00, 0x1c, 0, 1, 0x40, 0x00, 0x40, 1]; // ttl=64, proto=1
        ip.extend_from_slice(&[0, 0]); // csum
        ip.extend_from_slice(&[1, 2, 3, 4]); // src
        ip.extend_from_slice(&[5, 6, 7, 8]); // dst
        ip.extend_from_slice(&[8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01]); // icmp echo
        let v = dissect_frame(&ip);
        assert_eq!(v.summary, "IP / ICMP 1.2.3.4 > 5.6.7.8 echo-request 0");
    }

    #[test]
    fn unknown_ethertype_is_ether_raw() {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&0x9999u16.to_be_bytes());
        f.extend_from_slice(b"junkpayload");
        let v = dissect_frame(&f);
        assert_eq!(v.summary, "Ether / Raw");
        assert_eq!(v.ascii, "junkpayload");
    }

    #[test]
    fn http_request_detected() {
        let mut tcp = vec![0xc3, 0x50, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x18, 0x71, 0x10, 0, 0, 0, 0];
        tcp.extend_from_slice(b"GET /admin HTTP/1.1\r\nHost: target.local\r\nUser-Agent: curl/8.0\r\n\r\n");
        let v = dissect_frame(&eth_ip_proto(6, &tcp));
        assert!(v.summary.starts_with("Ether / IP / TCP 10.0.0.1.50000 > 10.0.0.2.80 PA"), "{}", v.summary);
        assert!(v.fields.contains(&("http.method".into(), "GET".into())));
        assert!(v.fields.contains(&("http.host".into(), "target.local".into())));
        assert!(v.fields.contains(&("http.user_agent".into(), "curl/8.0".into())));
    }

    #[test]
    fn http_response_detected() {
        let mut tcp = vec![0x00, 0x50, 0xc3, 0x50, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x18, 0x71, 0x10, 0, 0, 0, 0];
        tcp.extend_from_slice(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\n\r\n");
        // response traffic rides the reversed direction (server -> client)
        let v = dissect_frame(&eth_ip4([10, 0, 0, 2], [10, 0, 0, 1], 6, &tcp));
        assert!(v.summary.starts_with("Ether / IP / TCP 10.0.0.2.80 > 10.0.0.1.50000 PA"));
        assert!(v.summary.contains("HTTPResponse"));
        assert!(v.fields.contains(&("http.status".into(), "403".into())));
        assert!(v.fields.contains(&("http.reason".into(), "Forbidden".into())));
        assert!(v.fields.contains(&("http.content_type".into(), "text/html".into())));
    }

    #[test]
    fn ascii_runs_minimum_length() {
        let mut f = vec![0u8; 14];
        f[12..14].copy_from_slice(&0x9999u16.to_be_bytes());
        f.extend_from_slice(b"abc"); // too short
        f.push(0x00);
        f.extend_from_slice(b"abcd-much-longer-run");
        let v = dissect_frame(&f);
        assert_eq!(v.ascii, "abcd-much-longer-run");
    }

    // ---------------------------------------------------- robustness ----

    /// Every fixture frame the suite builds, for the sweep below.
    fn fixtures() -> Vec<Vec<u8>> {
        let mut tcp = vec![0xd2, 0xf0, 0x00, 0x16, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x18, 0x71, 0x10, 0, 0, 0, 0];
        tcp.extend_from_slice(b"GET /admin HTTP/1.1\r\nHost: target.local\r\n\r\n");
        let mut dns = vec![0xc3, 0x50, 0x00, 0x35, 0x00, 0x1e, 0x00, 0x00, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        dns.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1]);
        let mut tcp_dns = vec![0, 53, 0, 53, 0, 0, 0, 1, 0, 0, 0, 2, 0x50, 0x18, 0, 0, 0, 0, 0, 0, 0, 17];
        tcp_dns.extend_from_slice(&dns[8..]);
        let mut ip6 = vec![0x60, 0, 0, 0, 0x00, 0x08, 58, 0x40];
        ip6.extend_from_slice(&[0u8; 32]);
        ip6.extend_from_slice(&[128, 0, 0, 0, 0, 0, 0, 1]);
        let mut ip6tcp = vec![0x60, 0, 0, 0, 0, 20 + 14, 6, 0x40];
        ip6tcp.extend_from_slice(&[0u8; 32]);
        ip6tcp.extend_from_slice(&tcp[..34]);
        let mut arp = vec![0x00, 0x01, 0x08, 0x00, 6, 4, 0x00, 0x01];
        arp.extend_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 192, 168, 56, 101, 0, 0, 0, 0, 0, 0, 192, 168, 56, 102]);
        let icmp = eth_ip_proto(1, &[8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, b'p', b'i', b'n', b'g']);
        let mut vlan = vec![0u8; 12];
        vlan.extend_from_slice(&[0x81, 0x00, 0x00, 0x0a, 0x88, 0xa8, 0x00, 0x0b, 0x08, 0x00]);
        vlan.extend_from_slice(&icmp[14..]);
        vec![
            eth_ip_proto(6, &tcp),
            eth_ip_proto(17, &dns),
            eth_ip_proto(6, &tcp_dns),
            icmp.clone(),
            eth(0x86dd, &ip6),
            eth(0x86dd, &ip6tcp),
            eth(0x0806, &arp),
            vlan,
            icmp[14..].to_vec(), // bare IPv4
        ]
    }

    /// The robustness contract: every PREFIX of every fixture (what a
    /// snaplen or a truncated capture actually produces) dissects without
    /// panicking, under every linktype we dispatch on.
    #[test]
    fn prefix_sweep_never_panics() {
        let linktypes = [
            LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6,
            LINKTYPE_LINUX_SLL, LINKTYPE_LINUX_SLL2, LINKTYPE_NULL, LINKTYPE_LOOP, 9999,
        ];
        for f in fixtures() {
            for n in 0..=f.len() {
                for lt in linktypes {
                    let _ = dissect_frame_linktype(&f[..n], lt);
                }
            }
        }
    }

    /// Same, but with every length/offset byte in the headers lying: flip
    /// each byte of each fixture to 0x00 and 0xff in turn.
    #[test]
    fn byte_flip_sweep_never_panics() {
        for f in fixtures() {
            for i in 0..f.len() {
                for v in [0x00u8, 0xff] {
                    let mut g = f.clone();
                    g[i] = v;
                    let _ = dissect_frame(&g);
                }
            }
        }
    }

    // Regressions: the six panics found in review, each by name.

    #[test]
    fn regress_ether_ipv4_no_body() {
        let v = dissect_frame(&eth(0x0800, &[]));
        assert_eq!(v.summary, "Ether");
    }

    #[test]
    fn regress_vlan_tag_cut_off() {
        let v = dissect_frame(&eth(0x8100, &[]));
        assert_eq!(v.summary, "Ether");
        let v = dissect_frame(&eth(0x8100, &[0x00, 0x0a])); // TCI, no inner type
        assert_eq!(v.summary, "Ether / Raw");
    }

    fn ip6_snapped(nh: u8, l4: &[u8]) -> Vec<u8> {
        let mut ip6 = vec![0x60, 0, 0, 0, 0x03, 0xe8, nh, 64]; // plen 1000
        ip6.extend_from_slice(&[0u8; 32]);
        ip6.extend_from_slice(l4);
        eth(0x86dd, &ip6)
    }

    #[test]
    fn regress_ipv6_tcp_plen_beyond_capture() {
        let mut tcp = vec![0, 80, 0xc3, 0x50, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x18, 0, 0, 0, 0, 0, 0];
        tcp.extend_from_slice(b"GET / HTTP/1.1\r\nHost: h\r\n");
        let v = dissect_frame(&ip6_snapped(6, &tcp));
        assert!(v.summary.starts_with("Ether / IPv6 / TCP"), "{}", v.summary);
        assert!(v.summary.ends_with("HTTPRequest"), "{}", v.summary);
    }

    #[test]
    fn regress_ipv6_udp_plen_beyond_capture() {
        let v = dissect_frame(&ip6_snapped(17, &[0, 53, 0, 53, 0, 8, 0, 0, 1, 2, 3]));
        assert!(v.summary.starts_with("Ether / IPv6 / UDP"), "{}", v.summary);
    }

    #[test]
    fn regress_tcp_data_offset_past_capture() {
        let tcp = [0, 80, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0xf0, 0x02, 0, 0, 0, 0, 0, 0];
        let v = dissect_frame(&eth_ip_proto(6, &tcp));
        assert_eq!(v.summary, "Ether / IP / TCP 10.0.0.1.80 > 10.0.0.2.80 S");
        assert_eq!(v.ascii, "");
    }

    #[test]
    fn regress_icmp_echo_four_bytes() {
        let v = dissect_frame(&eth_ip_proto(1, &[8, 0, 0, 0]));
        assert_eq!(v.summary, "Ether / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0");
    }

    // ------------------------------------------------------ linktypes ----

    #[test]
    fn linktype_raw_ip() {
        let ip = eth_ip_proto(1, &[8, 0, 0, 0, 0, 1, 0, 1])[14..].to_vec();
        let v = dissect_frame_linktype(&ip, LINKTYPE_RAW);
        assert_eq!(v.summary, "IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0");
        assert_eq!(dissect_frame_linktype(&ip, LINKTYPE_IPV4).summary, v.summary);
    }

    #[test]
    fn linktype_linux_sll() {
        // tcpdump -i any, v1 cooked header: pkttype 0 (to us), ARPHRD_ETHER,
        // halen 6, addr (8, padded), protocol IPv4.
        let mut f = vec![0, 0, 0, 1, 0, 6, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0, 0, 0x08, 0x00];
        f.extend_from_slice(&eth_ip_proto(1, &[8, 0, 0, 0, 0, 1, 0, 1])[14..]);
        let v = dissect_frame_linktype(&f, LINKTYPE_LINUX_SLL);
        assert_eq!(v.summary, "SLL / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0");
        assert!(v.fields.contains(&("sll.src".into(), "66:77:88:99:aa:bb".into())));
        // The bug this replaces: the same bytes read as Ethernet are garbage.
        assert!(!dissect_frame(&f).summary.contains("ICMP"));
    }

    #[test]
    fn linktype_linux_sll2() {
        let mut f = vec![0x08, 0x00, 0, 0, 0, 0, 0, 3, 0, 1, 4, 6, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0, 0];
        f.extend_from_slice(&eth_ip_proto(1, &[8, 0, 0, 0, 0, 1, 0, 1])[14..]);
        let v = dissect_frame_linktype(&f, LINKTYPE_LINUX_SLL2);
        assert_eq!(v.summary, "SLL2 / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0");
        assert!(v.fields.contains(&("sll.ifindex".into(), "3".into())));
    }

    #[test]
    fn linktype_null_loopback() {
        let mut f = 2u32.to_le_bytes().to_vec(); // AF_INET, host order
        f.extend_from_slice(&eth_ip_proto(1, &[8, 0, 0, 0, 0, 1, 0, 1])[14..]);
        let v = dissect_frame_linktype(&f, LINKTYPE_NULL);
        assert_eq!(v.summary, "Loopback / IP / ICMP 10.0.0.1 > 10.0.0.2 echo-request 0");
    }

    #[test]
    fn unknown_linktype_is_flagged_not_misparsed() {
        let f = eth_ip_proto(1, &[8, 0, 0, 0, 0, 1, 0, 1]);
        let v = dissect_frame_linktype(&f, 127); // 802.11 radiotap
        assert_eq!(v.summary, "Raw (linktype 127 not dissected)");
        assert!(v.fields.contains(&("frame.linktype".into(), "127".into())));
    }
}
