# pcap — dadeb's pcap forensic lane, Rust port (the rustening)

Rust port of the pcap half of [`utils/packetcraft.py`](../../utils/packetcraft.py):
`save_pcap` / `load_pcap` / `list_pcaps` / `sniff_to_pcap`, plus the rustening
centerpiece this crate exists for — **streaming dissection + regex/substring
search over capture FILES**, in the same shape the scratch crate gives tool
results (projection machinery replayed frame-wise). File dissection is where a
compiled-language lane pays off: one streaming pass over bytes instead of a
scapy object graph per frame.

Lane boundaries (deliberate, agreed with the docket notes):

- **This crate** — pcap file codec (streaming reader, golden writer), frame
  dissection (Ether/VLAN/ARP/IPv4/IPv6/TCP/UDP/ICMP(+v6)/DNS/HTTP-shaped),
  frame-level projection (BPF-style substring filter + regex + context frames
  + paging), the python-parity file tools, and (behind the **`capture`
  feature**, default-on) libpcap wire capture.
- **scapy (python)** keeps ALL crafting / modifying / interactive dissection
  (`dissect_packet` shells out per-frame) and the send lane. Live wire work
  that needs crafting stays scapy; this crate's capture lane is
  read-and-file-only.

The python side stays the reference implementation; both sides are
cross-compatible over ordinary `.pcap` files (see *Cross-compat verification*).

## What's ported

| packetcraft.py | Rust | Notes |
|---|---|---|
| `save_pcap` (hex frames → file, `_safe_pcap_name`, cap 100k pkts) | `tools::save_pcap` | python-shaped text return, errors ride INSIDE the text |
| `load_pcap` (page over frames, `hex=`/`summary=`/`ascii=` shapes) | `tools::load_pcap` | **filter/regex/context are first-class args** (new capability, same text shapes) |
| `list_pcaps` (mtime-sorted index) | `tools::list_pcaps` | same shapes; `safe_name` keeps python's `os.path.basename` semantics verbatim |
| packet writer / reader | `format::{PcapWriter, PcapReader, golden_frame, count_records, dissected_frames}` | 24-byte LE header + per-record framing; truncated tails end cleanly |
| `_packet_from_hex` (`Ether / …` summary) | `dissect::dissect_frame` | streaming, allocation-light; see the layer contract below |
| sniff lane | `capture::sniff` + `tools::sniff_to_pcap` (feature `capture`) | libpcap via the `pcap` crate, BPF filter, promisc, 500 ms timeout |
| **NEW** — searchable pcap lane | `projection::{SearchOpts, SearchOutcome, pcap_search}` | structured (JSON-friendly) search outcomes; python has no analogue |

## Layout

```
src/lib.rs         crate docs (lane boundaries) + re-exports
src/config.rs      PcapConfig (PCAP_DIR, caps; with_dir() for tests)
src/format.rs      file codec: header/record parse + golden writer (errors)
src/dissect.rs     frame dissection: layers, transport suffix, ascii regions
src/projection.rs  filter/regex/context/paging over dissected frames (SearchOpts/SearchOutcome)
src/tools.rs       python-parity lane: save/load/list/sniff_to_pcap (+ parse_hex_frame)
src/capture.rs     libpcap sniff lane (feature `capture`); CaptureError + error-text mapping
examples/pcapinfo.rs  operator CLI: summary/write/count/read/search/list/bpf
```

## Config knobs

Captured once at `PcapConfig::from_env()` — mirrors python's config block:

| Env | Default | Meaning |
|---|---|---|
| `PCAP_DIR` | workspace `pcap/` | where `save_pcap` writes and `list_pcaps` indexes |
| `PCAP_MAX_PACKETS_PER_FILE` | 100000 | `save_pcap` refuses past this |
| `PCAP_MAX_FILE_MB` | 512 | `load_pcap` size guard (over-cap → the "use tcpdump/tshark" message) |
| `PACKET_CRAFT` | `enp92s0` | default interface for `sniff_to_pcap` |

Env-hazard note for `from_env()`: `WORKSPACE_ROOT` / brain env can hijack the
default dir on lanes where the checkout is read-only. **All tests** construct
via `PcapConfig::with_dir(tempdir::TempDir)` — never the env constructor.

## The dissection layer contract

`dissect_frame(&[u8]) -> Dissected` produces scapy-shaped summaries of the form
`Ether / IP / TCP 10.0.0.1.50000 > 10.0.0.2.80 PA` + an appended suffix per
application layer, matching python's summary text:

- **Transport sets the suffix** (`{src}.{sport} > {dst}.{dport} {flags}`);
  DNS/HTTP **append** to it (`DNS Qry "…"` / `HTTPRequest` / `HTTPResponse`).
  Application layers never push their own layer token — the summary stays
  `Ether / IP / TCP … HTTPRequest`, one push per header, like scapy.
- ICMP pushes its own layer (`ICMP`/`ICMPv6`) and suffixes `{src} > {dst} {name} {code}`;
  ARP pushes `ARP` and suffixes `who has {pdst} says {psrc}` / `is at {sha} says {psrc}`.
- `ascii` regions (payload start → end) are computed from the **deepest
  header end**, not layer end — DNS/HTTP text search works on actual payload.
- **L2/L3 discriminator** (deviating from python honestly): recognized
  ethertypes (0x0800/0x0806/0x86dd/0x8100/0x88a8) dispatch as Ethernet (with
  a VLAN walk); otherwise a 0x4 nibble with a ≥20-byte frame is treated as a
  bare IPv4 packet at offset 0 (0x6 → bare IPv6, ≥40 bytes); anything else is
  Ether/Raw. Python routes any *unrecognized* ethertype with a 0x4/0x6 nibble
  to a bare-IP parse too, so this is a *narrowing*, not a divergence for the
  frames real captures carry.
- Port summaries are numeric — no `/etc/services` resolution (a capture
  dissection must not depend on the dissecting box's services file).

## The search lane

`SearchOpts { filter, regex, context_frames, offset, limit }`:

- `filter` — BPF-style substring match, case-insensitive, over every frame
  surface (summary, ascii payload, hex, L7 fields). Substring beats regex per
  surface (scratch's rule); all surfaces may be tested per frame, and any hit
  selects it.
- `regex` — case-insensitive when no exact-case hit wins (same rule as the
  scratch projection).
- `context_frames` — ±N neighbor frames around each hit, rendered like python
  pages with `...` separators.
- `offset`/`limit` — paging both for the plain (unfiltered) walk and the
  filtered lane; filtered replies end with the ready-made
  `load_pcap('<file>', filter=…, offset=<next>, limit=…) … for the next page.` hint.
- Structured lane: `pcap_search` returns `SearchOutcome` (per-hit `OutcomeEntry`
  with `kind`, `frame_index`, `ts`, `summary`, `hex`, `ascii`, `matches`,
  meta: surfaces probed, total frames, bytes scanned) — the pcap analogue of
  scratch's `SearchMeta`.

`load_pcap` dispatches: no filter+regex → python-parity page walk; with either
→ the search pipeline with identical text shapes.

## Capture lane (`capture` feature, default)

`sniff(interface, bpf_filter, count, timeout)`:

- `pcap::Capture::from_device(interface)` → `.promisc(true).snaplen(262_144)`
  (MAX_SNAPLEN parity) `.timeout(500)` — the binding takes an `i32` of
  **milliseconds**, not a Duration.
- BPF compilation via `cap.filter(program, true)` (optimize=true); bad BPF
  surfaces as `CaptureError::Filter` mapped into the python-shaped error text.
- `next_packet()`'s `Err(libpcap::Error::TimeoutExpired)` is the *normal*
  end-of-count signal, not an error.
- **Requires CAP_NET_RAW** to actually open the interface (packet socket).
  Root-less lanes fail at *open*, before BPF compiles, with
  "Attempt to create packet socket failed - CAP_NET_RAW may be required" —
  surfaced in the error text keyword list. Tests that reach the BPF lane are
  capability-gated (probe `/proc/self/status` CapEff bit 13) instead of assumed.
- `sniff_to_pcap` wraps `sniff` into `save_pcap` output (python-shaped):
  sniff → write → "Captured {n} packet(s) …" text.

Not ported: live crafting/modify/send (stays scapy), pcapng files (refused —
LE header magic is authoritative, pcapng starts with 0x0A0D0D0A).

## Divergences from python, all deliberate

- No service-name resolution (`/etc/services`): ports stay numeric everywhere.
- Timestamps UTC (python rendered local time).
- `load_pcap`'s filter/regex/context/paging are first-class args (python
  `load_pcap` has zero filtering — this is the new capability, text shapes kept).
- `grepped_surfaces` from the scratch map is dropped here: selection is
  frame-level, per-frame tested surfaces live in structured rows.
- Bare-IP discriminator narrowed as described above (unrecognized-ethertype
  frames with a 4/6 nibble parse as bare IP only when the header actually fits).
- The **analysis snapshot cache is NOT extended here** — captures are
  observations of a changing world, the cache is for deterministic-tool lanes.
- Frame-by-frame equivalence is the compat contract, not file bytes: scapy and
  this writer disagree on timestamp sub-second zero-fill, so a scapy-written
  file and a this-writer-written file holding the same frames hash differently.
  Compare `count`/`summary` shapes, never `sha256`.

## Test discipline

- Every file-touching test uses `PcapConfig::with_dir(tempdir)` — env-derived
  default dirs are a cross-lane hazard (`WORKSPACE_ROOT`, brain env).
- Golden-writer tests pin the exact 24-byte header + record layout bytes
  (`golden_frame_bytes_match_writer_layout`), so byte-level compat is testable.
- The oversize test writes a *real* oversized `incl_len` record header
  (0x7fffffff) and asserts `OversizedRecord` names the 262144 cap.
- BPF-lane tests branch on the box's capabilities (`cap_net_raw()` probe) —
  with the cap the filter error is asserted, without it the open error text is.

## Building + tests

```bash
cd rust/pcap
cargo test      # 38 tests: codec, dissection, projection, tools text shapes, capture-gate
cargo build --no-default-features   # libpcap-free profile (tools/format/project only)
```

## Cross-compat verification (verified live)

```bash
cd rust/pcap
mkdir -p /tmp/pcap-compat

# 1. Scapy writes a mixed file (TCP/UDP-DNS/ARP, both directions)
python3 -c "
from scapy.all import wrpcap, IP, TCP, Ether, UDP, DNS, DNSQR, ARP, Raw
wrpcap('/tmp/pcap-compat/scapy.pcap', [
  Ether()/IP(src='192.168.56.106', dst='192.168.56.107')/TCP(sport=50000, dport=80, flags='PA')/Raw(b'GET /admin?q=x HTTP/1.1\r\nHost: t\r\n\r\n'),
  Ether()/IP(src='192.168.56.107', dst='192.168.56.106')/TCP(sport=50001, dport=53, flags='PA')/Raw(b'HTTP/1.1 302 Found'),
  Ether()/ARP(pdst='192.168.56.1', psrc='192.168.56.106', op=1),
])
"

# 2. Rust reads it
cargo run --example pcapinfo -- read /tmp/pcap-compat/scapy.pcap --limit 4
# → Ether / IP / TCP … HTTPRequest / HTTPResponse / Ether / ARP who has …
cargo run --example pcapinfo -- search /tmp/pcap-compat/scapy.pcap --regex "who|401"

# 3. Rust writes a frame (hex from step 2), scapy reads it back
cargo run --example pcapinfo -- write /tmp/pcap-compat/rust.pcap ffffff...0d0a
python3 -c "
from scapy.all import rdpcap, Ether, IP, TCP
p = rdpcap('/tmp/pcap-compat/rust.pcap')
assert Ether in p[0] and IP in p[0] and TCP in p[0]
assert (p[0][TCP].sport, p[0][TCP].dport) == (50000, 80)
print('scapy read rust-written frame:', p[0].summary())
"
```

Both directions must hold: rust's `summary:/hex:/ascii:` shapes byte-match the
python dissector's, and rdpcap parses this writer's files as full Ether/IP/TCP
stacks with untouched ports and payload.

## Where this slots in

- The python `packetcraft.py` lane keeps serving crafting (`sniff`+scapy);
  this crate is the file-forensic lane — load_pcap/search on files, sniff→file
  capture for the same shapes.
- Same projection philosophy as `rust/scratch`: filter surfaces, context
  windows, ready-made paging continuations — here at frame granularity with
  structured per-hit entries for model lanes that want JSON.