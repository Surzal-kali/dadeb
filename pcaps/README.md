# Packet Captures

Saved pcap files land here (scapy `wrpcap` output — sniff batches, captured
reply sets, forensic evidence). This directory is **gitignored** — captured
traffic never gets committed.

Save captures (default output root is this folder; override via `PCAP_DIR`):

```python
# Sniff + auto-save in one call
from utils.packetcraft import sniff_to_pcap
sniff_to_pcap(filter="tcp port 80", count=50, timeout=60)
# -> { "out_path": "/abs/pcaps/cap_20260101_120000.pcap", "packet_count": 42, ... }

# Save a batch of hexes (e.g. from sniff_packets or craft_* + replies)
from utils.packetcraft import save_pcap
save_pcap(hexes=["ab12...", "cd34..."], filename="my_capture.pcap")

# List saved captures with sizes, packet counts, timestamps
from utils.packetcraft import list_pcaps
list_pcaps()

# Load all packets from a pcap (paged summaries + hex)
from utils.packetcraft import load_pcap
load_pcap("cap_20260101_120000.pcap", offset=0, limit=20)

# Dissect an individual packet from the returned hexes
from utils.packetcraft import dissect_packet
dissect_packet(hex="<from load_pcap output>")
```

The single-packet `save_packet` / `load_packet` tools remain available for
quick one-off use; `save_pcap` / `load_pcap` / `sniff_to_pcap` / `list_pcaps`
are the batch/forensic lane.