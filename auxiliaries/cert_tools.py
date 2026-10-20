"""TLS certificate tooling.

Two families live here:
1. Self-signed cert generation for the OOB collaborator (generate_certs /
   clear_certs) — the collaborator listener (``listeners/collaborator.py``)
   serves HTTPS on TCP 443 from ``utils/plugins/certs/``.
2. Certificate INSPECTION (inspect_host / inspect_pem) — read-only analysis
   of a remote endpoint's leaf certificate or a provided cert blob. The
   inspection family exists to answer pinning-era questions in the pin
   vocabulary the app under test actually uses: base64(SHA1(SPKI DER)) — the
   format OkHttp CertificatePinner holds in decompiled smali pin arrays.
   Cert fingerprints change on every re-issuance; the SPKI hash only moves
   when the KEY moves, which is exactly the distinction a pin-rotation
   tripwire needs.
"""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import socket
import ssl
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

from constants import framework_tool, resolve_workspace_root


def _cert_dir() -> Path:
    """Resolve the certs directory the same way the collaborator does."""
    return resolve_workspace_root() / "utils" / "plugins" / "certs"


@framework_tool(
    "Generate a fresh self-signed TLS certificate (cert.pem + key.pem) for "
    "the OOB collaborator's HTTPS listener on TCP 443. Writes the files into "
    "utils/plugins/certs/ and overwrites any existing cert there. Use this "
    "when the collaborator is skipping HTTPS because the certs are missing, "
    "or when you want to rotate the cert.",
    next_hints=["framework_health"],
)
def generate_certs(common_name: str = "localhost", days: int = 365) -> Dict[str, Any]:
    """Generate a self-signed cert + key pair via ``openssl``.

    Runs ``openssl req -x509 -newkey rsa:2048`` with no passphrase
    (``-nodes``) so the collaborator can load it unattended.  Overwrites
    any existing ``cert.pem`` / ``key.pem`` in the certs directory.

    Args:
        common_name: Subject CN for the cert (default ``"localhost"``).
        days: Validity period in days (default ``365``).

    Returns a dict with ``status`` (``"ok"`` / ``"error"``), the resolved
    certs directory, and the generated file paths on success.
    """
    import subprocess

    cert_dir = _cert_dir()
    cert_dir.mkdir(parents=True, exist_ok=True)
    cert_path = cert_dir / "cert.pem"
    key_path = cert_dir / "key.pem"

    if shutil.which("openssl") is None:
        return {
            "status": "error",
            "error": "openssl not found on PATH; install openssl-cli to generate certs",
            "certs_dir": str(cert_dir),
        }

    cmd = [
        "openssl", "req", "-x509", "-newkey", "rsa:2048",
        "-keyout", str(key_path), "-out", str(cert_path),
        "-days", str(days), "-nodes",
        "-subj", f"/CN={common_name}",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True)
    except Exception as exc:
        return {
            "status": "error",
            "error": f"openssl invocation failed: {exc}",
            "certs_dir": str(cert_dir),
        }

    if proc.returncode != 0:
        return {
            "status": "error",
            "error": f"openssl exited {proc.returncode}",
            "stderr": proc.stderr.strip(),
            "certs_dir": str(cert_dir),
        }

    return {
        "status": "ok",
        "certs_dir": str(cert_dir),
        "cert": str(cert_path),
        "key": str(key_path),
        "common_name": common_name,
        "days": days,
    }


@framework_tool(
    "Clear the OOB collaborator's TLS certificate by removing cert.pem and "
    "key.pem from utils/plugins/certs/. After this, the collaborator's HTTPS "
    "listener on TCP 443 will be skipped on next startup (HTTP on 80 and DNS "
    "on UDP 53 keep working). The certs directory itself is preserved.",
    next_hints=["framework_health"],
)
def clear_certs() -> Dict[str, Any]:
    """Remove ``cert.pem`` and ``key.pem`` from the certs directory.

    Idempotent: missing files are not an error.  The directory itself is
    never removed so the collaborator's path resolution stays valid.

    Returns a dict with ``status`` (always ``"ok"``), the certs directory,
    and a list of the files that were removed.
    """
    cert_dir = _cert_dir()
    removed: list[str] = []
    for name in ("cert.pem", "key.pem"):
        target = cert_dir / name
        if target.is_file():
            target.unlink()
            removed.append(name)
    return {
        "status": "ok",
        "certs_dir": str(cert_dir),
        "removed": removed,
    }


# ---------------------------------------------------------------------------
# Inspection family — read-only cert analysis
# ---------------------------------------------------------------------------

def _cert_fields(der: bytes) -> Dict[str, Any]:
    """Extract the inspection field set from a DER-encoded leaf certificate.

    The SPKI fields are the money: base64(SHA1(SPKI DER)) is the exact
    string format OkHttp CertificatePinner pins carry in decompiled smali,
    so it can be compared directly against values like
    ``Ig2WwRMB85wQAed8JEkBXBaWics=`` without any conversion step.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        PublicFormat,
    )

    cert = x509.load_der_x509_certificate(der)
    now = datetime.now(timezone.utc)
    not_before = cert.not_valid_before_utc
    not_after = cert.not_valid_after_utc

    spki = cert.public_key().public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    key = cert.public_key()

    try:
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": round((not_after - now).total_seconds() / 86400.0, 2),
        "serial_hex": format(cert.serial_number, "x"),
        "sans_dns": sans,
        "key_type": type(key).__name__,
        "key_bits": getattr(key, "key_size", None),
        # Cert-level fingerprints: change on EVERY re-issuance.
        "sha1_cert_fp_b64": base64.b64encode(cert.fingerprint(hashes.SHA1())).decode("ascii"),
        "sha256_cert_fp_b64": base64.b64encode(cert.fingerprint(hashes.SHA256())).decode("ascii"),
        # SPKI-level hashes: change only when the KEY changes. spki_sha1_b64
        # is the CertificatePinner pin format.
        "spki_sha1_b64": base64.b64encode(hashlib.sha1(spki).digest()).decode("ascii"),
        "spki_sha256_b64": base64.b64encode(hashlib.sha256(spki).digest()).decode("ascii"),
    }


def _load_cert_input(cert_data: str) -> tuple:
    """Parse ``inspect_pem``'s flexible input into (der_bytes, source_label).

    Accepts, in order:
    1. PEM text (``-----BEGIN CERTIFICATE-----``)
    2. Base64-encoded DER (single blob, with or without newlines)
    3. A filesystem path to a PEM or DER cert file
    """
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding

    text = (cert_data or "").strip()
    if not text:
        raise ValueError("cert_data is empty")

    if "-----BEGIN CERTIFICATE-----" in text:
        cert = x509.load_pem_x509_certificate(text.encode("utf-8"))
        return cert.public_bytes(Encoding.DER), "pem"

    candidate = Path(text)
    try:
        candidate_is_file = candidate.is_file()
    except OSError:
        # Not a plausible path at all — most notably a long, slash-free
        # base64 blob: the whole string is one path component over the
        # 255-byte filename limit, so stat() raises ENAMETOOLONG (Errno 36)
        # instead of returning False. Falling through to the b64 branch is
        # the only correct verdict for such input.
        candidate_is_file = False
    if candidate_is_file:
        raw = candidate.read_bytes()
        if b"-----BEGIN CERTIFICATE-----" in raw:
            cert = x509.load_pem_x509_certificate(raw)
            return cert.public_bytes(Encoding.DER), "file:pem"
        return raw, "file:der"

    compact = "".join(text.split())
    try:
        der = base64.b64decode(compact, validate=True)
        # sanity: a DER certificate is a SEQUENCE; long-form length → 0x30 0x82
        if der[:1] != b"\x30":
            raise ValueError("not a DER structure")
        return der, "der"
    except Exception as exc:
        raise ValueError(
            "cert_data is not PEM text, base64 DER, or an existing file path"
        ) from exc


@framework_tool(
    "Fetch and inspect a host's leaf TLS certificate over a live connection "
    "(TCP connect + TLS handshake, no HTTP request). Reports the pin-relevant "
    "fields: spki_sha1_b64 (the OkHttp CertificatePinner pin format, directly "
    "comparable against decompiled smali pin arrays) and spki_sha256_b64, plus "
    "issuer, subject, SANs, notBefore/notAfter, days_remaining, cert "
    "fingerprints, key type/bits, TLS version, and the standard-chain "
    "verification verdict as data. LIVE NETWORK FETCH — only use for targets "
    "confirmed in-scope via check_scope; this tool connects to the target. "
    "For offline analysis (CT-log/crt.sh-served certs, APK-bundled CAs, "
    "automation-safe checks) use inspect_pem instead.",
    next_hints=["check_scope", "report_finding"],
)
def inspect_host(host: str, port: int = 443, sni: str = "", timeout: int = 8) -> Dict[str, Any]:
    """Live leaf-certificate inspection of ``host:port``.

    Performs ONE TLS handshake. A standard verified handshake is attempted
    first; if the chain/hostname fails verification the cert is still
    captured via a verify-disabled retry and the verification failure is
    reported as data (this tool is a microscope, not a judge).

    Args:
        host: Hostname or IP to connect to.
        port: TLS port (default 443).
        sni: Optional SNI hostname override (defaults to ``host``). Use when
            probing a vhost/edge that serves a different name than the
            connect address (e.g. CDN edges).
        timeout: Connect + handshake timeout in seconds (default 8).

    Returns a dict with ``status``, the certificate field set, ``endpoint``,
    ``tls_version``, and ``verification`` (``ok`` or the failure reason).
    """
    server_name = sni.strip() or host
    endpoint = f"{host}:{port}"

    def _handshake(ctx: ssl.SSLContext):
        with socket.create_connection((host, port), timeout=timeout) as raw:
            raw.settimeout(timeout)
            with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
                der = tls.getpeercert(binary_form=True)
                version = tls.version()
                cipher = tls.cipher()[0] if tls.cipher() else None
                return der, version, cipher

    verification = "ok"
    verify_detail = None
    try:
        der, version, cipher = _handshake(ssl.create_default_context())
    except ssl.SSLCertVerificationError as exc:
        verification = "failed"
        verify_detail = str(exc).split("(")[0].strip()
        try:
            lax = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            lax.check_hostname = False
            lax.verify_mode = ssl.CERT_NONE
            der, version, cipher = _handshake(lax)
        except (OSError, ssl.SSLError) as exc2:
            return {
                "status": "error",
                "endpoint": endpoint,
                "verification": verification,
                "verification_detail": verify_detail,
                "error": f"TLS handshake failed after verify-disabled retry: {exc2}",
            }
    except (OSError, ssl.SSLError) as exc:
        return {
            "status": "error",
            "endpoint": endpoint,
            "error": f"TLS connect/handshake failed: {exc}",
        }

    if not der:
        return {"status": "error", "endpoint": endpoint, "error": "no peer certificate returned"}

    fields = _cert_fields(der)
    return {
        "status": "ok",
        "source": "live",
        "endpoint": endpoint,
        "sni": server_name,
        "tls_version": version,
        "cipher": cipher,
        "verification": verification,
        **({"verification_detail": verify_detail} if verify_detail else {}),
        **fields,
    }


@framework_tool(
    "Inspect a TLS certificate OFFLINE (zero network traffic) from PEM text, "
    "base64 DER, or a filesystem path to a cert file. Reports the same "
    "pin-relevant field set as inspect_host: spki_sha1_b64 (OkHttp "
    "CertificatePinner pin format), spki_sha256_b64, issuer, subject, SANs, "
    "notBefore/notAfter, days_remaining, cert fingerprints, key type/bits. "
    "This is the automation-safe lane: feed it certs pulled from crt.sh/CT "
    "logs or extracted from APK assets and compare against decompiled pin "
    "arrays without touching the target.",
    next_hints=["report_finding"],
)
def inspect_pem(cert_data: str) -> Dict[str, Any]:
    """Offline certificate inspection from a provided blob or file path.

    Args:
        cert_data: One of — PEM text (``-----BEGIN CERTIFICATE-----``),
            base64-encoded DER, or a path to a PEM/DER cert file.

    Returns a dict with ``status``, ``source`` (``pem``/``der``/``file:*``)
    and the certificate field set.
    """
    try:
        der, source = _load_cert_input(cert_data)
    except Exception as exc:
        return {"status": "error", "error": str(exc)}

    try:
        fields = _cert_fields(der)
    except Exception as exc:
        return {"status": "error", "source": source, "error": f"cert parse failed: {exc}"}

    return {"status": "ok", "source": source, **fields}