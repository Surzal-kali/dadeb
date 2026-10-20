"""TLS/transport inspector — certificate + protocol posture in one call.

Answers the two recon questions a TLS endpoint raises: WHO is behind the
port (cert subject/issuer/SANs — also a subdomain source for scope and
recon) and HOW strong the handshake is (protocol versions accepted,
chosen cipher, key type/size, expiry runway).  Uses the stdlib ``ssl``
module for live handshakes and ``cryptography`` for certificate parsing;
no external binary.

Honest limits: client-side view only — it reports what THIS client can
negotiate, which is exactly what matters for a browser-class client; it
does not brute-force cipher suites individually (the sweep is per
protocol version, cipher chosen by server preference).  Self-signed lab
certs need ``insecure=True``.

Scope: every call is validated by the operator-armed scope gate
(utils/scope_gate.check_scan) BEFORE the socket opens — TLS handshakes
are real traffic to the target.
"""

from __future__ import annotations

import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any, Dict, List

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtensionOID, NameOID

from constants import framework_tool

_HANDSHAKE_TIMEOUT = 5.0
# ssl.TLSVersion member names differ from labels (TLS 1.0 = TLSv1, no _0).
_SWEEP_VERSIONS = (
    ("TLSv1.3", ssl.TLSVersion.TLSv1_3),
    ("TLSv1.2", ssl.TLSVersion.TLSv1_2),
    ("TLSv1.1", ssl.TLSVersion.TLSv1_1),
    ("TLSv1.0", ssl.TLSVersion.TLSv1),
)


def _days_left(not_after: datetime) -> int:
    return int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)


def _parse_cert(der: bytes) -> Dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    subject = cert.subject
    issuer = cert.issuer
    def _name(name: x509.Name) -> str:
        parts = []
        for attr in name:
            if attr.oid == NameOID.COMMON_NAME:
                parts.append(f"CN={attr.value}")
            elif attr.oid == NameOID.ORGANIZATION_NAME:
                parts.append(f"O={attr.value}")
            elif attr.oid == NameOID.ORGANIZATIONAL_UNIT_NAME:
                parts.append(f"OU={attr.value}")
            elif attr.oid == NameOID.COUNTRY_NAME:
                parts.append(f"C={attr.value}")
        return ", ".join(parts)
    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    sans: List[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        sans = [str(v) for v in ext.value.get_values_for_type(x509.DNSName)]
        sans += [str(v) for v in ext.value.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        pass
    pubkey = cert.public_key()
    if isinstance(pubkey, rsa.RSAPublicKey):
        key = f"RSA-{pubkey.key_size}"
    elif isinstance(pubkey, ec.EllipticCurvePublicKey):
        key = f"EC-{pubkey.curve.name}"
    else:
        key = type(pubkey).__name__
    days = _days_left(not_after)
    return {
        "subject": _name(subject),
        "issuer": _name(issuer),
        "self_signed": issuer == subject,
        "sans_dns_or_ip": sans[:100],
        "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "days_to_expiry": days,
        "expiring_soon": days <= 30,
        "serial": format(cert.serial_number, "x"),
        "signature_algorithm": cert.signature_algorithm_oid._name
        if hasattr(cert, "signature_algorithm_oid")
        else None,
        "key": key,
    }


def _sweep_protocols(host: str, port: int) -> Dict[str, Any]:
    """Try each TLS version; record accepted/refused + the live cipher."""
    accepted: List[str] = []
    refused: List[str] = []
    best: Dict[str, Any] = {}
    for label, enum_version in _SWEEP_VERSIONS:
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = enum_version
            ctx.maximum_version = enum_version
            # Verification OFF by design: a version sweep tests which protocol
            # versions the endpoint NEGOTIATES, not whether its cert chains.
            # Running verification here would report TLSv1.0/1.1 as "refused"
            # whenever the cert is self-signed/expired — a false negative on
            # exactly the legacy-acceptance question this sweep answers.
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=_HANDSHAKE_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as s:
                    proto = s.version() or label
                    cipher = s.cipher()
                    accepted.append(proto)
                    if not best:
                        best = {"protocol": proto, "cipher": cipher[0] if cipher else None, "bits": cipher[2] if cipher else None}
        except ssl.SSLError:
            refused.append(label)
        except (OSError, ValueError):
            refused.append(label)
    return {"accepted": accepted, "refused": refused, "chosen": best}


@framework_tool(
    "Inspect TLS on a target host:port — full certificate details (subject, "
    "issuer, SANs incl. subdomain list, validity window with days-to-expiry, "
    "key type/size, self-signed detection) plus a protocol-version sweep "
    "(TLSv1.0 through 1.3: which versions the endpoint accepts) and the "
    "negotiated cipher. Cert SANs are recon gold for scope expansion and "
    "subdomain takeover work. Self-signed lab certs: insecure=True. "
    "Scope-gated: the handshake is real traffic to the target.",
    next_hints=["check_cors", "check_security_headers", "report_finding", "probe_web"],
)
def tls_info(
    target: str,
    port: int = 443,
    insecure: bool = False,
) -> Dict[str, Any]:
    """TLS handshake + certificate report for ``target:port``.

    Args:
        target: In-scope host or IP (gate-checked before connect).
        port: TLS port (default 443).
        insecure: Skip certificate verification (self-signed lab certs).
    """
    from utils.scope_gate import check_scan, ScopeGateError

    target = (target or "").strip()
    if not target:
        raise ScopeGateError("scope gate: empty target")
    _sc_ok, _sc_reason = check_scan(target)
    if not _sc_ok:
        raise ScopeGateError(f"scope gate: {_sc_reason}")

    started = time.time()
    host_for_sni = target
    try:
        ip = socket.gethostbyname(target)
    except OSError:
        ip = None
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        if insecure:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        else:
            ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        with socket.create_connection(
            (target, int(port)), timeout=_HANDSHAKE_TIMEOUT
        ) as sock:
            with ctx.wrap_socket(sock, server_hostname=host_for_sni) as s:
                der = s.getpeercert(binary_form=True)
                proto = s.version()
                cipher = s.cipher()
    except ssl.SSLCertVerificationError:
        return {
            "status": "Failed",
            "error": (
                "certificate verification failed (self-signed or wrong "
                "hostname?) — retry with insecure=True to inspect anyway"
            ),
            "target": target,
            "port": port,
        }
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        return {
            "status": "Failed",
            "error": f"TLS connect failed: {type(e).__name__}: {e}",
            "target": target,
            "port": port,
        }

    cert = _parse_cert(der)
    sweep = _sweep_protocols(target, int(port))
    tls_versions_accepted = sweep["accepted"]
    weak_versions = [v for v in tls_versions_accepted if v in ("TLSv1", "TLSv1.1")]

    return {
        "status": "Success",
        "target": f"{target}:{port}",
        "resolved_ip": ip,
        "negotiated": {
            "protocol": proto,
            "cipher": cipher[0] if cipher else None,
            "cipher_bits": cipher[2] if cipher else None,
        },
        "certificate": cert,
        "protocol_sweep": sweep,
        "sweep_note": (
            "per-version probes run with certificate verification OFF — "
            "refused/accepted reflect VERSION negotiation only; cert trust "
            "issues do not suppress legacy-version detection."
        ),
        "weak_protocol_flags": (
            [f"{v} accepted (legacy/deprecated)" for v in tls_versions_accepted
             if v in ("TLSv1", "TLSv1.1")]
        ),
        "expiry_note": (
            f"cert expires in {cert['days_to_expiry']} days"
            + (" — EXPIRING SOON" if cert["expiring_soon"] else "")
        ),
        "elapsed_s": round(time.time() - started, 2),
        "note": (
            "SANs are subdomain recon gold — feed interesting entries to "
            "resolve_host/probe_web. Weak protocols and expiry are "
            "report_finding candidates."
        ),
    }
