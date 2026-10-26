"""Findings contract: the versioned results format shared by CLI, agents, service.

* ``SCHEMA`` is JSON Schema (draft 2020-12) for ``findings/1.x`` documents; the
  published copy lives in ``schemas/findings-<SCHEMA_VERSION>.schema.json``
  (earlier minor versions stay published unchanged).
* ``CHECK_IDS`` is the registry of stable check identifiers.  New ids are a
  minor-version change; renaming or removing one requires a new major version.
* ``load_document`` is the single entry point for consuming documents: it
  rejects unsupported major versions and validates structure.
* ``redact`` scrubs known secret values (and common encodings of them) plus
  any private-key PEM blocks before a document leaves the process.

Standard library only: agents and the service validate with the same code.
"""

from __future__ import annotations

import base64
import json
import re
import urllib.parse
from typing import Any, Dict, Iterable, List

SCHEMA_VERSION = "1.7"   # 1.1: facts block; 1.2: failure classification;
                         # 1.3: cause limitations, observation classes, endpoint state;
                         # 1.4: legacy-protocol acceptance classes;
                         # 1.5: finding uncertainty, unresolved diagnosis entries,
                         #      default-probe states, endpoint address coverage;
                         # 1.6: check id nginx.path_resolution;
                         # 1.7: certificate/service check ids, key and verifier
                         #      failure kinds, facts.certificates,
                         #      diagnosis.unexplained
SUPPORTED_MAJOR = 1

# Machine-readable classification of a failed probe.  "What went wrong" is
# separate from the finding status, because a stall and a rejection both end in
# FAIL while having different owners (network path vs. server configuration).
# Empty string = no classified failure (including every PASS).
FAILURE_KINDS: Dict[str, str] = {
    "connect-timeout": "the TCP connect to the probed address timed out",
    "negotiation-timeout": "the socket opened but the peer sent no TLS response in time",
    "tls-alert": "the peer rejected the offer with a TLS alert or no shared cipher",
    "network-error": "the connection was reset or became unreachable during negotiation",
    "no-version-accepted": "every per-version probe was refused",
    "no-version-answered": "every per-version probe stalled or errored without a TLS answer",
    "probe-inconclusive": "the probe could not establish a result within the evidence available",
    "endpoint-unreachable": "no endpoint could be reached to collect certificate evidence",
    # 1.7: why a certificate or key question stayed open (never a defect)
    "verifier-unavailable": "no tool was available to verify signatures or keys",
    "key-encrypted": "the private key is passphrase-encrypted, so it was not read",
    "key-unreadable": "the private key exists but this account cannot read it",
    "command-failed": "a command needed for the check exited unsuccessfully",
    "permission-denied": "the check needs access this account does not have",
    # 1.7: what is wrong with a certificate chain (tls.chain, nginx.chainfile,
    # cert.chainfile), so correlation never parses evidence text
    "chain-signature": "a link's signature, CA flag or path length does not verify",
    "chain-misordered": "a certificate is not followed by the certificate that issued it",
    "chain-incomplete": "the issuer of the top certificate was not included",
    "chain-unverified": "links match by name only; signatures could not be verified",
    "chain-hygiene": "the chain repeats certificates or holds unrelated ones",
    "chain-wrong-leaf": "the file does not start with the server certificate",
}

# Failure kinds that describe the path to the endpoint, not the endpoint's
# certificate or configuration: a FAIL carrying one never decides the verdict.
TRANSPORT_FAILURE_KINDS = ("connect-timeout", "negotiation-timeout", "network-error",
                           "endpoint-unreachable")

# Machine-readable classes for things that were *observed* but are not failures.
# Kept apart from FAILURE_KINDS so a diagnosis can treat an observation as
# corroboration instead of turning it into a defect.
OBSERVATIONS: Dict[str, str] = {
    "endpoint-certificate-difference":
        "two or more comparable endpoints presented different certificate facts",
    "endpoint-comparison-inconclusive":
        "fewer than two endpoints yielded comparable certificate evidence",
    "sni-certificate-differs":
        "a different certificate is served when the client sends no SNI",
    "sni-without-probe-failed":
        "the certificate served without SNI could not be obtained",
    "probe-inconclusive":
        "at least one protocol-version probe produced no definite result",
    "legacy-accepted-default":
        "deprecated TLS versions were accepted with the default cipher policy",
    "legacy-accepted-relaxed-only":
        "deprecated TLS versions were accepted only when legacy cipher suites were "
        "offered; a default-configured client is refused by the server",
    "legacy-accepted-unverified":
        "deprecated TLS versions answered only under a relaxed cipher policy and the "
        "default-policy probe could not establish ordinary-client compatibility",
    "tls12-relaxed-only":
        "TLS 1.2 answers only when legacy cipher suites are offered, so a "
        "default-configured client is refused",
}

# Endpoint probe states (see netchecks._probe_endpoint).
ENDPOINT_STATES = ["negotiated", "tls-rejected", "tcp-unreachable", "timed-out",
                   "probe-unavailable"]

CHECK_IDS: Dict[str, str] = {
    # remote network
    "net.dns": "DNS resolution of the target hostname",
    "net.tcp": "TCP connectivity to the target port",
    "tls.handshake": "Unauthenticated TLS handshake: protocol, cipher, presented chain",
    "tls.certvalid": "Validity period of the presented leaf",
    "tls.hostname": "Hostname coverage by subjectAltName",
    "tls.chain": "Completeness and linkage of the chain the server sends",
    "tls.verify": "Validation against the full system trust store",
    "tls.verify.rootonly": "Validation against trusted roots only (no cached intermediates)",
    "tls.protocols": "TLS protocol version matrix",
    "tls.sni": "Certificate difference with and without SNI",
    "tls.multiip": "Certificate consistency across DNS endpoints",
    "tls.weakcipher": "Acceptance of obsolete cipher suites",
    "https.response": "HTTPS response and redirect analysis",
    "scan.domain": "Domain identity profile",
    # local machine / certificate files
    "local.os": "Operating system and clock",
    "local.clockskew": "System clock versus server clock",
    "local.proxy": "Proxy configuration",
    "local.certstore": "Windows certificate stores",
    "local.rootca": "Expected root CA present in the Windows ROOT store",
    "local.certutil": "Windows chain engine validation (certutil)",
    "local.events": "Schannel event log",
    "cert.parse": "Certificate file parsing",
    "cert.validity": "Validity period of an inspected certificate file",
    "cert.selfsigned": "Self-signed inspected certificate",
    "cert.hostname": "Hostname coverage of an inspected certificate file",
    "cert.chainfile": "Chain structure inside an inspected file",
    "cert.keymatch": "Certificate / private key pairing (digest comparison)",
    # server side
    "ssh.hostkey": "SSH host key verification",
    "ssh.auth": "SSH authentication",
    "ssh.state": "SSH session state",
    "srv.os": "Server OS and identity",
    "srv.web": "Web server detection",
    "srv.cert": "Certificate file on the server",
    "srv.keymatch": "Certificate / key pairing on the server",
    "srv.perms": "Certificate and key file permissions",
    "srv.tlsconf": "TLS virtual host configuration overview",
    "srv.logs": "TLS-related service log entries",
    "srv.compare": "Configured versus presented certificate",
    "nginx.conf": "Nginx configuration source",
    "nginx.blocks": "Nginx server block inventory",
    "nginx.domain": "Nginx server block selected for the domain and port",
    "nginx.protocols": "Nginx ssl_protocols of the selected block",
    "nginx.ciphers": "Nginx ssl_ciphers of the selected block",
    "nginx.certref": "Certificate and key referenced by the selected block",
    "nginx.path_resolution": "Certificate and key file paths: resolution and access",
    "nginx.chainfile": "Linkage of the ssl_certificate file",
    # 1.7: verified certificate analysis
    "chain.validity": "Validity period of every non-leaf certificate in a chain",
    "chain.usage": "Basic Constraints, Key Usage and Extended Key Usage of a chain",
    "chain.trust": "Validation of a chain to a named trust anchor, and its trust class",
    "cert.policy": "Key strength and signature algorithm policy",
    "cert.cafile": "Root / CA bundle file parsing and classification",
    "tls.revocation": "OCSP / CRL revocation status",
    # 1.7: TLS service deployment on the server
    "srv.service": "Process that terminates TLS on the target port",
    "srv.configtest": "Native configuration test of the TLS service",
    "srv.reload": "Reload state of the service after certificate changes",
    "srv.renewal": "Renewal tooling that manages the configured certificate",
    "srv.keystartup": "Encrypted private key versus service startup configuration",
    "srv.inventory": "Every certificate configured for the TLS service",
}

# 1.7: certificate facts per judged chain
_CERT_ROLES = ["leaf", "intermediate", "root", "unrelated", ""]
_LINK_STATES = ["verified", "signature-failed", "name-mismatch", "name-only",
                "not-a-ca", "anchor", ""]
_TRUST_CLASSES = ["public", "private", "self-signed", "unknown", ""]
_REVOCATION_STATES = ["good", "revoked", "unavailable", "not-checked", "inconclusive", ""]
_CHAIN_SOURCES = ["presented", "configured", "supplied"]
_NULLABLE_STR = {"type": ["string", "null"]}
_STR_LIST = {"type": "array", "items": {"type": "string"}}
_CERTIFICATE: Dict[str, Any] = {
    "type": "object",
    "required": ["position", "sha256"],
    "properties": {
        "position": {"type": "integer"},
        "role": {"type": "string", "enum": _CERT_ROLES},
        "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
        "subject": {"type": "string"},
        "issuer": {"type": "string"},
        "not_before": _NULLABLE_STR,
        "not_after": _NULLABLE_STR,
        "key_type": {"type": "string"},
        "key_bits": {"type": ["integer", "null"]},
        "curve": {"type": "string"},
        "signature_algorithm": {"type": "string"},
        "ca": {"type": ["boolean", "null"]},
        "path_len": {"type": ["integer", "null"]},
        "key_usage": _STR_LIST,
        "extended_key_usage": _STR_LIST,
        "ski": {"type": "string"},
        "aki": {"type": "string"},
        # how this certificate's link to the next one was established
        "link": {"type": "string", "enum": _LINK_STATES},
    },
}
_CHAIN: Dict[str, Any] = {
    "type": "object",
    "required": ["source", "certificates"],
    "properties": {
        "source": {"type": "string", "enum": _CHAIN_SOURCES},
        "path": {"type": "string"},
        "status": {"type": "string", "enum": ["complete", "incomplete", "broken", "unread"]},
        "trust_class": {"type": "string", "enum": _TRUST_CLASSES},
        "anchor": {"type": "string"},
        "revocation": {"type": "string", "enum": _REVOCATION_STATES},
        "certificates": {"type": "array", "items": _CERTIFICATE},
    },
}

_STATUS = ["PASS", "FAIL", "WARNING", "NOT TESTED"]
_SCOPE = ["local", "remote-net", "server"]
_CHECK_RE = r"^[a-z]+(\.[a-z0-9_]+)+$"
_FAILURE_KINDS = [""] + list(FAILURE_KINDS)
_OBSERVATIONS = [""] + list(OBSERVATIONS)
_PROBE_SUPPORT = ["", "default", "relaxed-only", "relaxed-only-unverified",
                  "rejected", "inconclusive"]
# Raw outcome of a default-policy probe; "client-limited" = never sent.
_PROBE_STATES = ["accepted", "refused", "inconclusive", "unsupported", "client-limited"]

SCHEMA: Dict[str, Any] = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "https://ssl-doctor.dev/schemas/findings-1.1.schema.json",
    "title": "SSL Doctor findings document",
    "type": "object",
    "required": ["schema_version", "tool", "generated_utc", "summary", "findings"],
    "properties": {
        "schema_version": {"type": "string", "pattern": r"^1\.[0-9]+$"},
        "tool": {"type": "string"},
        "generated_utc": {"type": "string"},
        "meta": {"type": "object"},
        "summary": {
            "type": "object",
            "required": _STATUS,
            "properties": {s: {"type": "integer"} for s in _STATUS},
        },
        "diagnosis": {
            "type": ["object", "null"],
            "required": ["overall", "causes", "notes"],
            "properties": {
                "overall": {"type": "string", "enum": ["PASS", "WARNING", "FAIL"]},
                "causes": {"type": "array", "items": {
                    "type": "object",
                    "required": ["rank", "certainty", "origin", "summary", "evidence"],
                    "properties": {
                        "rank": {"type": "integer"},
                        "certainty": {"type": "string",
                                      "enum": ["confirmed", "probable", "possible"]},
                        "origin": {"type": "string",
                                   "enum": ["network", "server", "client", "certificate"]},
                        "summary": {"type": "string"},
                        "evidence": {"type": "array", "items": {"type": "string"}},
                        "recommendation": {"type": "string"},
                        # 1.3: where the evidence for this cause is incomplete
                        "limitations": {"type": "array", "items": {"type": "string"}},
                    },
                }},
                "notes": {"type": "array", "items": {"type": "string"}},
                # 1.5: warnings that stay open because no cause is justified
                "unresolved": {"type": "array", "items": {
                    "type": "object",
                    "required": ["check", "status", "observed", "conclusion",
                                 "uncertainty"],
                    "properties": {
                        "check": {"type": "string", "pattern": _CHECK_RE},
                        "status": {"type": "string", "enum": _STATUS},
                        "observation": {"type": "string", "enum": _OBSERVATIONS},
                        "observed": {"type": "string"},
                        "conclusion": {"type": "string"},
                        "uncertainty": {"type": "array", "items": {"type": "string"}},
                        "recommendation": {"type": "string"},
                    },
                }},
                # 1.7: FAIL/WARNING findings no cause rule explained; they still
                # count toward `overall`
                "unexplained": {"type": "array", "items": {
                    "type": "object",
                    "required": ["check", "status", "title"],
                    "properties": {
                        "check": {"type": "string", "pattern": _CHECK_RE},
                        "status": {"type": "string", "enum": _STATUS},
                        "title": {"type": "string"},
                        "failure_kind": {"type": "string", "enum": _FAILURE_KINDS},
                        "evidence": {"type": "array", "items": {"type": "string"}},
                    },
                }},
            },
        },
        "findings": {"type": "array", "items": {
            "type": "object",
            "required": ["check", "title", "status", "scope", "evidence"],
            "properties": {
                "check": {"type": "string", "pattern": _CHECK_RE},
                "title": {"type": "string"},
                "status": {"type": "string", "enum": _STATUS},
                "scope": {"type": "string", "enum": _SCOPE},
                "evidence": {"type": "array", "items": {"type": "string"}},
                "detail": {"type": "string"},
                "recommendation": {"type": "string"},
                "target": {"type": "string"},
                "ts": {"type": "number"},
                "ts_iso": {"type": "string"},
                # 1.2: classification of the failure, empty when none
                "failure_kind": {"type": "string", "enum": _FAILURE_KINDS},
                # 1.3: what was observed, when the check reports an observation
                "observation": {"type": "string", "enum": _OBSERVATIONS},
                # 1.5: why the evidence cannot settle the check's question
                "uncertainty": {"type": "array", "items": {"type": "string"}},
            },
        }},
        "disclaimer": {"type": "string"},
        # 1.1: structured facts for machine consumers (monitoring/drift)
        "facts": {
            "type": "object",
            "properties": {
                "leaf": {"type": ["object", "null"], "properties": {
                    "sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "subject": {"type": "string"},
                    "not_after": {"type": ["string", "null"]},
                }},
                "chain_status": {"type": "string",
                                 "enum": ["complete", "incomplete", "broken", "unread"]},
                # 1.2: address every probe connected to, and how the handshake failed
                "handshake_ip": {"type": ["string", "null"]},
                "handshake_failure": {"type": "string", "enum": _FAILURE_KINDS},
                # 1.3: per-endpoint outcome states and the comparison result
                "endpoints": {"type": "array", "items": {
                    "type": "object",
                    "required": ["ip", "state"],
                    "properties": {
                        "ip": {"type": "string"},
                        "state": {"type": "string", "enum": ENDPOINT_STATES + [""]},
                        "detail": {"type": "string"},
                        "sha256": {"type": "string"},
                        "sni": {"type": ["string", "null"]},
                    },
                }},
                "endpoint_comparison": {"type": ["object", "null"], "properties": {
                    "probed": {"type": "integer"},
                    "comparable": {"type": "integer"},
                    # 1.5: addresses DNS returned; comparable < addresses = partial
                    "addresses": {"type": "integer"},
                    "difference": {"type": "boolean"},
                    "attribute": {"type": "string"},
                }},
                "probe_policy": {"type": ["object", "null"], "properties": {
                    "negotiated": {"type": "string"},
                    "relaxed_versions": {"type": "array", "items": {"type": "string"}},
                    # 1.4: which policy actually proved each version
                    "support": {"type": "object", "properties": {
                        "TLS 1.0": {"type": "string", "enum": _PROBE_SUPPORT},
                        "TLS 1.1": {"type": "string", "enum": _PROBE_SUPPORT},
                        "TLS 1.2": {"type": "string", "enum": _PROBE_SUPPORT},
                        "TLS 1.3": {"type": "string", "enum": _PROBE_SUPPORT},
                    }},
                    "confirmed_legacy": {"type": "array", "items": {"type": "string"}},
                    "unverified_legacy": {"type": "array", "items": {"type": "string"}},
                    # 1.5: default-policy probe outcome per re-probed version
                    "default_probe": {"type": "object", "properties": {
                        v: {"type": "string", "enum": _PROBE_STATES}
                        for v in ("TLS 1.0", "TLS 1.1", "TLS 1.2")}},
                }},
                # 1.7: every judged chain, keyed "presented", "configured:<path>"
                # or "supplied:<path>"
                "certificates": {"type": "object", "additionalProperties": _CHAIN},
            },
        },
    },
}


class ContractError(ValueError):
    """A document does not satisfy the findings contract."""


# ------------------------------------------------------------------ validation

_TYPES = {"object": dict, "array": list, "string": str, "number": (int, float),
          "integer": int, "boolean": bool, "null": type(None)}


def _check_type(value: Any, expected) -> bool:
    for t in ([expected] if isinstance(expected, str) else expected):
        py = _TYPES[t]
        if isinstance(value, py) and not (t in ("number", "integer")
                                          and isinstance(value, bool)):
            return True
    return False


def validate(doc: Any, schema: Dict[str, Any] = SCHEMA, path: str = "$") -> List[str]:
    """Validate `doc` against the subset of JSON Schema SCHEMA uses.

    Returns a list of error strings (empty = valid).
    """
    errs: List[str] = []
    if "type" in schema and not _check_type(doc, schema["type"]):
        return [f"{path}: expected {schema['type']}, got {type(doc).__name__}"]
    if "enum" in schema and doc not in schema["enum"]:
        errs.append(f"{path}: {doc!r} not one of {schema['enum']}")
    if "pattern" in schema and isinstance(doc, str) and not re.search(schema["pattern"], doc):
        errs.append(f"{path}: {doc!r} does not match {schema['pattern']}")
    if isinstance(doc, dict):
        for key in schema.get("required", []):
            if key not in doc:
                errs.append(f"{path}: missing required '{key}'")
        props = schema.get("properties", {})
        for key, sub in props.items():
            if key in doc:
                errs.extend(validate(doc[key], sub, f"{path}.{key}"))
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict):
            for key in doc:
                if key not in props:
                    errs.extend(validate(doc[key], extra, f"{path}.{key}"))
    if isinstance(doc, list) and "items" in schema:
        for i, item in enumerate(doc):
            errs.extend(validate(item, schema["items"], f"{path}[{i}]"))
    return errs


def unregistered_checks(doc: Dict[str, Any]) -> List[str]:
    """Check ids in `doc` that the registry does not know.

    Kept out of `validate` on purpose: a later 1.x minor version may add ids,
    and a consumer must still accept its documents.
    """
    used = [f.get("check", "") for f in doc.get("findings") or []]
    diag = doc.get("diagnosis") or {}
    used += [e.get("check", "") for key in ("unresolved", "unexplained")
             for e in diag.get(key) or []]
    return sorted({c for c in used if c and c not in CHECK_IDS})


def load_document(data) -> Dict[str, Any]:
    """Parse (if needed) and accept a findings document, or raise ContractError."""
    doc = json.loads(data) if isinstance(data, (str, bytes, bytearray)) else data
    if not isinstance(doc, dict):
        raise ContractError("document must be a JSON object")
    version = doc.get("schema_version")
    if not isinstance(version, str) or not re.match(r"^\d+\.\d+$", version):
        raise ContractError(f"missing or malformed schema_version {version!r}; "
                            f"supported: {SUPPORTED_MAJOR}.x")
    if int(version.split(".")[0]) != SUPPORTED_MAJOR:
        raise ContractError(f"unsupported schema_version {version} "
                            f"(received major {version.split('.')[0]}); "
                            f"supported: {SUPPORTED_MAJOR}.x")
    errs = validate(doc)
    if errs:
        raise ContractError("invalid findings document: " + "; ".join(errs[:10]))
    return doc


# ------------------------------------------------------------------ redaction

REDACTED = "[REDACTED]"
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL)


def _variants(secret: str) -> List[str]:
    raw = secret.encode()
    return sorted({secret, urllib.parse.quote(secret, safe=""),
                   base64.b64encode(raw).decode(), raw.hex()}, key=len, reverse=True)


def redact(payload: Dict[str, Any], secrets: Iterable[str] = ()) -> Dict[str, Any]:
    """Return a copy of `payload` with secrets and private keys scrubbed.

    Works on the serialized form so no field can be missed.
    """
    text = json.dumps(payload, default=str)
    for secret in secrets:
        if secret and len(secret) >= 4:          # tiny strings would mangle output
            for v in _variants(secret):
                text = text.replace(json.dumps(v)[1:-1], REDACTED)
    text = _PRIVATE_KEY_RE.sub(REDACTED, text)
    return json.loads(text)
