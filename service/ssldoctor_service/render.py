"""HTML rendering of stored findings documents (shared with the CLI report)."""

from ssl_doctor import contract
from ssl_doctor.report import html_from_payload


def document_html(doc: dict) -> str:
    # documents were redacted at the producer; scrub key material again anyway
    return html_from_payload(contract.redact(doc))
