"""Re-check DKIM signatures ourselves instead of only trusting the receiving server.

A DKIM signature proves the signing domain sent the email and that the signed
headers and body were not changed afterwards. Re-checking needs the domain's
public key from DNS, so:
  - an old email may have a key that was since removed or rotated. That is
    "unverifiable", not "forged".
  - the DNS lookup goes to the signing domain's DNS servers. For a phishing
    domain that means the attacker can see that someone looked the key up
    (through your DNS resolver). Set DKIM_RECHECK=off to skip it.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass

import dkim

_TAG = re.compile(r"\b([a-z]+)\s*=\s*([^;]*)")


@dataclass
class DkimCheck:
    domain: str  # signing domain (d=)
    selector: str  # key selector (s=)
    status: str  # pass, fail, unverifiable, error
    reason: str  # why, in plain words


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.ERROR)
        self.messages: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(record.getMessage())


def _classify(error_text: str) -> tuple[str, str]:
    text = error_text.lower()
    if "body hash mismatch" in text:
        return "fail", "the body was changed after signing"
    if "missing public key" in text:
        return "unverifiable", "the signing key is no longer published in DNS"
    if "dnstimeout" in text or "timeout" in text:
        return "unverifiable", "DNS lookup for the key timed out"
    if "x= value is past" in text or "expired" in text:
        return "unverifiable", "the signature has expired"
    if "keyformaterror" in text or "public key" in text:
        return "unverifiable", f"the published key is unusable ({error_text})"
    return "error", error_text


def check_dkim(raw: bytes, dnsfunc=None, timeout: int = 5) -> list[DkimCheck]:
    """One result per DKIM-Signature header, top of the email first."""
    # A private, unregistered logger per call: dkimpy reports key and DNS
    # problems only through logger.error, and concurrent web requests must not
    # read each other's messages.
    handler = _ListHandler()
    logger = logging.Logger("phishtriage.dkim")
    logger.addHandler(handler)
    try:
        signer = dkim.DKIM(raw, logger=logger, timeout=timeout)
        signatures = [value for name, value in signer.headers if name.lower() == b"dkim-signature"]
        checks = []
        for index, signature in enumerate(signatures):
            tags = dict(_TAG.findall(signature.decode("ascii", errors="replace").replace("\r\n", "")))
            domain = re.sub(r"\s+", "", tags.get("d", "")).lower()
            selector = re.sub(r"\s+", "", tags.get("s", ""))
            handler.messages.clear()
            try:
                kwargs = {"dnsfunc": dnsfunc} if dnsfunc else {}
                if signer.verify(idx=index, **kwargs):
                    checks.append(DkimCheck(domain, selector, "pass", "signature verified"))
                    continue
                error_text = " ".join(handler.messages)
                status, reason = (
                    _classify(error_text) if error_text
                    else ("fail", "the signature does not match: signed headers were changed or forged")
                )
            except dkim.DKIMException as error:
                status, reason = _classify(f"{type(error).__name__}: {error}")
            except Exception as error:  # noqa: BLE001 - hostile input must never crash the analysis
                status, reason = "error", f"{type(error).__name__}: {error}"
            checks.append(DkimCheck(domain, selector, status, reason))
        return checks
    except Exception as error:  # noqa: BLE001
        return [DkimCheck("", "", "error", f"could not read the signatures: {type(error).__name__}: {error}")]
