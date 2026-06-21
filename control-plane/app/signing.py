from __future__ import annotations

import base64
import hashlib

from . import _ed25519
from .config import SIGNING_KEY

# Demo keypair (base64-std, raw 32-byte seed / 32-byte public). The agent pins
# DEMO_PUB_B64; signing with DEMO_SEED_B64 produces bundles it accepts.
DEMO_SEED_B64 = "70kJtI1NajTd1yQXFHVRuBVQfc6P2CAtRroaLCmYYbY="
DEMO_PUB_B64 = "DRLpngzapOzExqzZsykc6h8LTpuGjw3ahrGJvnMwFhY="

# Field/record/group/space separators. Must match the Go agent verifier byte
# for byte — do not "clean up" the canonical encoding.
US = "\x1f"
RS = "\x1e"
GS = "\x1d"
SP = " "


def _matcher_values(matcher: dict) -> str:
    t = matcher.get("type")
    if t == "dsl":
        return ",".join(matcher.get("dsl") or [])
    if t == "word":
        return ",".join(matcher.get("words") or [])
    if t == "status":
        return ",".join(str(c) for c in (matcher.get("status") or []))
    if t == "regex":
        return ",".join(matcher.get("regex") or [])
    if t == "binary":
        return ",".join(matcher.get("binary") or [])
    return ""


def _matcher_key(matcher: dict) -> str:
    # "type:values" plus "|part=" for a non-default part and "|neg" for a
    # negative matcher. Must match the Go verifier's matchersString byte for byte.
    key = matcher.get("type", "") + ":" + _matcher_values(matcher)
    part = matcher.get("part") or ""
    if part and part != "body":
        key += "|part=" + part
    if matcher.get("negative"):
        key += "|neg"
    return key


def _http_field(det: dict) -> str:
    if det.get("engine") != "nuclei" or not det.get("http"):
        return ""
    steps: list[str] = []
    for step in det["http"]:
        method = step.get("method", "")
        path = step.get("path", "")
        body = step.get("body") or ""
        matchers = GS.join(_matcher_key(m) for m in (step.get("matchers") or []))
        step_str = method + SP + path + SP + body + SP + matchers
        cond = step.get("matchers-condition") or ""
        if cond and cond != "and":
            step_str += SP + "cond=" + cond
        steps.append(step_str)
    return RS.join(steps)


def _flow_field(det: dict) -> str:
    # Canonical segment for a declarative module flow. Every byte must match the
    # Go verifier's flowString:
    #   "flow" US <requests joined by RS> US <confirm exprs joined by GS>
    # where each request is: id SP method SP path SP body SP <headers>, headers
    # being "k=v" pairs sorted lexicographically and joined by ",".
    flow = det.get("flow") or {}
    reqs: list[str] = []
    for r in flow.get("requests") or []:
        headers = r.get("headers") or {}
        hdrs = ",".join(sorted(f"{k}={v}" for k, v in headers.items()))
        reqs.append(
            SP.join([r.get("id", ""), r.get("method", ""), r.get("path", ""), r.get("body") or "", hdrs])
        )
    return "flow" + US + RS.join(reqs) + US + GS.join(flow.get("confirm") or [])


def _engine_body(det: dict) -> str:
    # Last canonical field: nuclei http steps, or a module's declarative flow.
    # A spec_ref-only module has no body, so it hashes exactly as before.
    if det.get("engine") == "module" and det.get("flow"):
        return _flow_field(det)
    return _http_field(det)


def _canonical(det: dict) -> str:
    cve = det.get("cve") or ""
    spec_ref = det.get("spec_ref") or ""
    match = det.get("match") or {}
    return US.join(
        [
            det["id"],
            cve,
            det["severity"],
            det["category"],
            det["engine"],
            match.get("service", ""),
            match.get("versions", ""),
            spec_ref,
            det["remediation"],
            _engine_body(det),
        ]
    )


def _hash(det: dict) -> str:
    return hashlib.sha256(_canonical(det).encode("utf-8")).hexdigest()


def build_manifest(version: int, detections: list[dict]) -> bytes:
    hashes = [_hash(d) for d in sorted(detections, key=lambda x: x["id"])]
    return ("palisade-catalog-v1\n" + str(version) + "\n" + "\n".join(hashes)).encode("utf-8")


def sign_bundle(version: int, detections: list[dict]) -> str:
    if not SIGNING_KEY:
        return "stub"
    seed = base64.b64decode(SIGNING_KEY)
    sig = _ed25519.sign(build_manifest(version, detections), seed)
    return base64.b64encode(sig).decode()


def verify_bundle(version: int, detections: list[dict], signature_b64: str, pub_b64: str) -> bool:
    if signature_b64 in ("", "stub"):
        return False
    try:
        sig = base64.b64decode(signature_b64)
        pub = base64.b64decode(pub_b64)
        return _ed25519.verify(build_manifest(version, detections), sig, pub)
    except Exception:
        return False
