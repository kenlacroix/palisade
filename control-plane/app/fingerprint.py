from __future__ import annotations

import hashlib


def finding_fingerprint(asset_id: str, detection_id: str, short_evidence_key: str) -> str:
    """sha256_hex("<asset_id>|<detection_id>|<short_evidence_key>")."""
    raw = f"{asset_id}|{detection_id}|{short_evidence_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()
