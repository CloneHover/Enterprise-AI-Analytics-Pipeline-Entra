"""Deterministic, one-way de-identification for PAX v1.11.15 CSV output."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import uuid
from typing import Any, Iterable

DEFAULT_SALT = b"PAX-Deidentify-Salt-v1-DO-NOT-CHANGE-7f3c1e9b2d846050a1c4e8b3"
EMAIL_DOMAIN = "deidentified.domain"


class PaxDeidentifier:
    """Produces stable analytics-safe tokens without retaining a reverse map."""

    def __init__(self, salt: bytes = DEFAULT_SALT):
        self.salt = salt
        self._cache: dict[tuple[str, str, int], str] = {}

    def _hex(self, value: str, length: int = 12) -> str:
        key = ("hex", value, length)
        if key not in self._cache:
            norm = value.strip().lower().encode("utf-8")
            self._cache[key] = hmac.new(self.salt, norm, hashlib.sha256).hexdigest()[:length]
        return self._cache[key]

    def deid_name(self, value: str) -> str:
        return self._hex(value)

    def deid_upn(self, value: str) -> str:
        return f"{self._hex(value)}@{EMAIL_DOMAIN}"

    def deid_guid(self, value: str) -> str:
        try:
            uuid.UUID(value)
        except (TypeError, ValueError, AttributeError):
            return value
        digest = self._hex(value, 32)
        return f"{digest[:8]}-{digest[8:12]}-{digest[12:16]}-{digest[16:20]}-{digest[20:]}"

    def deid_sid(self, value: str) -> str:
        if not value.startswith("S-"):
            return value
        digest = self._hex(value, 32)
        return "S-1-5-21-" + "-".join(str(int(digest[i:i + 8], 16)) for i in range(0, 32, 8))

    def deid_ip(self, value: str) -> str:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return value
        digest = bytes.fromhex(self._hex(value, 32))
        if ip.version == 4:
            return ".".join(str(byte) for byte in digest[:4])
        return ":".join(f"{int.from_bytes(digest[i:i + 2], 'big'):x}" for i in range(0, 16, 2))

    def deid_resource(self, value: str) -> str:
        return f"resource_{self._hex(value)}"

    def deid_file(self, value: str) -> str:
        suffix = value.rsplit(".", 1)[-1] if "." in value else ""
        return f"file_{self._hex(value)}" + (f".{suffix}" if suffix else "")

    def deid_json(self, value: str) -> str:
        """Recursively scrub identity and resource fields from AuditData JSON.

        A malformed value is redacted, never passed through, so enabling the
        switch cannot leak PII through an unparseable nested payload.
        """
        try:
            node = json.loads(value)
        except (TypeError, ValueError, json.JSONDecodeError):
            return "[REDACTED-DEIDENTIFY]"

        def scrub(item: Any, key: str = "") -> Any:
            if isinstance(item, dict):
                return {k: scrub(v, k) for k, v in item.items()}
            if isinstance(item, list):
                return [scrub(v, key) for v in item]
            if item in (None, ""):
                return item
            name, text = key.lower().replace("_", ""), str(item)
            if name in {"userid", "userprincipalname", "useremail", "mail", "email", "actorupn", "ownerupn", "sender"}:
                return self.deid_upn(text)
            if name in {"displayname", "username", "actorname", "ownername"}:
                return self.deid_name(text)
            if name in {"objectid", "mailboxguid", "siteid", "webid", "listid", "uniqueid"}:
                return self.deid_guid(text)
            if "sid" in name:
                return self.deid_sid(text)
            if "ip" in name or name in {"clientaddress"}:
                return self.deid_ip(text)
            if any(token in name for token in ("url", "path", "resource", "site", "file", "folder")):
                return self.deid_resource(text)
            return item

        return json.dumps(scrub(node), ensure_ascii=False, separators=(",", ":"))

    def deidentify_purview_record(self, row: dict[str, Any]) -> dict[str, Any]:
        out = dict(row)
        for key, value in tuple(out.items()):
            if value in (None, ""):
                continue
            name, text = key.lower().replace("_", ""), str(value)
            if key == "AuditData":
                out[key] = self.deid_json(text)
            elif name in {"userid", "userprincipalname", "useremail", "mail", "email", "actorupn"}:
                out[key] = self.deid_upn(text)
            elif name in {"username", "displayname", "actorname"}:
                out[key] = self.deid_name(text)
            elif name in {"mailboxguid", "objectid", "siteid", "webid", "listid", "uniqueid"}:
                out[key] = self.deid_guid(text)
            elif "sid" in name:
                out[key] = self.deid_sid(text)
            elif name in {"clientip", "clientaddress", "ipaddress"}:
                out[key] = self.deid_ip(text)
            elif any(token in name for token in ("siteurl", "filepath", "folderpath", "resourceurl", "objectpath")):
                out[key] = self.deid_resource(text)
        return out

    def deidentify_record(self, dataset: str, row: dict[str, Any]) -> dict[str, Any]:
        if dataset == "Purview":
            return self.deidentify_purview_record(row)
        out = dict(row)
        for key, value in tuple(out.items()):
            if value in (None, ""):
                continue
            name = key.lower().replace("_", "")
            if name in {"userprincipalname", "upn", "mail", "email", "manageruserprincipalname"}:
                out[key] = self.deid_upn(str(value))
            elif name in {"displayname", "managerdisplayname", "username"}:
                out[key] = self.deid_name(str(value))
            elif name in {"id", "managerid", "objectid"}:
                out[key] = self.deid_guid(str(value))
        return out

    def deidentify_rows(self, dataset: str, rows: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        return [self.deidentify_record(dataset, row) for row in rows]


default_deidentifier = PaxDeidentifier()
"""Deterministic, one-way de-identification for PAX v1.11.15 CSV output."""
