"""STIX 2.1 bundle validation: per-object schema checks (stix2.parse) + referential integrity."""

from __future__ import annotations

from typing import Any

import stix2
from stix2.exceptions import STIXError

REF_KEYS = ("created_by_ref", "source_ref", "target_ref", "sighting_of_ref", "sample_ref")
REF_LIST_KEYS = (
    "object_refs",
    "object_marking_refs",
    "where_sighted_refs",
    "observed_data_refs",
    "resolves_to_refs",
    "belongs_to_refs",
)
# Well-known definitions that may be referenced without being embedded.
BUILTIN_REFS = {stix2.TLP_WHITE.id, stix2.TLP_GREEN.id, stix2.TLP_AMBER.id, stix2.TLP_RED.id}


def validate_bundle(bundle: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if bundle.get("type") != "bundle":
        return ["not a bundle"]
    objects = bundle.get("objects", [])
    ids: set[str] = set()
    for obj in objects:
        oid = obj.get("id", "<missing id>")
        if oid in ids:
            errors.append(f"duplicate id {oid}")
        ids.add(oid)
        if obj.get("type") not in ("bundle",) and obj.get("spec_version", "2.1") != "2.1":
            errors.append(f"{oid}: spec_version must be 2.1")
        try:
            stix2.parse(obj, allow_custom=True)
        except (STIXError, ValueError, TypeError) as exc:
            errors.append(f"{oid}: {exc}")
    known = ids | BUILTIN_REFS
    for obj in objects:
        oid = obj.get("id")
        for key in REF_KEYS:
            ref = obj.get(key)
            if ref and ref not in known:
                errors.append(f"{oid}: dangling {key} -> {ref}")
        for key in REF_LIST_KEYS:
            for ref in obj.get(key, []) or []:
                if ref not in known:
                    errors.append(f"{oid}: dangling {key} -> {ref}")
    return errors
