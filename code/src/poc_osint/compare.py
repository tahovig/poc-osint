from dataclasses import dataclass


@dataclass
class ComparisonResult:
    added: list[dict]
    removed: list[dict]
    changed: list[tuple[dict, dict]]


def _key(entry: dict) -> tuple[str, int]:
    return (entry["host"], entry["port"])


def compare_reports(old: list[dict], new: list[dict]) -> ComparisonResult:
    """Diff two saved `lookup --json`/`--save` result sets, keyed by host:port.

    Operates on plain dicts (as loaded from JSON), not SubdomainReport --
    dict equality is all "did anything change?" needs, no reason to
    reconstruct the nested dataclasses just to diff them.
    """
    old_by_key = {_key(entry): entry for entry in old}
    new_by_key = {_key(entry): entry for entry in new}

    added_keys = new_by_key.keys() - old_by_key.keys()
    removed_keys = old_by_key.keys() - new_by_key.keys()
    common_keys = old_by_key.keys() & new_by_key.keys()

    changed = [
        (old_by_key[key], new_by_key[key])
        for key in common_keys
        if old_by_key[key] != new_by_key[key]
    ]

    return ComparisonResult(
        added=sorted((new_by_key[key] for key in added_keys), key=_key),
        removed=sorted((old_by_key[key] for key in removed_keys), key=_key),
        changed=sorted(changed, key=lambda pair: _key(pair[0])),
    )
