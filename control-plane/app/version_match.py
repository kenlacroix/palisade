"""Version-range matching for scan target selection.

Primary path uses PEP 440 via `packaging` (correct pre-release, epoch, and
trailing-zero ordering, plus range specifier sets). Detection specs use comma-
and/or whitespace-separated constraints (e.g. "<1.40.2", ">=11.1.4 <15.2.3"),
normalized to a comma-separated SpecifierSet. Non-PEP440 vendor versions (e.g.
"2.7.11p2") that packaging cannot parse fall back to the hand-rolled dotted
comparator below.

Fail-open rationale: a security scanner must not silently skip a vulnerable
asset because its version was unknown or unparseable. When the asset version is
missing, or neither path can parse it, we prefer to scan (return True) rather
than risk missing a real vuln.
"""

from __future__ import annotations

try:
    from packaging.specifiers import SpecifierSet
    from packaging.version import Version
except Exception:  # pragma: no cover - packaging is a declared dependency
    SpecifierSet = None  # type: ignore[assignment]
    Version = None  # type: ignore[assignment]

_OPERATORS = ("<=", ">=", "==", "!=", "<", ">")


def _parse_component(component: str) -> tuple[int, str]:
    """Split a version component into (leading int, remaining suffix).

    "7" -> (7, ""), "2rc1" -> (2, "rc1"), "rc1" -> (0, "rc1").
    """
    i = 0
    while i < len(component) and component[i].isdigit():
        i += 1
    num = int(component[:i]) if i > 0 else 0
    return num, component[i:]


def _compare(a: str, b: str) -> int:
    """Compare two dotted version strings. Returns -1, 0, or 1."""
    a_parts = a.split(".")
    b_parts = b.split(".")
    length = max(len(a_parts), len(b_parts))
    for idx in range(length):
        a_comp = a_parts[idx] if idx < len(a_parts) else "0"
        b_comp = b_parts[idx] if idx < len(b_parts) else "0"
        a_num, a_rest = _parse_component(a_comp)
        b_num, b_rest = _parse_component(b_comp)
        if a_num != b_num:
            return -1 if a_num < b_num else 1
        if a_rest != b_rest:
            return -1 if a_rest < b_rest else 1
    return 0


def _is_version(value: str) -> bool:
    """True if `value` looks like a parseable dotted version."""
    if not value:
        return False
    for component in value.split("."):
        num_part = ""
        for ch in component:
            if ch.isdigit():
                num_part += ch
            else:
                break
        if not num_part:
            return False
    return True


def _split_constraints(spec: str) -> list[str]:
    """Split a spec into constraint tokens on commas and/or whitespace."""
    tokens: list[str] = []
    for chunk in spec.replace(",", " ").split():
        if chunk:
            tokens.append(chunk)
    return tokens


def _satisfies(asset_version: str, constraint: str) -> bool:
    op = "=="
    operand = constraint
    for candidate in _OPERATORS:
        if constraint.startswith(candidate):
            op = candidate
            operand = constraint[len(candidate):].strip()
            break

    if not _is_version(operand):
        # Unparseable operand -> ignore this single constraint (fail-open).
        return True

    cmp = _compare(asset_version, operand)
    if op == "<":
        return cmp < 0
    if op == "<=":
        return cmp <= 0
    if op == ">":
        return cmp > 0
    if op == ">=":
        return cmp >= 0
    if op == "!=":
        return cmp != 0
    return cmp == 0


def _packaging_match(asset_version: str, constraints: list[str]) -> bool | None:
    """PEP 440 evaluation via packaging. Returns the match result, or None when
    the library is unavailable or either side is not valid PEP 440 (caller then
    falls back to the hand-rolled comparator)."""
    if SpecifierSet is None or not constraints:
        return None
    # A bare version with no operator is not a specifier; let the fallback's
    # default-equality handle it.
    if not any(c.startswith(_OPERATORS) for c in constraints):
        return None
    try:
        spec_set = SpecifierSet(",".join(constraints))
        version = Version(asset_version)
    except Exception:
        return None
    # prereleases=True so a pre-release asset version is still considered in
    # range (fail toward scanning).
    return spec_set.contains(version, prereleases=True)


def service_matches(asset_version: str | None, spec: str) -> bool:
    """Return True if `asset_version` satisfies version constraint `spec`.

    See module docstring for fail-open semantics. Never raises.
    """
    stripped = spec.strip() if spec else ""
    if not stripped or stripped == "*":
        return True

    if asset_version is None:
        return True
    av = asset_version.strip()
    if not av:
        return True

    constraints = _split_constraints(stripped)
    result = _packaging_match(av, constraints)
    if result is not None:
        return result

    # Fallback: hand-rolled dotted comparison for non-PEP440 vendor versions.
    if not _is_version(av):
        return True
    for constraint in constraints:
        if not _satisfies(av, constraint):
            return False
    return True
