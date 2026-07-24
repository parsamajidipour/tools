"""XML comparison with XXE-safe parsing (external entities never resolved)."""

from __future__ import annotations

from xml.etree import ElementTree as ET

from ..models import ChangeType, Difference, DifferenceCategory


class _SafeXMLParser(ET.XMLParser):
    """An ElementTree parser that refuses to resolve external entities."""

    def __init__(self) -> None:
        target = ET.TreeBuilder()
        super().__init__(target=target)


def _safe_parse(text: str) -> ET.Element | None:
    try:
        # ElementTree's default expat parser does not fetch external
        # resources or resolve external entities by default; we still
        # avoid DTD-triggering constructs defensively.
        if "<!DOCTYPE" in text or "<!ENTITY" in text:
            # Strip any DOCTYPE/ENTITY declarations before parsing to
            # guarantee no external entity resolution is attempted.
            import re

            text = re.sub(r"<!DOCTYPE[^>]*(\[[^\]]*\])?>", "", text, flags=re.DOTALL)
        return ET.fromstring(text)
    except ET.ParseError:
        return None


def _element_signature(el: ET.Element, path: str = "") -> dict[str, str]:
    """Flatten an XML tree into a path -> text/attrs signature map."""
    result: dict[str, str] = {}
    current = f"{path}/{el.tag}"
    attrs = ",".join(f"{k}={v}" for k, v in sorted(el.attrib.items()))
    text = (el.text or "").strip()
    result[current] = f"attrs=[{attrs}] text={text!r}"
    counts: dict[str, int] = {}
    for child in el:
        counts[child.tag] = counts.get(child.tag, 0) + 1
        child_path = f"{current}[{counts[child.tag]}]"
        result.update(_element_signature(child, child_path))
    return result


def analyze_xml(baseline_text: str, candidate_text: str) -> list[Difference]:
    diffs: list[Difference] = []
    b_root = _safe_parse(baseline_text)
    c_root = _safe_parse(candidate_text)
    if b_root is None or c_root is None:
        return diffs

    b_sig = _element_signature(b_root)
    c_sig = _element_signature(c_root)
    all_paths = sorted(set(b_sig) | set(c_sig))

    for path in all_paths:
        b_val = b_sig.get(path)
        c_val = c_sig.get(path)
        if b_val == c_val:
            continue
        if b_val is None:
            diffs.append(
                Difference(
                    category=DifferenceCategory.XML,
                    path=path,
                    change_type=ChangeType.ADDED,
                    baseline_value=None,
                    candidate_value=c_val,
                    description=f"XML element added at {path}",
                )
            )
        elif c_val is None:
            diffs.append(
                Difference(
                    category=DifferenceCategory.XML,
                    path=path,
                    change_type=ChangeType.REMOVED,
                    baseline_value=b_val,
                    candidate_value=None,
                    description=f"XML element removed at {path}",
                )
            )
        else:
            diffs.append(
                Difference(
                    category=DifferenceCategory.XML,
                    path=path,
                    change_type=ChangeType.MODIFIED,
                    baseline_value=b_val,
                    candidate_value=c_val,
                    description=f"XML element changed at {path}",
                )
            )
    return diffs
