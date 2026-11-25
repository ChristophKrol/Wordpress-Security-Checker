"""Data model shared by fingerprinting, matching and reporting."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Ordered from weakest to strongest.
CONFIDENCE = ("low", "medium", "high")


@dataclass
class Evidence:
    source: str                    # e.g. "meta-generator", "readme.txt", "asset-ver", "header:Server"
    detail: str                    # URL or snippet the evidence came from
    version: Optional[str] = None  # version this evidence points to, if any
    confidence: str = "medium"


@dataclass
class Component:
    type: str                      # "core" | "plugin" | "theme" | "server"
    slug: str                      # plugin/theme slug, "wordpress", or server product (e.g. "apache")
    name: Optional[str] = None
    evidence: List[Evidence] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)  # filled by matching
    notes: List[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.slug}"

    @property
    def version(self) -> Optional[str]:
        """Version backed by the strongest evidence (ties: most frequently seen)."""
        best = self.version_evidence
        return best.version if best else None

    @property
    def version_evidence(self) -> Optional[Evidence]:
        with_version = [e for e in self.evidence if e.version]
        if not with_version:
            return None
        counts: Dict[str, int] = {}
        for e in with_version:
            counts[e.version] = counts.get(e.version, 0) + 1
        return max(with_version, key=lambda e: (CONFIDENCE.index(e.confidence), counts[e.version]))

    @property
    def version_conflicts(self) -> List[str]:
        return sorted({e.version for e in self.evidence if e.version} - {self.version})

    def add(self, evidence: Evidence) -> None:
        if not any(e.source == evidence.source and e.detail == evidence.detail and e.version == evidence.version
                   for e in self.evidence):
            self.evidence.append(evidence)

    def to_dict(self) -> Dict[str, Any]:
        best = self.version_evidence
        return {
            "type": self.type,
            "slug": self.slug,
            "name": self.name,
            "version": self.version,
            "versionConfidence": best.confidence if best else None,
            "versionConflicts": self.version_conflicts,
            "evidence": [asdict(e) for e in self.evidence],
            "notes": self.notes,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass
class Finding:
    """A configuration issue that is not tied to a vulnerable software version."""
    id: str
    title: str
    severity: str                  # "info" | "low" | "medium" | "high"
    url: str
    detail: str = ""


@dataclass
class ScanResult:
    target: str
    final_url: str = ""
    scanned_at: str = ""
    mode: str = "passive"
    is_wordpress: bool = False
    components: Dict[str, Component] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    rest_namespaces: List[str] = field(default_factory=list)
    requests_made: int = 0
    errors: List[str] = field(default_factory=list)

    def component(self, type_: str, slug: str, name: Optional[str] = None) -> Component:
        key = f"{type_}:{slug}"
        if key not in self.components:
            self.components[key] = Component(type=type_, slug=slug, name=name)
        elif name and not self.components[key].name:
            self.components[key].name = name
        return self.components[key]

    def to_dict(self) -> Dict[str, Any]:
        order = {"core": 0, "server": 1, "theme": 2, "plugin": 3}
        comps = sorted(self.components.values(), key=lambda c: (order.get(c.type, 9), c.slug))
        return {
            "target": self.target,
            "finalUrl": self.final_url,
            "scannedAt": self.scanned_at,
            "mode": self.mode,
            "isWordPress": self.is_wordpress,
            "components": [c.to_dict() for c in comps],
            "findings": [asdict(f) for f in self.findings],
            "restNamespaces": self.rest_namespaces,
            "requestsMade": self.requests_made,
            "errors": self.errors,
        }
