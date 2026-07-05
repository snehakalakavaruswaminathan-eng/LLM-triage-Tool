"""Duplicate clustering for normalized findings."""

from __future__ import annotations

import hashlib
import re
from difflib import SequenceMatcher

from config import get_settings
from models import ClusterSummary, NormalizedFinding


def cluster_findings(findings: list[NormalizedFinding]) -> list[NormalizedFinding]:
    """Group duplicate findings and attach cluster metadata."""
    if not findings:
        return []

    settings = get_settings()
    threshold = settings.cluster_similarity_threshold

    clusters: list[list[NormalizedFinding]] = []

    for finding in findings:
        placed = False
        for cluster in clusters:
            representative = cluster[0]
            if _are_duplicates(representative, finding, threshold):
                cluster.append(finding)
                placed = True
                break
        if not placed:
            clusters.append([finding])

    deduped: list[NormalizedFinding] = []
    for index, cluster in enumerate(clusters, start=1):
        cluster_id = f"cluster-{index:03d}"
        representative = _pick_representative(cluster)
        tools = sorted({item.tool for item in cluster})
        representative.cluster_id = cluster_id
        representative.duplicate_count = len(cluster)
        representative.source_tools = tools
        deduped.append(representative)

    return deduped


def build_cluster_summaries(findings: list[NormalizedFinding]) -> list[ClusterSummary]:
    summaries: list[ClusterSummary] = []
    for finding in findings:
        summaries.append(
            ClusterSummary(
                cluster_id=finding.cluster_id or finding.id,
                representative_title=finding.title,
                finding_count=finding.duplicate_count,
                tools=finding.source_tools or [finding.tool],
                max_severity_score=finding.severity_score,
            )
        )
    return summaries


def _pick_representative(cluster: list[NormalizedFinding]) -> NormalizedFinding:
    return max(cluster, key=lambda item: (item.severity_score, item.duplicate_count))


def _are_duplicates(
    left: NormalizedFinding,
    right: NormalizedFinding,
    threshold: float,
) -> bool:
    if left.rule_id and right.rule_id and left.rule_id == right.rule_id:
        if left.file == right.file:
            return True

    if left.file and right.file and left.file == right.file:
        if left.line and right.line and abs(left.line - right.line) <= 5:
            if _title_similarity(left.title, right.title) >= 0.65:
                return True
        if left.cwe and right.cwe and left.cwe == right.cwe:
            if left.line and right.line and abs(left.line - right.line) <= 10:
                return True

    signature_left = _signature(left)
    signature_right = _signature(right)
    if signature_left == signature_right:
        return True

    return _title_similarity(left.title, right.title) >= 0.95 and left.file == right.file


def _signature(finding: NormalizedFinding) -> str:
    basis = "|".join(
        [
            _normalize_for_match(finding.title),
            finding.file or "",
            str(finding.line or ""),
            finding.cwe or "",
        ]
    )
    return hashlib.md5(basis.encode("utf-8")).hexdigest()


def _title_similarity(left: str, right: str) -> float:
    return SequenceMatcher(None, _normalize_for_match(left), _normalize_for_match(right)).ratio()


def _normalize_for_match(value: str) -> str:
    cleaned = re.sub(r"[^a-z0-9]+", " ", value.lower())
    return re.sub(r"\s+", " ", cleaned).strip()
