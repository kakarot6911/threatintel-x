"""Knowledge graph (NetworkX) built from the repository, plus pivot queries and SVG rendering.

NetworkX keeps the graph in-process and dependency-light (see ADR-002); the node/edge
model maps 1:1 onto a Neo4j property graph if scale ever demands it.
"""

from __future__ import annotations

import math
from collections import deque
from html import escape
from typing import Any

import networkx as nx

from threatintel.attack.knowledge_base import AttackKnowledgeBase
from threatintel.storage.repository import Repository

EDGE_LABELS = {
    "indicates": "INDICATES",
    "uses": "USES",
    "exploits": "EXPLOITS",
    "related-to": "RELATED_TO",
    "resolves-to": "RESOLVES_TO",
    "belongs-to": "HOSTED_ON",
    "uses-nameserver": "USES_NAMESERVER",
    "reported-attribution": "ATTRIBUTED_TO (reported)",
    "attributed-to": "ATTRIBUTED_TO (assessed)",
    "exhibits-technique": "USES_TECHNIQUE",
}
KIND_COLORS = {
    "threat-actor": "actor",
    "campaign": "campaign",
    "malware": "malware",
    "tool": "malware",
    "vulnerability": "vuln",
    "attack-pattern": "ttp",
    "observable": "ioc",
    "report": "report",
}


def build_graph(
    repo: Repository, kb: AttackKnowledgeBase, *, include_reports: bool = False
) -> nx.MultiDiGraph:
    g: nx.MultiDiGraph = nx.MultiDiGraph()
    for ent in repo.list_entities():
        g.add_node(ent.id, kind=ent.entity_type, label=ent.name, synthetic=ent.synthetic)
    for obs in repo.list_observables(limit=100_000):
        g.add_node(
            obs.id, kind="observable", label=obs.value, obs_type=obs.type.value, synthetic=obs.synthetic
        )
    stix_to_tech = {t.stix_id: t for t in kb.techniques.values()}
    for r in repo.list_relationships():
        if r.relationship_type == "exhibits-technique" and not include_reports:
            continue
        for ref in (r.source_ref, r.target_ref):
            if ref not in g and ref in stix_to_tech:
                t = stix_to_tech[ref]
                g.add_node(ref, kind="attack-pattern", label=f"{t.technique_id} {t.name}", synthetic=False)
            elif ref not in g and ref.startswith("collected-item--"):
                item = repo.get_collected_item(ref)
                g.add_node(
                    ref,
                    kind="report",
                    label=item.title if item else ref,
                    synthetic=bool(item and item.synthetic),
                )
        if r.source_ref in g and r.target_ref in g:
            g.add_edge(
                r.source_ref,
                r.target_ref,
                key=r.relationship_type,
                rel=r.relationship_type,
                label=EDGE_LABELS.get(r.relationship_type, r.relationship_type.upper()),
                confidence=r.confidence,
            )
    return g


def pivot(g: nx.MultiDiGraph, start: str, max_depth: int = 4, limit: int = 50) -> list[list[dict[str, Any]]]:
    """Shortest IOC -> infrastructure -> campaign -> actor / TTP paths.

    Breadth-first, O(V+E). Actors and ATT&CK techniques are *endpoints only*: walking through a technique
    (used by hundreds of groups) or an actor would connect an IOC to unrelated activity.
    """
    if start not in g:
        return []
    ug = g.to_undirected(as_view=True)
    parent: dict[str, str | None] = {start: None}
    depth = {start: 0}
    queue: deque[str] = deque([start])
    while queue:
        node = queue.popleft()
        if depth[node] >= max_depth or (node != start and g.nodes[node]["kind"] in TERMINAL_KINDS):
            continue
        for nxt in sorted(ug.neighbors(node)):
            if nxt not in parent:
                parent[nxt] = node
                depth[nxt] = depth[node] + 1
                queue.append(nxt)
    paths = []
    for node in parent:
        if node == start or g.nodes[node]["kind"] not in TERMINAL_KINDS:
            continue
        path: list[str] = []
        cur: str | None = node
        while cur is not None:
            path.append(cur)
            cur = parent[cur]
        paths.append(path[::-1])
    paths.sort(key=lambda p: (len(p), [g.nodes[n]["label"] for n in p]))
    return [
        [{"id": n, "kind": g.nodes[n]["kind"], "label": g.nodes[n]["label"]} for n in path]
        for path in paths[:limit]
    ]


TERMINAL_KINDS = {"threat-actor", "attack-pattern"}


def neighborhood(g: nx.MultiDiGraph, center: str, radius: int = 2, limit: int = 60) -> nx.MultiDiGraph:
    if center not in g:
        return nx.MultiDiGraph()
    nodes = nx.single_source_shortest_path_length(g.to_undirected(as_view=True), center, cutoff=radius)
    keep = sorted(nodes, key=lambda n: (nodes[n], g.nodes[n]["kind"], g.nodes[n]["label"]))[:limit]
    return g.subgraph(keep).copy()


def render_svg(g: nx.MultiDiGraph, center: str, width: int = 900, height: int = 620) -> str:
    """Deterministic radial layout: centre node, ring 1 = direct neighbours, ring 2 = the rest.

    All labels are HTML-escaped: node labels come from collected (untrusted) intelligence.
    """
    if center not in g:
        return ""
    ug = g.to_undirected(as_view=True)
    dist = nx.single_source_shortest_path_length(ug, center, cutoff=2)
    rings: dict[int, list[str]] = {0: [center], 1: [], 2: []}
    for n, d in sorted(dist.items(), key=lambda kv: (kv[1], g.nodes[kv[0]]["kind"], g.nodes[kv[0]]["label"])):
        if d in (1, 2):
            rings[d].append(n)
    cx, cy = width / 2, height / 2
    radius = {1: min(width, height) * 0.25, 2: min(width, height) * 0.44}
    pos = {center: (cx, cy)}
    for ring in (1, 2):
        members = rings[ring]
        for i, n in enumerate(members):
            angle = 2 * math.pi * i / max(len(members), 1) - math.pi / 2 + (0.3 if ring == 2 else 0)
            pos[n] = (cx + radius[ring] * math.cos(angle), cy + radius[ring] * math.sin(angle))
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {width} {height}" class="graph" role="img" '
        f'aria-label="relationship graph">'
    ]
    for u, v, data in g.edges(data=True):
        if u in pos and v in pos:
            (x1, y1), (x2, y2) = pos[u], pos[v]
            dashed = (
                ' stroke-dasharray="4 3"' if data["rel"] in ("related-to", "reported-attribution") else ""
            )
            parts.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" class="edge"{dashed}>'
                f"<title>{escape(data['label'])} ({data['confidence']})</title></line>"
            )
    for n, (x, y) in pos.items():
        d = g.nodes[n]
        cls = KIND_COLORS.get(d["kind"], "ioc")
        r = 16 if n == center else 9
        label = d["label"] if len(d["label"]) <= 28 else d["label"][:26] + ".."
        parts.append(
            f'<g class="node {cls}"><circle cx="{x:.1f}" cy="{y:.1f}" r="{r}"><title>{escape(d["kind"])}: '
            f'{escape(d["label"])}</title></circle><text x="{x:.1f}" y="{y + r + 12:.1f}" '
            f'text-anchor="middle">{escape(label)}</text></g>'
        )
    parts.append("</svg>")
    return "".join(parts)
