"""Entity-relationship graph for a target's OSINT data.

    person --owns----> name / username / email / phone
           --born----> birth_year / birth_month / birth_day / birthdate
           --lives in--> city / country
    each PII value --reported by--> source        (provenance view only)

The graph is built from the same Observation stream the pipeline persists
(data/observations/<target_id>.jsonl). When no observations exist yet, it falls back
to the target's ground-truth PII (using the ``planted`` map as the source tier) so the
view is still populated and clearly labelled as planted rather than collected.

Two views:
    entities    person + PII values only (clean identity view, default)
    provenance  person + PII values + sources (where each value came from)

Outputs:
    render_html(payload)          self-contained dark HTML, d3 from CDN, zero extra deps
    render_png(payload, path)     dark force-directed PNG, matplotlib + networkx
                                  (lazy-imported; needs the 'analysis' extra)

CLI:
    python -m osint_ai_pwg.visualize t01 --out out/graphs
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from osint_ai_pwg.schemas import Directness, Observation

# How a PII field relates to the person node. Unknown fields fall back to "has".
FIELD_RELATION: dict[str, str] = {
    "name": "owns", "username": "owns", "email": "owns", "phone": "owns",
    "birth_year": "born", "birth_month": "born", "birth_day": "born", "birthdate": "born",
    "city": "lives in", "country": "lives in", "location": "lives in",
}

GROUP_COLOR: dict[str, str] = {
    "Person": "#e74c3c",
    "Identity": "#3498db",
    "Temporal": "#e67e22",
    "Location": "#2ecc71",
    "Contact": "#9b59b6",
    "Source": "#8a8f94",
}

# strongest-first ordering (for picking one directness per merged value)
_DIRECTNESS_RANK: dict[Directness, int] = {
    Directness.STATED: 4,
    Directness.STRONGLY_IMPLIED: 3,
    Directness.WEAKLY_IMPLIED: 2,
    Directness.INFERRED: 1,
}

# --------------------------------------------------------------------------- loaders


def load_observations(obs_dir: Path, target_id: str) -> list[Observation]:
    """Read data/observations/<target_id>.jsonl if present, else []."""
    path = Path(obs_dir) / f"{target_id}.jsonl"
    if not path.exists():
        return []
    from osint_ai_pwg.collect.store import load_observations as _load

    return _load(path)


def load_ground_truth(gt_dir: Path, target_id: str) -> dict | None:
    """Read data/ground_truth/<target_id>.json if present, else None."""
    path = Path(gt_dir) / f"{target_id}.json"
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------- build


def relation_for(field: str) -> str:
    return FIELD_RELATION.get(field, "has")


def _gt_label(gt: dict | None, target_id: str) -> str:
    if gt:
        name = ((gt.get("pii") or {}).get("Identity") or {}).get("name")
        if name:
            return str(name)
    return target_id


def _flatten_gt(gt: dict) -> list[tuple[str, str, str]]:
    """[(field, value, group)] from a ground-truth JSON's nested ``pii`` block."""
    out: list[tuple[str, str, str]] = []
    for group, fields in (gt.get("pii") or {}).items():
        if not isinstance(fields, dict):
            continue
        for field, value in fields.items():
            if value:
                out.append((field, str(value), group))
    return out


def _planted_sources(gt: dict | None) -> dict[str, list[str]]:
    if not gt:
        return {}
    planted = gt.get("planted") or {}
    return {k: [str(s) for s in v] for k, v in planted.items() if isinstance(v, list)}


def build_payload(
    observations: list[Observation] | None,
    target_id: str,
    *,
    target_label: str | None = None,
    ground_truth: dict | None = None,
    view: str = "entities",
) -> dict[str, Any]:
    """Build ``{nodes, links}`` for the entity graph.

    ``view='entities'`` keeps only person + PII value nodes; ``view='provenance'`` adds
    one source node per distinct tool and a ``reported by`` edge from each value.
    """
    nodes: dict[str, dict] = {}
    links: list[dict] = []
    label = target_label or _gt_label(ground_truth, target_id)

    nodes["person"] = {"id": "person", "label": label, "kind": "person", "group": "Person"}

    def add_entity(field: str, value: str, group: str, sources: int,
                   urls: list[str] | None = None) -> str:
        nid = f"{field}:{value}"
        urls = [u for u in (urls or []) if u]
        nodes[nid] = {
            "id": nid, "label": value, "kind": "entity", "group": group,
            "field": field, "value": value, "sources": sources,
            "url": urls[0] if urls else "", "urls": urls,
        }
        links.append({"source": "person", "target": nid, "rel": relation_for(field)})
        return nid

    def add_source(nid: str, source: str, rel: str, directness: str = "stated") -> None:
        sid = f"src:{source}"
        nodes.setdefault(sid, {"id": sid, "label": source, "kind": "source", "group": "Source"})
        links.append({"source": nid, "target": sid, "rel": rel, "directness": directness})

    if observations:
        # merge per (field, value): distinct sources + strongest directness
        merged: dict[tuple[str, str], dict] = {}
        for o in observations:
            key = (o.field, o.value)
            rec = merged.setdefault(
                key, {"group": o.group.value, "sources": set(),
                      "directness": o.directness, "urls": []}
            )
            rec["sources"].add(o.source)
            if o.url and o.url not in rec["urls"]:
                rec["urls"].append(o.url)
            if _DIRECTNESS_RANK.get(o.directness, 0) > _DIRECTNESS_RANK.get(rec["directness"], 0):
                rec["directness"] = o.directness

        for (field, value), rec in merged.items():
            nid = add_entity(field, value, rec["group"], len(rec["sources"]), rec["urls"])
            if view == "provenance":
                for src in sorted(rec["sources"]):
                    add_source(nid, src, "reported by", rec["directness"].value)

    elif ground_truth:
        planted = _planted_sources(ground_truth)
        for field, value, group in _flatten_gt(ground_truth):
            nid = add_entity(field, value, group, len(planted.get(field, [])))
            if view == "provenance":
                for src in planted.get(field, []):
                    add_source(nid, src, "planted in", "stated")

    return {
        "target_id": target_id,
        "label": label,
        "view": view,
        "origin": "observations" if observations else ("ground_truth" if ground_truth else "empty"),
        "nodes": list(nodes.values()),
        "links": links,
    }


# --------------------------------------------------------------------------- html


_HTML = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>__TITLE__</title>
<script src="https://d3js.org/d3.v7.min.js"></script>
<style>
body{margin:0;background:#1b1b1b;color:#e6e6e6;font-family:system-ui,sans-serif;overflow:hidden}
#hud{position:absolute;top:14px;left:14px;font-size:13px;color:#a8adb3}
#legend{position:absolute;top:14px;right:14px;background:#242424;border:1px solid #3a3a3a;
 border-radius:8px;padding:12px 14px;font-size:12px}
.row{display:flex;align-items:center;margin:4px 0}
.dot{width:11px;height:11px;border-radius:50%;margin-right:8px;display:inline-block}
</style></head><body>
<div id="hud"><b style="color:#e6e6e6">__TITLE__</b><br>__ORIGIN__ &middot; <a href="?view=entities" style="color:#58a6ff">entities</a> &middot; <a href="?view=provenance" style="color:#58a6ff">provenance</a> &middot; drag to move, scroll to zoom</div>
<div id="legend"><div style="font-weight:600;margin-bottom:6px">Entity type</div>
 <div class="row"><span class="dot" style="background:#e74c3c"></span>Person</div>
 <div class="row"><span class="dot" style="background:#3498db"></span>Identity</div>
 <div class="row"><span class="dot" style="background:#e67e22"></span>Temporal</div>
 <div class="row"><span class="dot" style="background:#2ecc71"></span>Location</div>
 <div class="row"><span class="dot" style="background:#9b59b6"></span>Contact</div>
 <div class="row"><span class="dot" style="background:#8a8f94"></span>Source</div>
</div>
<script>
const data=__GRAPH__;
const w=innerWidth,h=innerHeight;
const svg=d3.select("body").append("svg").attr("width",w).attr("height",h);
const g=svg.append("g");
svg.call(d3.zoom().on("zoom",e=>g.attr("transform",e.transform)));
const nodes=data.nodes.map(d=>({...d})), links=data.links.map(d=>({...d}));
const sim=d3.forceSimulation(nodes)
 .force("link",d3.forceLink(links).id(d=>d.id).distance(d=>d.rel==="reported by"||d.rel==="planted in"?80:120))
 .force("charge",d3.forceManyBody().strength(-380))
 .force("center",d3.forceCenter(w/2,h/2))
 .force("collide",d3.forceCollide().radius(d=>d.kind==="person"?34:22));
const link=g.append("g").selectAll("line").data(links).join("line")
 .attr("stroke","#5f6368").attr("stroke-opacity",.55).attr("stroke-width",1.5)
 .attr("stroke-dasharray",d=>(d.directness&&d.directness!=="stated")?"4,3":null);
const elab=g.append("g").selectAll("text").data(links).join("text")
 .text(d=>d.rel).attr("font-size",8.5).attr("fill","#7d8288").attr("text-anchor","middle");
const node=g.append("g").selectAll("g").data(nodes).join("g").call(
 d3.drag().on("start",(e,d)=>{if(!e.active)sim.alphaTarget(.3).restart();d.fx=d.x;d.fy=d.y;})
  .on("drag",(e,d)=>{d.fx=e.x;d.fy=e.y;})
  .on("end",(e,d)=>{if(!e.active)sim.alphaTarget(0);d.fx=null;d.fy=null;}));
node.append("circle").attr("r",d=>d.kind==="person"?22:(d.kind==="source"?9:13+1.5*(d.sources||0)))
 .attr("fill",d=>data.colors[d.group]||"#8a8f94").attr("stroke","#111").attr("stroke-width",1.5);
node.style("cursor",d=>d.url?"pointer":"grab")
 .on("click",(e,d)=>{if(d.url){window.open(d.url,"_blank","noopener");}});
node.append("text").text(d=>d.label).attr("x",16).attr("y",4).attr("font-size",11.5)
 .attr("fill","#e6e6e6").attr("font-weight",d=>d.kind==="person"?700:400);
node.append("title").text(d=>d.kind==="entity"
 ? `${d.field}: ${d.value}  —  ${d.sources} source(s)${d.url?"  ·  click to open proof":""}` : d.label);
sim.on("tick",()=>{
 link.attr("x1",d=>d.source.x).attr("y1",d=>d.source.y)
     .attr("x2",d=>d.target.x).attr("y2",d=>d.target.y);
 elab.attr("x",d=>(d.source.x+d.target.x)/2).attr("y",d=>(d.source.y+d.target.y)/2-3);
 node.attr("transform",d=>`translate(${d.x},${d.y})`);
});
</script></body></html>"""


def render_html(payload: dict[str, Any], title: str | None = None) -> str:
    """Self-contained dark d3 HTML for a graph payload (no server, no extra deps)."""
    resolved_title: str = title or f"Entity graph — {payload.get('target_id', '')}"
    origin = {"observations": "collected observations", "ground_truth": "planted ground truth",
              "empty": "no data yet"}.get(payload.get("origin", ""), payload.get("origin", ""))
    data = dict(payload)
    data["colors"] = GROUP_COLOR
    return (
        _HTML.replace("__TITLE__", resolved_title)
        .replace("__ORIGIN__", origin)
        .replace("__GRAPH__", json.dumps(data))
    )


# --------------------------------------------------------------------------- png


def render_png(payload: dict[str, Any], out_path: Path | str) -> Path:
    """Dark force-directed PNG. Requires matplotlib (+networkx) from the 'analysis' extra."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import networkx as nx

    G = nx.Graph()
    meta: dict[str, dict] = {}
    for n in payload["nodes"]:
        G.add_node(n["id"])
        meta[n["id"]] = n
    for link in payload["links"]:
        G.add_edge(link["source"], link["target"], rel=link.get("rel", ""))

    if G.number_of_nodes() == 0:
        raise ValueError("empty graph — nothing to render")

    bg = "#1b1b1b"
    plt.rcParams.update({"figure.facecolor": bg, "axes.facecolor": bg, "text.color": "#e6e6e6"})
    fig, ax = plt.subplots(figsize=(13, 8))
    pos = nx.spring_layout(G, k=1.3, iterations=220, seed=7)

    colors, sizes = [], []
    for nid in G.nodes:
        m = meta[nid]
        colors.append(GROUP_COLOR.get(m.get("group", ""), "#8a8f94"))
        sizes.append(2500 if m.get("kind") == "person" else
                     900 if m.get("kind") == "source" else 1300 + 180 * m.get("sources", 0))

    nx.draw_networkx_edges(G, pos, ax=ax, edge_color="#5f6368", width=1.5, alpha=0.65)
    nx.draw_networkx_nodes(G, pos, ax=ax, node_color=colors, node_size=sizes,
                           edgecolors="#111", linewidths=1.4, alpha=0.95)
    nx.draw_networkx_labels(G, pos, {n: meta[n]["label"] for n in G.nodes},
                            ax=ax, font_size=8, font_color="#e6e6e6")
    nx.draw_networkx_edge_labels(
        G, pos, edge_labels={(a, b): d["rel"] for a, b, d in G.edges(data=True)},
        ax=ax, font_size=6.5, font_color="#a8adb3",
        bbox=dict(boxstyle="round,pad=0.15", fc=bg, ec="none", alpha=0.85),
    )

    from matplotlib.patches import Patch

    handles = [Patch(color=c, label=g) for g, c in GROUP_COLOR.items()]
    ax.legend(handles=handles, loc="center right", fontsize=9, frameon=True,
              facecolor="#242424", edgecolor="#3a3a3a", labelcolor="#e6e6e6",
              title="Entity type", title_fontsize=10)
    ax.set_title(f"OSINT entity graph — {payload.get('label', '')}", color="#e6e6e6", fontsize=13, pad=14)
    ax.axis("off")
    plt.tight_layout()

    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(out, dpi=150, facecolor=bg, bbox_inches="tight")
    plt.close(fig)
    return out


# --------------------------------------------------------------------------- cli


def main(argv: list[str] | None = None) -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Render a target's OSINT entity graph.")
    ap.add_argument("target_id")
    ap.add_argument("--obs-dir", default="data/observations")
    ap.add_argument("--gt-dir", default="data/ground_truth")
    ap.add_argument("--out", default="out/graphs", help="output directory")
    ap.add_argument("--view", choices=("entities", "provenance"), default="entities")
    ap.add_argument("--png", action="store_true", help="also render a PNG (needs analysis extra)")
    args = ap.parse_args(argv)

    obs = load_observations(Path(args.obs_dir), args.target_id)
    gt = load_ground_truth(Path(args.gt_dir), args.target_id)
    payload = build_payload(obs, args.target_id, ground_truth=gt, view=args.view)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / f"{args.target_id}_{args.view}.html"
    html_path.write_text(render_html(payload, f"Entity graph — {payload['label']}"), encoding="utf-8")
    print(f"wrote {html_path}  ({len(payload['nodes'])} nodes, {len(payload['links'])} links, origin={payload['origin']})")

    if args.png:
        png_path = render_png(payload, out_dir / f"{args.target_id}_{args.view}.png")
        print(f"wrote {png_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
