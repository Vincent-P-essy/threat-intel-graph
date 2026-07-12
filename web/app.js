"use strict";

/**
 * Threat Intel Graph explorer — a D3 force-directed graph over the /api backend.
 * Renders nodes coloured by STIX category (or by detected community), lets you
 * filter node types, inspect a node's neighbourhood, export a STIX bundle, and
 * generate a campaign narrative.
 */

const COLORS = {
  ip: "#f87171",
  domain: "#fbbf24",
  url: "#fb923c",
  hash: "#a78bfa",
  cve: "#f472b6",
  actor: "#38bdf8",
  campaign: "#34d399",
  technique: "#60a5fa",
  malware: "#f43f5e",
};
const RADIUS = { actor: 13, campaign: 12, malware: 10, technique: 8, cve: 8 };
const community_palette = d3.schemeTableau10;

const svg = d3.select("#graph");
const gLink = svg.append("g");
const gNode = svg.append("g");
const gLabel = svg.append("g");
const tooltip = d3.select("body").append("div").attr("class", "tooltip");

let allNodes = [], allLinks = [], sim, communityMap = {}, colorByCommunity = false;
const hidden = new Set();

const zoom = d3.zoom().scaleExtent([0.2, 4]).on("zoom", (e) => {
  gLink.attr("transform", e.transform);
  gNode.attr("transform", e.transform);
  gLabel.attr("transform", e.transform);
});
svg.call(zoom);

init();

async function init() {
  const [graph, communities] = await Promise.all([
    fetch("/api/graph").then((r) => r.json()),
    fetch("/api/analysis/communities").then((r) => r.json()),
  ]);
  allNodes = graph.nodes.map((n) => ({ ...n }));
  allLinks = graph.links.map((l) => ({ ...l }));
  communities.forEach((c, i) => c.members.forEach((m) => (communityMap[m] = i)));

  d3.select("#stats").text(`${allNodes.length} nodes · ${allLinks.length} edges · ${communities.length} communities`);
  buildFilters();
  render();
}

function buildFilters() {
  const cats = [...new Set(allNodes.map((n) => n.category))].sort();
  const box = d3.select("#type-filters");
  cats.forEach((cat) => {
    const label = box.append("label");
    label.append("input").attr("type", "checkbox").property("checked", true)
      .on("change", function () {
        if (this.checked) hidden.delete(cat); else hidden.add(cat);
        render();
      });
    label.append("span").attr("class", "swatch").style("background", COLORS[cat] || "#888");
    label.append("span").text(cat);
  });
}

function visibleData() {
  const nodes = allNodes.filter((n) => !hidden.has(n.category));
  const ids = new Set(nodes.map((n) => n.id));
  const links = allLinks.filter((l) => ids.has(srcId(l)) && ids.has(tgtId(l)));
  return { nodes, links };
}
const srcId = (l) => (typeof l.source === "object" ? l.source.id : l.source);
const tgtId = (l) => (typeof l.target === "object" ? l.target.id : l.target);

function fill(n) {
  if (colorByCommunity && communityMap[n.id] !== undefined)
    return community_palette[communityMap[n.id] % community_palette.length];
  return COLORS[n.category] || "#888";
}

function render() {
  const { nodes, links } = visibleData();
  const w = svg.node().clientWidth, h = svg.node().clientHeight;

  const link = gLink.selectAll("line").data(links, (d) => srcId(d) + tgtId(d) + d.rel);
  link.exit().remove();
  const linkEnter = link.enter().append("line").attr("class", "link");
  const links_all = linkEnter.merge(link);

  const node = gNode.selectAll("circle").data(nodes, (d) => d.id);
  node.exit().remove();
  const nodeEnter = node.enter().append("circle").attr("class", "node")
    .attr("r", (d) => RADIUS[d.category] || 6)
    .call(drag())
    .on("click", (_, d) => inspect(d))
    .on("mouseover", (e, d) => tooltip.style("opacity", 1).html(`${d.category}: ${d.label}`))
    .on("mousemove", (e) => tooltip.style("left", e.pageX + 12 + "px").style("top", e.pageY + 12 + "px"))
    .on("mouseout", () => tooltip.style("opacity", 0));
  const nodes_all = nodeEnter.merge(node).attr("fill", fill);

  const label = gLabel.selectAll("text").data(nodes, (d) => d.id);
  label.exit().remove();
  const labels_all = label.enter().append("text").attr("class", "nlabel")
    .text((d) => (d.label.length > 22 ? d.label.slice(0, 22) + "…" : d.label))
    .merge(label);

  sim = d3.forceSimulation(nodes)
    .force("link", d3.forceLink(links).id((d) => d.id).distance(70).strength(0.5))
    .force("charge", d3.forceManyBody().strength(-260))
    .force("center", d3.forceCenter(w / 2, h / 2))
    .force("collide", d3.forceCollide().radius((d) => (RADIUS[d.category] || 6) + 4))
    .on("tick", () => {
      links_all.attr("x1", (d) => d.source.x).attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x).attr("y2", (d) => d.target.y);
      nodes_all.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
      labels_all.attr("x", (d) => d.x + 10).attr("y", (d) => d.y + 3);
    });
  sim.alpha(0.9).restart();
}

function drag() {
  return d3.drag()
    .on("start", (e, d) => { if (!e.active) sim.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
    .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
    .on("end", (e, d) => { if (!e.active) sim.alphaTarget(0); d.fx = null; d.fy = null; });
}

async function inspect(d) {
  highlightNeighborhood(d.id);
  const res = await fetch(`/api/node/${encodeURIComponent(d.id)}?depth=1`).then((r) => r.json());
  const nbr = res.neighborhood;
  const rows = Object.entries(d)
    .filter(([k]) => !["id", "x", "y", "vx", "vy", "index", "fx", "fy"].includes(k))
    .map(([k, v]) => `<div class="kv"><span>${k}</span><span class="val">${fmt(v)}</span></div>`).join("");

  d3.select("#detail").html(`
    <div class="badge">${d.category}</div>
    <h4 style="margin:8px 0 6px">${escapeHtml(d.label)}</h4>
    ${rows}
    <div class="kv"><span>neighbours</span><span class="val">${nbr.nodes.length - 1}</span></div>
    <div class="actions">
      <button id="stix-btn" class="ghost">Export STIX</button>
      <button id="narr-btn">Narrative</button>
    </div>
    <div id="narr-out"></div>`);

  document.getElementById("stix-btn").onclick = () =>
    window.open(`/api/stix/${encodeURIComponent(d.id)}?depth=2`, "_blank");
  document.getElementById("narr-btn").onclick = async () => {
    document.getElementById("narr-out").innerHTML = `<div class="narrative">generating…</div>`;
    const n = await fetch(`/api/narrative/${encodeURIComponent(d.id)}?depth=2`).then((r) => r.json());
    document.getElementById("narr-out").innerHTML =
      `<div class="narrative">${escapeHtml(n.narrative)}</div><div class="badge" style="margin-top:6px">narrator: ${n.narrator}</div>`;
  };
}

function highlightNeighborhood(id) {
  const linked = new Set([id]);
  allLinks.forEach((l) => {
    if (srcId(l) === id) linked.add(tgtId(l));
    if (tgtId(l) === id) linked.add(srcId(l));
  });
  gNode.selectAll("circle").classed("dim", (d) => !linked.has(d.id)).classed("pulse", (d) => d.id === id);
  gLink.selectAll("line")
    .classed("hot", (l) => srcId(l) === id || tgtId(l) === id)
    .classed("dim", (l) => !(linked.has(srcId(l)) && linked.has(tgtId(l))));
}

document.getElementById("color-community").addEventListener("change", (e) => {
  colorByCommunity = e.target.checked;
  gNode.selectAll("circle").attr("fill", fill);
});

document.getElementById("central-btn").addEventListener("click", async () => {
  const central = await fetch("/api/analysis/central?top=5").then((r) => r.json());
  const top = new Set(central.map((c) => c.id));
  gNode.selectAll("circle").classed("dim", (d) => !top.has(d.id)).classed("pulse", (d) => top.has(d.id));
  gLink.selectAll("line").classed("dim", true).classed("hot", false);
  d3.select("#detail").html(
    `<h4 style="margin:0 0 8px">Top by PageRank</h4>` +
    central.map((c) => `<div class="kv"><span>${c.category}</span><span class="val">${escapeHtml(c.label)} · ${c.pagerank}</span></div>`).join(""));
});

function fmt(v) { return escapeHtml(Array.isArray(v) ? v.join(", ") : String(v)); }
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
