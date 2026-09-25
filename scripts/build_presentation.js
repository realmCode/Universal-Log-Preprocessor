const pptxgen = require("pptxgenjs");
const React = require("react");
const ReactDOMServer = require("react-dom/server");
const sharp = require("sharp");
const { FaSearch, FaPlug, FaDatabase, FaProjectDiagram, FaRocket } = require("react-icons/fa");

async function iconToBase64Png(IconComponent, color, size = 256) {
  const svg = ReactDOMServer.renderToStaticMarkup(
    React.createElement(IconComponent, { color, size: String(size) })
  );
  const png = await sharp(Buffer.from(svg)).png().toBuffer();
  return "image/png;base64," + png.toString("base64");
}

async function main() {
  const pres = new pptxgen();
  pres.layout = "LAYOUT_16x9";
  pres.author = "ULPF Team";
  pres.title = "ULPF: Universal Log Pre-processing Framework";

  // Colors — Midnight Executive
  const C = {
    navy: "1E2761",
    ice: "CADCFC",
    white: "FFFFFF",
    offWhite: "F5F7FA",
    text: "1E293B",
    muted: "64748B",
    accent: "38BDF8",
    cardBg: "FFFFFF",
  };

  // ─────────────────────────────────────────────
  // SLIDE 1 — Title (dark navy background)
  // ─────────────────────────────────────────────
  const s1 = pres.addSlide();
  s1.background = { color: C.navy };

  // Accent bar at top
  s1.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 0.06, fill: { color: C.accent } });

  // Title
  s1.addText("ULPF", {
    x: 0.7, y: 1.0, w: 8.5, h: 1.3,
    fontSize: 72, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", valign: "middle", margin: 0,
  });

  s1.addText("Universal Log Pre-processing Framework", {
    x: 0.7, y: 2.2, w: 8.5, h: 0.6,
    fontSize: 28, fontFace: "Calibri", bold: false,
    color: C.ice, align: "left", valign: "middle", margin: 0,
  });

  s1.addText("SIH26 — NTRO Problem #26156", {
    x: 0.7, y: 2.85, w: 8.5, h: 0.4,
    fontSize: 16, fontFace: "Calibri",
    color: C.accent, align: "left", margin: 0,
  });

  // Tagline
  s1.addText("Universal  ·  Extensible  ·  Lossless  ·  Scalable", {
    x: 0.7, y: 3.5, w: 8.5, h: 0.4,
    fontSize: 14, fontFace: "Calibri",
    color: C.muted, align: "left", margin: 0,
  });

  // Bottom line
  s1.addShape(pres.shapes.RECTANGLE, { x: 0.7, y: 4.5, w: 8.5, h: 0.02, fill: { color: C.ice, transparency: 50 } });

  // ─────────────────────────────────────────────
  // SLIDE 2 — The Problem
  // ─────────────────────────────────────────────
  const s2 = pres.addSlide();
  s2.background = { color: C.offWhite };

  s2.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 0.06, fill: { color: C.navy } });

  s2.addText("The Problem: Log Chaos at Scale", {
    x: 0.5, y: 0.25, w: 9, h: 0.7,
    fontSize: 32, fontFace: "Calibri", bold: true,
    color: C.navy, align: "left", margin: 0,
  });

  // Problem cards — 2 columns
  const problems = [
    { title: "Thousands of Sources", desc: "Firewalls, servers, containers, IoT, databases, cloud services — each producing logs in their own format." },
    { title: "Format Fragmentation", desc: "Syslog, JSON, XML, CEF, LEEF, proprietary vendor formats — no common standard." },
    { title: "New Source Overhead", desc: "Every new log source requires weeks of parser development before analytics can begin." },
    { title: "Broken Analytics", desc: "Threat hunting, compliance reporting, and incident response all hampered by incompatible formats." },
  ];

  const cols = [
    { x: 0.5, w: 4.2 },
    { x: 5.3, w: 4.2 },
  ];

  problems.forEach((p, i) => {
    const col = cols[i % 2];
    const row = Math.floor(i / 2);
    const y = 1.2 + row * 1.8;

    s2.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: col.x, y, w: col.w, h: 1.55,
      fill: { color: C.cardBg },
      shadow: { type: "outer", color: "000000", blur: 4, offset: 2, angle: 135, opacity: 0.08 },
      rectRadius: 0.05,
    });

    // Number circle
    s2.addShape(pres.shapes.OVAL, {
      x: col.x + 0.15, y: y + 0.2, w: 0.4, h: 0.4,
      fill: { color: C.navy },
    });
    s2.addText(String(i + 1), {
      x: col.x + 0.15, y: y + 0.2, w: 0.4, h: 0.4,
      fontSize: 16, fontFace: "Calibri", bold: true,
      color: C.white, align: "center", valign: "middle", margin: 0,
    });

    s2.addText(p.title, {
      x: col.x + 0.65, y: y + 0.15, w: col.w - 0.8, h: 0.4,
      fontSize: 16, fontFace: "Calibri", bold: true,
      color: C.navy, align: "left", margin: 0,
    });
    s2.addText(p.desc, {
      x: col.x + 0.15, y: y + 0.65, w: col.w - 0.3, h: 0.75,
      fontSize: 13, fontFace: "Calibri",
      color: C.text, align: "left", margin: 0,
    });
  });

  // ─────────────────────────────────────────────
  // SLIDE 3 — The Solution
  // ─────────────────────────────────────────────
  const s3 = pres.addSlide();
  s3.background = { color: C.offWhite };
  s3.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 0.06, fill: { color: C.accent } });

  s3.addText("Our Solution: ULPF", {
    x: 0.5, y: 0.25, w: 9, h: 0.7,
    fontSize: 32, fontFace: "Calibri", bold: true,
    color: C.navy, align: "left", margin: 0,
  });

  // Pre-render icons
  const iconPlug = await iconToBase64Png(FaPlug, "#1E2761", 256);
  const iconDb = await iconToBase64Png(FaDatabase, "#1E2761", 256);
  const iconSearch = await iconToBase64Png(FaSearch, "#1E2761", 256);
  const iconFlow = await iconToBase64Png(FaProjectDiagram, "#1E2761", 256);

  const solutions = [
    { title: "Plug-and-Play Modules", desc: "Drop a YAML config or Python class into the modules/ directory. Auto-discovered at startup. No framework code changes.", icon: iconPlug },
    { title: "5 Built-in Parsers", desc: "Cisco ASA, Nginx, Linux Syslog, Generic Syslog, Generic JSON — covering the most common enterprise log sources.", icon: iconDb },
    { title: "Drain3 AI Discovery", desc: "Automatic template mining for unknown log sources. Discovers patterns from IoT, proprietary, and custom formats.", icon: iconSearch },
    { title: "Streaming Architecture", desc: "Kafka + Pathway workers handle billions of events/day. Stateless, horizontally scalable, with backpressure.", icon: iconFlow },
  ];

  solutions.forEach((sol, i) => {
    const x = 0.5 + (i % 2) * 4.7;
    const y = 1.15 + Math.floor(i / 2) * 1.85;

    s3.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y, w: 4.5, h: 1.7,
      fill: { color: C.cardBg },
      shadow: { type: "outer", color: "000000", blur: 4, offset: 2, angle: 135, opacity: 0.08 },
      rectRadius: 0.05,
    });

    s3.addImage({ data: sol.icon, x: x + 0.2, y: y + 0.2, w: 0.5, h: 0.5 });

    s3.addText(sol.title, {
      x: x + 0.8, y: y + 0.15, w: 3.5, h: 0.4,
      fontSize: 16, fontFace: "Calibri", bold: true,
      color: C.navy, align: "left", margin: 0,
    });
    s3.addText(sol.desc, {
      x: x + 0.2, y: y + 0.7, w: 4.1, h: 0.85,
      fontSize: 13, fontFace: "Calibri",
      color: C.text, align: "left", margin: 0,
    });
  });

  // Bottom stats
  s3.addText("Deployable in air-gapped networks · Containerized · AI/ML ready", {
    x: 0.5, y: 5.0, w: 9, h: 0.35,
    fontSize: 12, fontFace: "Calibri", italic: true,
    color: C.muted, align: "center", margin: 0,
  });

  // ─────────────────────────────────────────────
  // SLIDE 4 — Architecture
  // ─────────────────────────────────────────────
  const s4 = pres.addSlide();
  s4.background = { color: C.offWhite };
  s4.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 0.06, fill: { color: C.navy } });

  s4.addText("Architecture: Streaming Pipeline", {
    x: 0.5, y: 0.25, w: 9, h: 0.7,
    fontSize: 32, fontFace: "Calibri", bold: true,
    color: C.navy, align: "left", margin: 0,
  });

  // Source boxes (left side)
  const sources = ["Firewalls", "Servers", "Containers", "IoT", "Databases"];
  sources.forEach((src, i) => {
    s4.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 0.4, y: 1.1 + i * 0.7, w: 1.8, h: 0.5,
      fill: { color: C.navy },
      rectRadius: 0.04,
    });
    s4.addText(src, {
      x: 0.4, y: 1.1 + i * 0.7, w: 1.8, h: 0.5,
      fontSize: 12, fontFace: "Calibri", bold: true,
      color: C.white, align: "center", valign: "middle", margin: 0,
    });
  });

  // Arrow 1: Sources → Kafka
  s4.addShape(pres.shapes.LINE, {
    x: 2.2, y: 3.25, w: 0.8, h: 0,
    line: { color: C.muted, width: 2 },
  });
  s4.addText("push", {
    x: 2.35, y: 2.9, w: 0.5, h: 0.3,
    fontSize: 9, fontFace: "Calibri",
    color: C.muted, align: "center", margin: 0,
  });

  // Kafka box
  s4.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 3.0, y: 2.3, w: 1.8, h: 1.0,
    fill: { color: "374151" },
    rectRadius: 0.04,
  });
  s4.addText("Kafka Broker", {
    x: 3.0, y: 2.5, w: 1.8, h: 0.4,
    fontSize: 13, fontFace: "Calibri", bold: true,
    color: C.white, align: "center", margin: 0,
  });
  s4.addText("raw_logs topic", {
    x: 3.0, y: 2.9, w: 1.8, h: 0.3,
    fontSize: 10, fontFace: "Calibri",
    color: C.ice, align: "center", margin: 0,
  });

  // Arrow 2: Kafka → Workers
  s4.addShape(pres.shapes.LINE, {
    x: 4.8, y: 2.8, w: 0.7, h: 0,
    line: { color: C.muted, width: 2 },
  });

  // Pathway Workers box
  s4.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 5.5, y: 1.3, w: 2.8, h: 3.0,
    fill: { color: C.navy },
    shadow: { type: "outer", color: "000000", blur: 6, offset: 2, angle: 135, opacity: 0.12 },
    rectRadius: 0.06,
  });
  s4.addText("ULPF Workers", {
    x: 5.5, y: 1.4, w: 2.8, h: 0.4,
    fontSize: 14, fontFace: "Calibri", bold: true,
    color: C.accent, align: "center", margin: 0,
  });

  const pipelineSteps = [
    "1. Format Detect",
    "2. Module Match",
    "3. Parse",
    "4. Normalize",
    "5. Enrich",
    "6. Output",
  ];
  pipelineSteps.forEach((step, i) => {
    s4.addText(step, {
      x: 5.7, y: 1.9 + i * 0.38, w: 2.4, h: 0.33,
      fontSize: 11, fontFace: "Calibri",
      color: C.white, align: "left", margin: 0,
    });
  });

  // Arrow 3: Workers → Outputs
  s4.addShape(pres.shapes.LINE, {
    x: 8.3, y: 2.8, w: 0.5, h: 0,
    line: { color: C.muted, width: 2 },
  });

  // Output boxes (right side)
  const outputs = [
    { name: "Kafka\nnormalized", color: "374151", y: 1.1 },
    { name: "Elasticsearch\n(SIEM)", color: C.navy, y: 2.4 },
    { name: "S3 / MinIO\n(archival)", color: "1a2744", y: 3.7 },
  ];

  outputs.forEach((out) => {
    s4.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x: 8.8, y: out.y, w: 1.0, h: 0.7,
      fill: { color: out.color },
      rectRadius: 0.04,
    });
    s4.addText(out.name, {
      x: 8.8, y: out.y, w: 1.0, h: 0.7,
      fontSize: 10, fontFace: "Calibri", bold: true,
      color: C.white, align: "center", valign: "middle", margin: 0,
    });
  });

  // Key properties
  s4.addShape(pres.shapes.ROUNDED_RECTANGLE, {
    x: 0.4, y: 4.7, w: 9.2, h: 0.65,
    fill: { color: C.white },
    shadow: { type: "outer", color: "000000", blur: 3, offset: 1, angle: 135, opacity: 0.06 },
    rectRadius: 0.04,
  });
  s4.addText("Key Properties:  Push-based ingestion  ·  Lossless preservation  ·  Stateless workers  ·  Drain3 LRU eviction  ·  Air-gap ready  ·  No external API dependencies", {
    x: 0.6, y: 4.75, w: 8.8, h: 0.5,
    fontSize: 11, fontFace: "Calibri",
    color: C.text, align: "center", valign: "middle", margin: 0,
  });

  // ─────────────────────────────────────────────
  // SLIDE 5 — Demo & Results
  // ─────────────────────────────────────────────
  const s5 = pres.addSlide();
  s5.background = { color: C.navy };
  s5.addShape(pres.shapes.RECTANGLE, { x: 0, y: 0, w: 10, h: 0.06, fill: { color: C.accent } });

  s5.addText("Demo & Results", {
    x: 0.5, y: 0.25, w: 9, h: 0.7,
    fontSize: 32, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0,
  });

  // Big stat callouts — row of 4
  const stats = [
    { num: "7/7", label: "Tests Passing" },
    { num: "3,500+", label: "Events/sec" },
    { num: "5", label: "Parser Modules" },
    { num: "0", label: "Errors in Demo" },
  ];

  stats.forEach((stat, i) => {
    const x = 0.4 + i * 2.35;
    s5.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 1.15, w: 2.2, h: 1.1,
      fill: { color: "243057" },
      rectRadius: 0.05,
    });
    s5.addText(stat.num, {
      x, y: 1.2, w: 2.2, h: 0.6,
      fontSize: 36, fontFace: "Calibri", bold: true,
      color: C.accent, align: "center", valign: "middle", margin: 0,
    });
    s5.addText(stat.label, {
      x, y: 1.75, w: 2.2, h: 0.35,
      fontSize: 11, fontFace: "Calibri",
      color: C.ice, align: "center", margin: 0,
    });
  });

  // Architecture highlights
  s5.addText("Architecture Highlights", {
    x: 0.5, y: 2.45, w: 9, h: 0.35,
    fontSize: 18, fontFace: "Calibri", bold: true,
    color: C.white, align: "left", margin: 0,
  });

  const highlights = [
    { title: "Format Coverage", items: ["JSON", "Syslog (RFC 3164/5424)", "CEF/LEEF", "Nginx access logs", "Cisco ASA firewall"] },
    { title: "Drain3 Discovery", items: ["Auto-mines log templates", "Handles IoT & proprietary formats", "Generates YAML config scaffolds", "LRU eviction for memory"] },
    { title: "Deployment", items: ["Air-gapped network ready", "Docker Compose orchestration", "Kafka streaming pipeline", "No runtime external APIs"] },
  ];

  highlights.forEach((h, i) => {
    const x = 0.4 + i * 3.1;
    s5.addShape(pres.shapes.ROUNDED_RECTANGLE, {
      x, y: 2.9, w: 2.95, h: 1.9,
      fill: { color: "243057" },
      rectRadius: 0.04,
    });
    s5.addText(h.title, {
      x: x + 0.15, y: 3.0, w: 2.65, h: 0.35,
      fontSize: 14, fontFace: "Calibri", bold: true,
      color: C.accent, align: "left", margin: 0,
    });

    const items = h.items.map((item, idx) => ({
      text: item,
      options: { bullet: { code: "2022", indent: 12, color: C.accent }, breakLine: idx < h.items.length - 1, fontSize: 11, color: C.ice },
    }));
    s5.addText(items, {
      x: x + 0.15, y: 3.4, w: 2.65, h: 1.3,
      fontFace: "Calibri", color: C.ice, align: "left", margin: 0, paraSpaceAfter: 4,
    });
  });

  // Deliverables
  s5.addText("Deliverables: Source Code · README · Architecture Document · Demo Video · Technical Presentation", {
    x: 0.5, y: 5.15, w: 9, h: 0.3,
    fontSize: 11, fontFace: "Calibri", italic: true,
    color: C.muted, align: "center", margin: 0,
  });

  // Footer
  s5.addText("ULPF — Universal Log Pre-processing Framework", {
    x: 0.5, y: 5.35, w: 9, h: 0.25,
    fontSize: 9, fontFace: "Calibri",
    color: C.muted, align: "center", margin: 0,
  });

  // Save
  const outPath = "C:/Users/DHC/Desktop/SIH26/docs/presentation.pptx";
  await pres.writeFile({ fileName: outPath });
  console.log("Saved:", outPath);
}

main().catch((err) => { console.error(err); process.exit(1); });
