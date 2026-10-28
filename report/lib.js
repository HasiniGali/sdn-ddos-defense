// Rendering helpers: a small spec language -> docx-js objects.
// Text markup: **bold**, *italic*, `code`, {fig:x}/{tab:x} cross-references,
// {f:key} values from facts.json (every number in the report comes from there).
const fs = require("fs");
const path = require("path");
const d = require("docx");

const FONT = "Calibri";
const MONO = "Consolas";
const PAGE_W = 11906, MARGIN = 1300;          // A4, ~0.9 in margins
const TEXT_W = PAGE_W - 2 * MARGIN;           // DXA

function makeResolver(spec, facts) {
  const nums = {}, counters = { fig: 0, tab: 0 };
  for (const b of spec) {
    if (b.label) {
      const kind = b.label.split(":")[0];
      nums[b.label] = ++counters[kind];
    }
  }
  return (text) => text
    .replace(/\{(fig|tab):([\w-]+)\}/g, (m, k, id) => {
      const n = nums[`${k}:${id}`];
      if (!n) throw new Error(`unknown reference ${m}`);
      return `${k === "fig" ? "Figure" : "Table"} ${n}`;
    })
    .replace(/\{f:([\w.-]+)\}/g, (m, key) => {
      if (!(key in facts)) {
        if (process.env.DRAFT) return `[[${key}]]`;
        throw new Error(`missing fact ${key}`);
      }
      return String(facts[key]);
    });
}

function runs(text, base = {}) {
  const out = [];
  const re = /(\*\*[^*]+\*\*|\*[^*]+\*|`[^`]+`)/g;
  let last = 0, m;
  while ((m = re.exec(text))) {
    if (m.index > last) out.push(new d.TextRun({ text: text.slice(last, m.index), ...base }));
    const t = m[0];
    if (t.startsWith("**")) out.push(new d.TextRun({ text: t.slice(2, -2), bold: true, ...base }));
    else if (t.startsWith("`")) out.push(new d.TextRun({ text: t.slice(1, -1), font: MONO, size: 19, ...base }));
    else out.push(new d.TextRun({ text: t.slice(1, -1), italics: true, ...base }));
    last = m.index + t.length;
  }
  if (last < text.length) out.push(new d.TextRun({ text: text.slice(last), ...base }));
  return out;
}

function cell(text, width, opts = {}) {
  return new d.TableCell({
    width: { size: width, type: d.WidthType.DXA },
    shading: opts.header ? { fill: "E8EEF6", type: d.ShadingType.CLEAR, color: "auto" } : undefined,
    margins: { top: 40, bottom: 40, left: 80, right: 80 },
    children: [new d.Paragraph({
      alignment: opts.align || d.AlignmentType.LEFT,
      spacing: { before: 0, after: 0, line: 240 },
      children: runs(String(text), { size: opts.size || 17, bold: !!opts.header }),
    })],
  });
}

function render(spec, facts, figDir) {
  const R = makeResolver(spec, facts);
  const counters = { fig: 0, tab: 0 };
  const out = [];
  const caption = (kind, text) => new d.Paragraph({
    alignment: d.AlignmentType.CENTER,
    spacing: { before: kind === "Table" ? 160 : 60, after: kind === "Table" ? 60 : 200 },
    keepNext: kind === "Table",
    children: [new d.TextRun({ text: `${kind} ${++counters[kind === "Table" ? "tab" : "fig"]}. `, bold: true, size: 19 }),
               ...runs(R(text), { size: 19 })],
  });
  for (const b of spec) {
    switch (b.type) {
      case "h1": out.push(new d.Paragraph({ heading: d.HeadingLevel.HEADING_1, pageBreakBefore: !!b.break, children: [new d.TextRun(R(b.text))] })); break;
      case "h2": out.push(new d.Paragraph({ heading: d.HeadingLevel.HEADING_2, children: [new d.TextRun(R(b.text))] })); break;
      case "h3": out.push(new d.Paragraph({ heading: d.HeadingLevel.HEADING_3, children: [new d.TextRun(R(b.text))] })); break;
      case "p": out.push(new d.Paragraph({ alignment: d.AlignmentType.JUSTIFIED, spacing: { after: 120 }, children: runs(R(b.text)) })); break;
      case "bullets":
        for (const t of b.items) out.push(new d.Paragraph({ numbering: { reference: "bullets", level: 0 }, spacing: { after: 60 }, children: runs(R(t)) }));
        break;
      case "numbered":
        for (const t of b.items) out.push(new d.Paragraph({ numbering: { reference: b.ref || "numbers", level: 0 }, spacing: { after: 60 }, children: runs(R(t)) }));
        break;
      case "code":
        for (const line of b.text.split("\n")) out.push(new d.Paragraph({
          spacing: { before: 0, after: 0, line: 240 }, shading: { fill: "F4F4F2", type: d.ShadingType.CLEAR, color: "auto" },
          indent: { left: 200 }, children: [new d.TextRun({ text: line || " ", font: MONO, size: 16 })] }));
        if (b.caption) out.push(caption("Figure", b.caption));
        else out.push(new d.Paragraph({ spacing: { after: 120 }, children: [] }));
        break;
      case "table": {
        let rowsData = b.rows || facts[b.rowsKey];
        if (!rowsData && process.env.DRAFT) rowsData = [b.header.map(() => `[[${b.rowsKey}]]`)];
        if (!rowsData) throw new Error(`missing table rows ${b.rowsKey}`);
        const ncol = b.header.length;
        const widths = b.widths
          ? b.widths.map((w) => Math.round(w * TEXT_W / b.widths.reduce((a, c) => a + c, 0)))
          : Array(ncol).fill(Math.floor(TEXT_W / ncol));
        const total = widths.reduce((a, c) => a + c, 0);
        out.push(caption("Table", b.caption));
        const rows = [new d.TableRow({ tableHeader: true, children: b.header.map((h, i) => cell(R(h), widths[i], { header: true, size: b.size })) })];
        for (const r of rowsData) rows.push(new d.TableRow({ cantSplit: true, children: r.map((v, i) => cell(R(String(v)), widths[i], { size: b.size, align: i > 0 && b.numeric !== false ? d.AlignmentType.RIGHT : d.AlignmentType.LEFT })) }));
        out.push(new d.Table({ width: { size: total, type: d.WidthType.DXA }, columnWidths: widths, rows }));
        if (b.note) out.push(new d.Paragraph({ spacing: { before: 40, after: 160 }, children: runs(R(b.note), { size: 16, italics: true }) }));
        else out.push(new d.Paragraph({ spacing: { after: 120 }, children: [] }));
        break;
      }
      case "figure": {
        const file = path.join(figDir, b.file);
        if (!fs.existsSync(file) && process.env.DRAFT) { out.push(caption("Figure", `[[missing ${b.file}]] ` + b.caption)); break; }
        const buf = fs.readFileSync(file);
        // PNG width/height from the IHDR chunk.
        const w = buf.readUInt32BE(16), h = buf.readUInt32BE(20);
        const widthPx = Math.round(Math.min(b.width || 5.8, 5.8) * 96);
        out.push(new d.Paragraph({ alignment: d.AlignmentType.CENTER, keepNext: true, spacing: { before: 120, after: 40 },
          children: [new d.ImageRun({ type: "png", data: buf, transformation: { width: widthPx, height: Math.round(widthPx * h / w) } })] }));
        out.push(caption("Figure", b.caption));
        break;
      }
      case "pagebreak": out.push(new d.Paragraph({ children: [new d.PageBreak()] })); break;
      case "toc": out.push(new d.TableOfContents("Contents", { hyperlink: true, headingStyleRange: "1-1" })); break;
      case "raw": out.push(...b.items); break;
      default: throw new Error(`unknown block ${b.type}`);
    }
  }
  return out;
}

const styles = {
  default: { document: { run: { font: FONT, size: 21 }, paragraph: { spacing: { line: 259 } } } },
  paragraphStyles: [
    { id: "Heading1", name: "Heading 1", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { size: 32, bold: true, color: "1F3864" }, paragraph: { spacing: { before: 240, after: 160 }, outlineLevel: 0 } },
    { id: "Heading2", name: "Heading 2", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { size: 26, bold: true, color: "1F3864" }, paragraph: { spacing: { before: 220, after: 100 }, outlineLevel: 1, keepNext: true } },
    { id: "Heading3", name: "Heading 3", basedOn: "Normal", next: "Normal", quickFormat: true,
      run: { size: 23, bold: true, italics: true }, paragraph: { spacing: { before: 160, after: 80 }, outlineLevel: 2, keepNext: true } },
  ],
};

const numbering = {
  config: [
    { reference: "bullets", levels: [{ level: 0, format: d.LevelFormat.BULLET, text: "•", alignment: d.AlignmentType.LEFT,
      style: { paragraph: { indent: { left: 540, hanging: 270 } } } }] },
    ...["numbers", "numbers2", "numbers3", "numbers4", "refs"].map((reference) => ({ reference, levels: [{ level: 0,
      format: d.LevelFormat.DECIMAL, text: reference === "refs" ? "[%1]" : "%1.", alignment: d.AlignmentType.LEFT,
      style: { paragraph: { indent: reference === "refs" ? { left: 640, hanging: 640 } : { left: 540, hanging: 400 } } } }] })),
  ],
};

module.exports = { d, render, styles, numbering, TEXT_W, MARGIN, PAGE_W, runs };
