import { createElement, type ReactNode } from "react";

/**
 * A tiny, dependency-free Markdown renderer for the enclave's chat replies.
 *
 * It deliberately covers only the common subset a chat model emits — paragraphs,
 * headings, ordered/unordered lists, blockquotes, fenced + inline code, bold,
 * italic, strikethrough, and links. Anything it doesn't recognise is rendered as
 * literal text, so it degrades gracefully and never throws.
 *
 * It builds a React element tree and never uses `dangerouslySetInnerHTML`, so
 * model output cannot inject HTML. Link hrefs are restricted to http(s)/mailto;
 * any other scheme is rendered as plain text. Keeping our own ~120-line renderer
 * (vs. pulling in remark/rehype) is in keeping with the project's small,
 * auditable dependency surface.
 */
export function Markdown({ children }: { children: string }) {
  return <>{parseBlocks(children)}</>;
}

const SAFE_HREF = /^(https?:|mailto:)/i;

function isBlockStart(line: string): boolean {
  return (
    /^```/.test(line) ||
    /^#{1,6}\s+/.test(line) ||
    /^>\s?/.test(line) ||
    /^\s*[-*+]\s+/.test(line) ||
    /^\s*\d+\.\s+/.test(line)
  );
}

function parseBlocks(src: string): ReactNode[] {
  const lines = src.replace(/\r\n/g, "\n").split("\n");
  const blocks: ReactNode[] = [];
  let i = 0;
  let key = 0;

  while (i < lines.length) {
    const line = lines[i];

    // Blank line: skip (block separation is handled per-block below).
    if (line.trim() === "") {
      i++;
      continue;
    }

    // Fenced code block: ```lang … ```
    const fence = /^```(\w*)\s*$/.exec(line);
    if (fence) {
      const code: string[] = [];
      i++;
      while (i < lines.length && !/^```\s*$/.test(lines[i])) {
        code.push(lines[i]);
        i++;
      }
      i++; // consume the closing fence (or step past EOF)
      blocks.push(
        <pre key={key++} className="md-pre">
          <code>{code.join("\n")}</code>
        </pre>,
      );
      continue;
    }

    // ATX heading: #, ##, … ######
    const heading = /^(#{1,6})\s+(.*)$/.exec(line);
    if (heading) {
      const level = heading[1].length;
      blocks.push(
        createElement(
          `h${level}`,
          { key: key++, className: "md-h" },
          parseInline(heading[2]),
        ),
      );
      i++;
      continue;
    }

    // Blockquote: consecutive lines starting with ">"
    if (/^>\s?/.test(line)) {
      const quoted: string[] = [];
      while (i < lines.length && /^>\s?/.test(lines[i])) {
        quoted.push(lines[i].replace(/^>\s?/, ""));
        i++;
      }
      blocks.push(
        <blockquote key={key++} className="md-quote">
          {parseBlocks(quoted.join("\n"))}
        </blockquote>,
      );
      continue;
    }

    // Unordered list
    if (/^\s*[-*+]\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*[-*+]\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*[-*+]\s+/, ""));
        i++;
      }
      blocks.push(
        <ul key={key++} className="md-list">
          {items.map((it, j) => (
            <li key={j}>{parseInline(it)}</li>
          ))}
        </ul>,
      );
      continue;
    }

    // Ordered list
    if (/^\s*\d+\.\s+/.test(line)) {
      const items: string[] = [];
      while (i < lines.length && /^\s*\d+\.\s+/.test(lines[i])) {
        items.push(lines[i].replace(/^\s*\d+\.\s+/, ""));
        i++;
      }
      blocks.push(
        <ol key={key++} className="md-list">
          {items.map((it, j) => (
            <li key={j}>{parseInline(it)}</li>
          ))}
        </ol>,
      );
      continue;
    }

    // Paragraph: gather lines until a blank line or the start of another block.
    const para: string[] = [];
    while (i < lines.length && lines[i].trim() !== "" && !isBlockStart(lines[i])) {
      para.push(lines[i]);
      i++;
    }
    blocks.push(
      <p key={key++} className="md-p">
        {parseInline(para.join("\n"))}
      </p>,
    );
  }

  return blocks;
}

/**
 * Inline span parser. Scans left to right, emitting the earliest recognised
 * token (code → bold → strikethrough → italic → link) and accumulating
 * everything else as plain text. Recurses for nested emphasis.
 */
function parseInline(text: string): ReactNode[] {
  const out: ReactNode[] = [];
  let buf = "";
  let key = 0;
  let i = 0;

  const flush = () => {
    if (buf !== "") {
      out.push(buf);
      buf = "";
    }
  };

  while (i < text.length) {
    const rest = text.slice(i);

    // Inline code: `…` (literal — no inner parsing)
    let m = /^`([^`]+)`/.exec(rest);
    if (m) {
      flush();
      out.push(
        <code key={key++} className="md-code">
          {m[1]}
        </code>,
      );
      i += m[0].length;
      continue;
    }

    // Bold: **…** or __…__
    m = /^(\*\*|__)(\S(?:.*?\S)?)\1/.exec(rest);
    if (m) {
      flush();
      out.push(<strong key={key++}>{parseInline(m[2])}</strong>);
      i += m[0].length;
      continue;
    }

    // Strikethrough: ~~…~~
    m = /^~~(\S(?:.*?\S)?)~~/.exec(rest);
    if (m) {
      flush();
      out.push(<del key={key++}>{parseInline(m[1])}</del>);
      i += m[0].length;
      continue;
    }

    // Italic: *…* or _…_ (no markers inside, no leading/trailing space)
    m = /^(\*|_)(\S(?:[^*_]*\S)?)\1/.exec(rest);
    if (m) {
      flush();
      out.push(<em key={key++}>{parseInline(m[2])}</em>);
      i += m[0].length;
      continue;
    }

    // Link: [text](href) — only http(s)/mailto hrefs become anchors.
    m = /^\[([^\]]+)\]\(([^)\s]+)\)/.exec(rest);
    if (m) {
      flush();
      if (SAFE_HREF.test(m[2])) {
        out.push(
          <a key={key++} href={m[2]} target="_blank" rel="noopener noreferrer">
            {parseInline(m[1])}
          </a>,
        );
      } else {
        out.push(m[0]); // unknown scheme: render the raw markdown literally
      }
      i += m[0].length;
      continue;
    }

    buf += text[i];
    i++;
  }

  flush();
  return out;
}
