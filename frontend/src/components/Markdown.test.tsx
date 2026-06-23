import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { Markdown } from "./Markdown";

const html = (md: string) => renderToStaticMarkup(<Markdown>{md}</Markdown>);

describe("Markdown", () => {
  it("renders inline emphasis", () => {
    expect(html("**bold**")).toContain("<strong>bold</strong>");
    expect(html("_italic_")).toContain("<em>italic</em>");
    expect(html("*italic*")).toContain("<em>italic</em>");
    expect(html("~~gone~~")).toContain("<del>gone</del>");
  });

  it("renders inline and fenced code literally", () => {
    expect(html("use `npm install`")).toContain(
      '<code class="md-code">npm install</code>',
    );
    const block = html("```js\nconst x = 1;\n```");
    expect(block).toContain('<pre class="md-pre"><code>');
    expect(block).toContain("const x = 1;");
    // Markdown inside a code span is not re-parsed.
    expect(html("`**not bold**`")).not.toContain("<strong>");
  });

  it("renders headings, paragraphs, and lists", () => {
    expect(html("# Title")).toContain('<h1 class="md-h">Title</h1>');
    expect(html("### Deep")).toContain('<h3 class="md-h">Deep</h3>');
    expect(html("first\n\nsecond")).toBe(
      '<p class="md-p">first</p><p class="md-p">second</p>',
    );
    expect(html("- a\n- b")).toContain(
      '<ul class="md-list"><li>a</li><li>b</li></ul>',
    );
    expect(html("1. one\n2. two")).toContain(
      '<ol class="md-list"><li>one</li><li>two</li></ol>',
    );
  });

  it("renders blockquotes with nested inline markup", () => {
    expect(html("> be **brave**")).toContain(
      '<blockquote class="md-quote"><p class="md-p">be <strong>brave</strong></p></blockquote>',
    );
  });

  it("links only safe schemes, and renders others as text", () => {
    expect(html("[site](https://example.com)")).toContain(
      '<a href="https://example.com" target="_blank" rel="noopener noreferrer">site</a>',
    );
    const xss = html("[click](javascript:alert(1))");
    expect(xss).not.toContain("<a ");
    expect(xss).toContain("[click](javascript:alert(1))");
  });

  it("escapes raw HTML rather than injecting it", () => {
    const out = html("<img src=x onerror=alert(1)>");
    expect(out).not.toContain("<img");
    expect(out).toContain("&lt;img");
  });

  it("never throws on empty or malformed input", () => {
    expect(html("")).toBe("");
    expect(() => html("**unterminated")).not.toThrow();
    expect(html("**unterminated")).toContain("**unterminated");
  });
});
