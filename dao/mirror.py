"""Every page as markdown, and /llms.txt.

Append `.md` to any page path (the home page is `/index.md`), or ask with `Accept: text/markdown`, and the
HTML the browser would get is converted on the way out: bar, footer, scripts, forms and the signer box are
dropped; headings, prose, tables, lists and links are kept. One converter, so every page present and
future has a markdown twin without a second template. `/llms.txt` is the reading list for agents.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import quote

from bs4 import BeautifulSoup
from markdownify import MarkdownConverter

from .config import Config

SKIP_PREFIXES = ("/v1", "/static")
DROP = ("script", "style", "template", "form", "button", "input", "textarea", "select", "noscript")
DROP_CLASSES = ("keybox",)


# ---- paths ------------------------------------------------------------------------------------------

def md_target(path: str) -> str | None:
    """The page a `.md` path mirrors, or None when the path is not a markdown request."""
    if not path.endswith(".md") or path.startswith(SKIP_PREFIXES):
        return None
    page = path[:-3]
    return "/" if page in ("", "/index") else page


def site_path(path: str) -> str:
    """A request path as a link to this site: percent-encoded, and beginning with exactly one `/`.

    The path a request arrives on is the requester's text, decoded. Written back into a page as it came,
    `//host/x` is a link to another site (and so is `/\\host/x`, which browsers read the same way), and a
    `>` or a newline ends whatever it was written inside. Everything that puts the request path into a page
    or a twin takes it from here (XE-7815, XE-7861)."""
    return "/" + quote(path, safe="/").lstrip("/")


def md_path(page: str) -> str:
    """The `.md` twin of a page path: always a path on this site."""
    p = site_path(page)
    return "/index.md" if p == "/" else p.rstrip("/") + ".md"


def wants_markdown(accept: str) -> bool:
    """True for a client that asked for markdown and did not also ask for HTML (browsers always do)."""
    a = (accept or "").lower()
    return "text/markdown" in a and "text/html" not in a


# ---- conversion -------------------------------------------------------------------------------------

class _Converter(MarkdownConverter):
    """Text is text. Everything the HTML page showed as characters stays characters in the twin: markdown
    punctuation, `<`, `&` and `[` in user-written text are backslash-escaped, and a preformatted block is
    fenced with more backticks than any run inside it, so a proposal body, vote reason or inbox message
    cannot add links, images, headings or raw HTML to the page under the DAO's name (XE-0507)."""

    def convert_pre(self, el, text, parent_tags):
        if not text:
            return ""
        longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
        fence = "`" * max(3, longest + 1)
        return f"\n\n{fence}\n{text.strip(chr(10))}\n{fence}\n\n"


_converter = _Converter(
    heading_style="ATX", bullets="-", escape_underscores=True, escape_asterisks=True, escape_misc=True,
    table_infer_header=True,
)


def html_to_markdown(html: str, canonical: str) -> str:
    """The `<main>` of a rendered page as markdown, with a line saying where it came from."""
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else ""
    main = soup.find("main") or soup.body or soup
    for tag in main.find_all(DROP):
        tag.decompose()
    for cls in DROP_CLASSES:
        for tag in main.find_all(class_=cls):
            tag.decompose()
    # diagrams: keep what they say, not how they draw it
    for svg in main.find_all("svg"):
        label = svg.get("aria-label")
        rep = soup.new_tag("p")
        if label:
            em = soup.new_tag("em")
            em.string = label
            rep.append(em)
        svg.replace_with(rep)
    # <details><summary>: the question as a bold line, the answer below it
    for summ in main.find_all("summary"):
        p = soup.new_tag("p")
        strong = soup.new_tag("strong")
        strong.string = summ.get_text(" ", strip=True)
        p.append(strong)
        summ.replace_with(p)
    # relative links become absolute so the file reads the same anywhere
    root = canonical.split("/", 3)
    origin = "/".join(root[:3]) if len(root) >= 3 else ""
    for a in main.find_all("a", href=True):
        href = a["href"]
        if href.startswith("/") and not href.startswith("//"):
            a["href"] = origin + href
    body = _converter.convert_soup(main)
    body = re.sub(r"[ \t]+\n", "\n", body)
    body = re.sub(r"\n{3,}", "\n\n", body).strip()
    # the address is partly the requester's text; inside the autolink it is one URL and nothing else
    link = re.sub(r"[^!#-;=?-~]", lambda m: quote(m.group()), canonical)
    head = f"*Markdown view of <{link}>. The page is the record; this is the same page for reading.*"
    if title:
        # the title is page-controlled text; it must not be able to close the comment it sits in
        head = f"<!-- {title.replace('--', '- -').replace('>', '›')} -->\n{head}"
    return f"{head}\n\n{body}\n"


# ---- middleware -------------------------------------------------------------------------------------

class MarkdownMirror:
    """Pure ASGI. Rewrites `/x.md` to `/x`, lets the app render, converts text/html answers to markdown."""

    def __init__(self, app, base_url: str | Callable[[], str] = ""):
        self.app = app
        self._base_url = base_url

    @property
    def base_url(self) -> str:
        b = self._base_url() if callable(self._base_url) else self._base_url
        return (b or "").rstrip("/")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") != "GET":   # a HEAD arrives here as a GET (main.HeadAsGet)
            return await self.app(scope, receive, send)
        path = scope["path"]
        target = md_target(path)
        if target is None:
            if path.startswith(SKIP_PREFIXES):
                return await self.app(scope, receive, send)
            accept = next((v.decode("latin-1") for k, v in scope.get("headers", []) if k == b"accept"), "")
            if not wants_markdown(accept):
                return await self.app(scope, receive, send)
            target = path
        scope = {**scope, "path": target, "raw_path": target.encode()}

        status = 200
        headers: list[tuple[bytes, bytes]] = []
        body = bytearray()

        async def capture(message):
            nonlocal status, headers
            if message["type"] == "http.response.start":
                status = message["status"]
                headers = list(message.get("headers", []))
            elif message["type"] == "http.response.body":
                body.extend(message.get("body", b""))

        await self.app(scope, receive, capture)

        ctype = next((v for k, v in headers if k == b"content-type"), b"").decode("latin-1")
        if not ctype.startswith("text/html"):
            # not a page (a redirect, say): hand through what came back
            await send({"type": "http.response.start", "status": status, "headers": headers})
            await send({"type": "http.response.body", "body": bytes(body)})
            return

        # The address is the configured one. The Host header is the requester's and is not consulted: without
        # a configured base the twin says the path and leaves the page's links relative.
        out = html_to_markdown(body.decode("utf-8", "replace"), self.base_url + site_path(target)).encode("utf-8")
        keep = [(k, v) for k, v in headers if k not in (b"content-type", b"content-length", b"vary")]
        keep += [(b"content-type", b"text/markdown; charset=utf-8"), (b"content-length", str(len(out)).encode()),
                 (b"vary", b"Accept")]
        await send({"type": "http.response.start", "status": status, "headers": keep})
        await send({"type": "http.response.body", "body": out})


# ---- llms.txt ---------------------------------------------------------------------------------------

def public_mode(mode: str) -> str:
    """The register's word for the harness mode. The config value `members-direct` carries a word the public
    copy does not use (kill_list.yaml); the pages and llms.txt say `direct` (XE-0650)."""
    return "direct" if mode == "members-direct" else mode


def build_llms_txt(cfg: Config, base_url: str, network_id: str, mode: str) -> str:
    """The reading list, per llmstxt.org: an H1, a blockquote summary, then sections of links."""
    b = base_url.rstrip("/")
    copy = cfg.copy_public

    def link(path: str, text: str, note: str = "") -> str:
        tail = f": {note}" if note else ""
        return f"- [{text}]({b}{path}){tail}"

    out: list[str] = [
        f"# {copy.get('site_name', 'XE DAO')}",
        "",
        f"> {copy.get('headline', '')} {copy.get('sub', '')}".strip(),
        "",
        f"Network `{network_id}`, mode `{public_mode(mode)}`. Every page here is also markdown: append `.md` to its path "
        "(the home page is `/index.md`), or request it with `Accept: text/markdown`. The JSON API lives under "
        "`/v1`; `GET /v1` lists it. Writes are signed requests, never forms.",
        "",
        "## Start here",
        link("/index.md", "Home", "what this is, what is open now, the latest log entries"),
        link("/how-it-works.md", "How it works", "the order the seats work in, how they exchange records, where it stops"),
        link("/charter.md", "Charter", "the rules the DAO runs under, with its hash"),
        link("/seats.md", "Seats", "every seat, its scopes, status and instructions"),
        "",
        "## Seats",
    ]
    for a in cfg.agent_seats:
        out.append(link(f"/seats/{a.slug}.md", a.role, a.summary.strip().split("\n")[0] if a.summary else ""))
    for h in cfg.human_seats:
        out.append(link(f"/seats/{h.slug}.md", h.name, h.role))
    out += [
        "",
        "## Governance",
        link("/proposals.md", "Proposals", "open and past proposals with their votes"),
        link("/decisions.md", "Decisions", "closed votes and the written answer to each"),
        link("/decisions/example.md", "Example decision record", "the shape every record takes"),
        link("/inbox.md", "Inbox", "messages sent to the DAO account, acknowledged and answered in public"),
        link("/log.md", "Log", "the hash-chained public log of everything the harness does"),
        link("/live", "Live", "the log as it happens; `/v1/events` is the stream itself"),
        link("/records.md", "Records", "resolutions, keyset, registry, anchors and pauses: the formal register"),
        "",
        "## API",
        link("/v1", "Manifest", "JSON index of every endpoint"),
        link("/v1/openapi.json", "OpenAPI", "the schema"),
        link("/v1/charter", "Charter JSON", "text and hash"),
        link("/v1/seats", "Seats JSON", "seats, scopes, prompt hashes and the scope glossary"),
        link("/v1/log/head", "Log head", "the current tip of the log"),
        link("/v1/log/verify", "Log verify", "walks the chain and reports"),
        link("/v1/events", "Event stream", "server-sent events, one `entry` per log entry"),
        "",
        "## Optional",
        "- [Source](https://github.com/xeprotocol/dao): GPL-3.0-or-later; `docs/BRIEF.md` is the design",
        "- [xe.network](https://xe.network): the network this governs",
        "",
    ]
    return "\n".join(out)
