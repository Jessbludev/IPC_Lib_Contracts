#!/usr/bin/env python3
"""
Genera `docs/site/` a partir del Markdown fuente.

Determinista: la misma entrada produce siempre la misma salida. Sin CDN, sin
JavaScript, sin dependencias externas. Ejecutable con la stdlib de Python 3.9+.

    python3 tools/render_docs.py

Por qué existe como script y no como proceso manual:

- Los slugs se generan aquí y sólo aquí. La versión previa transliteraba
  `ó` como `n` en vez de `o`, lo que producía nombres de archivo y anclas como
  `implementaci-n.html#implementaci-n-de-blake3`. Dos fuentes de verdad para
  los identificadores, y ninguna correcta.
- Un sitio generado por un comando que no está en el repositorio no es
  reproducible: nadie puede regenerarlo ni comprobar que el HTML publicado
  corresponde al Markdown.

Salida: `docs/site/*.html` más `index.html` como raíz.
"""

from __future__ import annotations

import html
import re
import sys
import unicodedata
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "docs" / "site"

# fuente Markdown -> nombre de salida. El nombre se declara explícitamente en
# vez de derivarse del título: así el slug vive en un solo sitio y no depende
# de cómo se translitere un acento.
PAGES = [
    ("README.md", "readme.html", "README", ("root",)),
    ("DSL.md", "dsl.html", "DSL", ("root",)),
    ("docs/ADR.md", "adr.html", "ADR", ("root",)),
    ("docs/CONTRACTS.md", "contratos.html", "Contratos", ("root",)),
    ("docs/PROTOCOL.md", "protocolo.html", "Protocolo", ("root",)),
    ("docs/SECURITY.md", "seguridad.html", "Seguridad", ("root",)),
    ("docs/wiki/README.md", "wiki.html", "Wiki", ("root",)),
    ("docs/wiki/get-started.md", "get-started.html", "Primeros pasos", ("root",)),
    ("docs/wiki/usage.md", "usage.html", "Uso", ("root",)),
    ("docs/wiki/implementation.md", "implementation.html", "Implementación", ("root",)),
    ("docs/wiki/integration.md", "integration.html", "Integración", ("root",)),
    ("docs/wiki/roadmap.md", "roadmap.html", "Hoja de ruta", ("root",)),
    ("docs/wiki/snapshots.md", "snapshots.html", "Snapshots", ("root",)),
    ("docs/wiki/security.md", "security-wiki.html", "Seguridad (Wiki)", ("root",)),
]

VERSION = "2.1.2"


# --------------------------------------------------------------------------
# Slugs
# --------------------------------------------------------------------------

def strip_accents(text: str) -> str:
    """Quitar diacríticos conservando la letra base.

    `ó` -> `o`, `í` -> `i`, `ñ` -> `n`. NFD separa la letra de su acento, así
    que basta con descartar los marcas no ASCII.
    """
    decomposed = unicodedata.normalize("NFD", text)
    return "".join(c for c in decomposed if not unicodedata.combining(c))


def slugify(text: str) -> str:
    """Convertir un título en un identificador estable para anclas.

    Es determinista y no colisiona con los nombres de página. El texto se pasa
    por `strip_accents` ANTES de filtrar, que es donde la versión anterior se
    equivocaba.
    """
    text = strip_accents(text).lower()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text.strip("-")


# --------------------------------------------------------------------------
# Markdown -> HTML
# --------------------------------------------------------------------------

def inline(text: str) -> str:
    """Formateo inline. El orden importa: primero el código, para que un
    `**` dentro de un fragmento de código no se interprete como énfasis."""
    out = []
    for i, part in enumerate(re.split(r"(`[^`]+`)", text)):
        if i % 2 == 1:
            out.append(f"<code>{html.escape(part[1:-1])}</code>")
            continue
        part = html.escape(part)
        part = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', part)
        part = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", part)
        part = re.sub(r"(?<![\*\w])\*([^*]+)\*(?!\*)", r"<em>\1</em>", part)
        out.append(part)
    return "".join(out)


def render_blocks(lines: list[str]) -> list[str]:
    """Convertir líneas de Markdown ya divididas en bloques HTML."""
    out: list[str] = []
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i]
        stripped = line.strip()

        if not stripped:
            i += 1
            continue

        # Bloque de código con lenguaje
        if stripped.startswith("```"):
            lang = stripped[3:].strip()
            i += 1
            body = []
            while i < n and not lines[i].strip().startswith("```"):
                body.append(lines[i])
                i += 1
            i += 1  # cerrar el bloque
            cls = f' class="lang-{html.escape(lang)}"' if lang else ""
            out.append(f"<pre><code{cls}>{html.escape(chr(10).join(body))}</code></pre>")
            continue

        # Tabla
        if stripped.startswith("|") and i + 1 < n and re.match(
            r"^\|[\s:|-]+\|$", lines[i + 1].strip()
        ):
            header = [c.strip() for c in stripped.strip("|").split("|")]
            i += 2
            rows = []
            while i < n and lines[i].strip().startswith("|"):
                rows.append([c.strip() for c in lines[i].strip().strip("|").split("|")])
                i += 1
            out.append("<table><thead><tr>")
            for cell in header:
                out.append(f"<th>{inline(cell)}</th>")
            out.append("</tr></thead><tbody>")
            for row in rows:
                out.append("<tr>")
                for cell in row:
                    out.append(f"<td>{inline(cell)}</td>")
                out.append("</tr>")
            out.append("</tbody></table>")
            continue

        # Encabezado
        m = re.match(r"^(#{1,6})\s+(.*)$", stripped)
        if m:
            level = len(m.group(1))
            text = m.group(2).strip()
            anchor = slugify(re.sub(r"[`*]", "", text))
            out.append(f'<h{level} id="{anchor}">{inline(text)}</h{level}>')
            i += 1
            continue

        # Separador
        if re.match(r"^([-*_])\1{2,}$", stripped):
            out.append("<hr>")
            i += 1
            continue

        # Cita
        if stripped.startswith(">"):
            body = []
            while i < n and lines[i].strip().startswith(">"):
                body.append(lines[i].strip().lstrip(">").strip())
                i += 1
            out.append(f"<blockquote><p>{inline(' '.join(body))}</p></blockquote>")
            continue

        # Listas
        bullet = re.match(r"^[-*]\s+", stripped)
        numbered = re.match(r"^\d+\.\s+", stripped)
        if bullet or numbered:
            tag = "ul" if bullet else "ol"
            items = []
            while i < n:
                cur = lines[i].strip()
                m2 = re.match(r"^[-*]\s+(.*)$", cur) or re.match(r"^\d+\.\s+(.*)$", cur)
                if not m2:
                    # continuación indentada de un ítem previo
                    if cur and items and lines[i].startswith(("   ", "\t")):
                        items[-1] += " " + cur
                        i += 1
                        continue
                    break
                items.append(m2.group(1))
                i += 1
            out.append(f"<{tag}>" + "".join(f"<li>{inline(it)}</li>" for it in items) + f"</{tag}>")
            continue

        # Párrafo: consumir líneas hasta el siguiente bloque
        para = []
        while i < n:
            cur = lines[i]
            s = cur.strip()
            if (
                not s
                or s.startswith(("#", "```", "|", ">", "- ", "* "))
                or re.match(r"^\d+\.\s", s)
                or re.match(r"^([-*_])\1{2,}$", s)
            ):
                break
            para.append(s)
            i += 1
        if para:
            out.append(f"<p>{inline(' '.join(para))}</p>")

    return out


# --------------------------------------------------------------------------
# Rewriting de enlaces .md -> .html
# --------------------------------------------------------------------------

# Indice: nombre de archivo Markdown -> nombre de HTML de salida
TARGETS = {src: out for src, out, _, _ in PAGES}

# Índice por nombre de archivo pelado. Sin esto, un enlace `adr.md` escrito
# desde `docs/wiki/implementation.md` no resuelve: ahí el fichero real se
# llama `docs/ADR.md`.
BY_BASENAME: dict[str, str] = {}
for _src, _out, _label, _ in PAGES:
    BY_BASENAME[_src.rsplit("/", 1)[-1].lower()] = _out
# `README.md` es ambiguo entre la raíz y la wiki: gana la portada, que es a
# donde casi siempre se quiere ir.
BY_BASENAME["readme.md"] = "readme.html"


def rewrite_links(text: str) -> str:
    """Apuntar los enlaces entre documentos al HTML generado.

    `docs/wiki/usage.md` y `usage.md` tienen que resolver ambos a
    `usage.html`, aunque el segundo no exista en disco: la wiki se publique
    como HTML plano, donde los enlaces relativos a `.md` no llevan a ninguna
    parte.
    """

    def fix(match: re.Match) -> str:
        label, href = match.group(1), match.group(2)
        base = href.split("#", 1)[0]
        if not base.endswith(".md"):
            return match.group(0)
        out = BY_BASENAME.get(base.rsplit("/", 1)[-1].lower())
        if out is None:
            return match.group(0)
        return f"[{label}]({out})"

    return re.sub(r"\[([^\]]+)\]\(([^)]+\.md(?:#[^)]*)?)\)", fix, text)


# --------------------------------------------------------------------------
# Plantillas
# --------------------------------------------------------------------------

CSS = """
:root{color-scheme:dark;--bg:#0b1020;--panel:#111827;--text:#e5e7eb;
--muted:#94a3b8;--accent:#8b9cff;--line:#263247;--code:#090d16}
*{box-sizing:border-box}
body{margin:0;background:linear-gradient(135deg,#0b1020,#101827);color:var(--text);
font:15px/1.7 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
.layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
.side{background:var(--panel);border-right:1px solid var(--line);padding:24px 16px;
position:sticky;top:0;height:100vh;overflow-y:auto}
.brand{font-weight:700;font-size:16px;letter-spacing:.2px}
.version{color:var(--muted);font-size:12px;margin:4px 0 20px}
.side a{display:block;color:var(--muted);text-decoration:none;padding:6px 10px;
border-radius:6px;font-size:14px}
.side a:hover{background:#1b2436;color:var(--text)}
.side a.on{background:#1b2436;color:var(--accent);font-weight:600}
.main{padding:40px 48px;max-width:960px}
h1{font-size:30px;margin:0 0 20px;letter-spacing:-.4px}
h2{font-size:22px;margin:36px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
h3{font-size:17px;margin:26px 0 10px}
a{color:var(--accent)}
p,li{color:#d6dbe6}
ul,ol{padding-left:22px}
code{background:var(--code);border:1px solid var(--line);border-radius:4px;
padding:1px 5px;font-size:13px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace}
pre{background:var(--code);border:1px solid var(--line);border-radius:8px;
padding:14px 16px;overflow-x:auto}
pre code{background:none;border:none;padding:0;font-size:13px;line-height:1.6}
table{border-collapse:collapse;width:100%;margin:16px 0;font-size:14px}
th,td{border:1px solid var(--line);padding:9px 12px;text-align:left;vertical-align:top}
th{background:#1b2436;color:var(--text);font-weight:600}
blockquote{margin:16px 0;padding:10px 16px;border-left:3px solid var(--accent);
background:#131c2e;color:var(--muted)}
hr{border:none;border-top:1px solid var(--line);margin:28px 0}
footer{color:var(--muted);font-size:12px;margin-top:48px;padding-top:16px;
border-top:1px solid var(--line)}
@media(max-width:820px){.layout{grid-template-columns:1fr}
.side{position:static;height:auto;border-right:none;border-bottom:1px solid var(--line)}
.main{padding:24px 18px}}
"""


def nav(current: str) -> str:
    items = []
    for _, out, label, _ in PAGES:
        cls = ' class="on"' if out == current else ""
        items.append(f'<a href="{out}"{cls}>{html.escape(label)}</a>')
    return "".join(items)


def page(title: str, current: str, body: str) -> str:
    return (
        "<!doctype html>\n"
        f'<html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        f"<title>{html.escape(title)}</title>"
        '<link rel="stylesheet" href="style.css"></head><body>'
        '<div class="layout">'
        f'<aside class="side"><div class="brand">IPC Lib Contracts</div>'
        f'<div class="version">{VERSION} — pre-release</div>{nav(current)}</aside>'
        f'<main class="main">{body}'
        f'<footer>IPC Lib Contracts · {VERSION} pre-release · generado por '
        "tools/render_docs.py</footer></main></div></body></html>\n"
    )


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    generated: list[str] = []
    missing: list[str] = []

    for src, out_name, label, _ in PAGES:
        path = ROOT / src
        if not path.exists():
            missing.append(src)
            continue
        text = path.read_text(encoding="utf-8")
        text = rewrite_links(text)
        body = "\n".join(render_blocks(text.splitlines()))
        title = f"{label} — IPC Lib Contracts"
        (OUT / out_name).write_text(page(title, out_name, body), encoding="utf-8")
        generated.append(out_name)

    # Portada. Es la primera página que ve alguien que abre docs/site/ en el
    # navegador, así que orienta en lugar de repetir el README entero.
    index_body = f"""
<h1>IPC Contract System</h1>
<p>Sistema de contratos binarios canónicos con seguridad criptográfica real
para comunicación inter-procesos, sin FFI ni NDK.</p>

<h2 id="estado">Estado</h2>
<p><strong>{VERSION} — pre-release.</strong> La capa de contrato y
criptografía está completa y verificada con conformidad cruzada entre Rust,
C++ y Kotlin. El transporte todavía no está implementado.</p>
<p>Antes de integrar, lee la <a href="roadmap.html">hoja de ruta</a>: enumera
con precisión qué funciona y qué no.</p>

<h2 id="empezar">Empezar</h2>
<ul>
<li><a href="get-started.html">Primeros pasos</a> — requisitos, instalación y
primer contrato</li>
<li><a href="usage.html">Uso</a> — referencia de la CLI y de las APIs</li>
<li><a href="integration.html">Integración</a> — insertarlo en tu aplicación</li>
</ul>

<h2 id="referencia">Referencia</h2>
<ul>
<li><a href="implementation.html">Implementación</a> — formato CBC1, frames,
criptografía</li>
<li><a href="dsl.html">DSL</a> — sintaxis del lenguaje de contratos</li>
<li><a href="contratos.html">Contratos</a> — formato binario</li>
<li><a href="protocolo.html">Protocolo</a> — handshake y framing</li>
<li><a href="security-wiki.html">Seguridad</a> — políticas y modelo de amenaza</li>
<li><a href="adr.html">ADR</a> — decisiones de arquitectura</li>
</ul>

<h2 id="verificar">Verificar</h2>
<p>El repositorio incluye un runner de nueve gates que compila y prueba los
tres lenguajes:</p>
<pre><code>./run_all_tests.sh</code></pre>
<p>Los tests de conformidad fallan si algún binding diverge de la
referencia en Rust. Eso no es un problema de estilo: significa que un
componente acepta algo que otro rechaza.</p>
"""
    (OUT / "index.html").write_text(
        page("Documentación — IPC Lib Contracts", "index.html", index_body),
        encoding="utf-8",
    )
    generated.append("index.html")

    (OUT / "style.css").write_text(CSS, encoding="utf-8")

    print(f"{len(generated)} páginas generadas en docs/site/")
    if missing:
        print("FALTAN fuentes:")
        for m in missing:
            print(f"  {m}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
