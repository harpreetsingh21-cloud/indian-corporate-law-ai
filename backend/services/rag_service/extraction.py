import logging
import re
import unicodedata
from collections import Counter
from pathlib import Path
import pdfplumber
import PyPDF2
import docx as python_docx
from docx.table import Table
from docx.text.paragraph import Paragraph

logger = logging.getLogger(__name__)

_PAGE_NUMBER = re.compile(r"^\s*[-–—]?\s*(page\s*)?\d{1,4}(\s*(of|/)\s*\d{1,4})?\s*[-–—]?\s*$", re.IGNORECASE)
_LIST_START = re.compile(r"^(\d+(\.\d+)*[.)]?\s|[a-z][.)]\s|\([a-z0-9ivx]+\)\s|[-•*▪●◦]\s)", re.IGNORECASE)
_HEADING = re.compile(r"^[A-Z0-9][A-Z0-9 ,&/()'\-.:]{2,}$")
_SENTENCE_END = re.compile(r"[.:;!?]$")


def _clean_chars(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\f", "\n")
    text = text.replace(" ", " ").replace("\t", " ")
    text = text.replace("‘", "'").replace("’", "'").replace("“", '"').replace("”", '"')
    return text


def _is_heading(line: str) -> bool:
    return bool(_HEADING.match(line)) and any(c.isalpha() for c in line)


def _strip_repeated_page_lines(pages: list[str]) -> list[str]:
    pages = [_clean_chars(p) for p in pages]
    if len(pages) < 3:
        return pages
    counts = Counter()
    for page in pages:
        lines = [l.strip() for l in page.split("\n") if l.strip()]
        edges = set(lines[:2] + lines[-2:])
        counts.update(re.sub(r"\d+", "#", l) for l in edges)
    limit = max(3, len(pages) // 2)
    repeated = {l for l, n in counts.items() if n >= limit}
    if not repeated:
        return pages
    cleaned = []
    for page in pages:
        lines = [l for l in page.split("\n") if l.strip()]
        keep = []
        for i, line in enumerate(lines):
            at_edge = i < 2 or i >= len(lines) - 2
            if at_edge and len(line.strip()) <= 120 and re.sub(r"\d+", "#", line.strip()) in repeated:
                continue
            keep.append(line)
        cleaned.append("\n".join(keep))
    return cleaned


def normalize_text(text: str) -> str:
    text = _clean_chars(text)
    text = re.sub(r"(\w)-\n(\w)", r"\1-\2", text)
    text = re.sub(r"([a-z])\n(\(\d+\))", r"\1 \2", text)
    lines = [re.sub(r"\s+", " ", l).strip() for l in text.split("\n")]
    lines = [l for l in lines if l and not _PAGE_NUMBER.match(l)]

    paragraphs: list[str] = []
    for line in lines:
        if not paragraphs:
            paragraphs.append(line)
            continue
        prev = paragraphs[-1]
        both_headings = _is_heading(prev) and _is_heading(line) and not _LIST_START.match(line) and not _LIST_START.match(prev)
        new_block = not both_headings and (
            _SENTENCE_END.search(prev)
            or _is_heading(prev)
            or _is_heading(line)
            or _LIST_START.match(line)
        )
        if new_block:
            paragraphs.append(line)
        else:
            paragraphs[-1] = f"{prev} {line}"
    return "\n".join(paragraphs).strip()


def _docx_text(filepath: str) -> str:
    doc = python_docx.Document(filepath)
    parts: list[str] = []
    for child in doc.element.body.iterchildren():
        tag = child.tag.rsplit("}", 1)[-1]
        if tag == "p":
            parts.append(Paragraph(child, doc).text)
        elif tag == "tbl":
            for row in Table(child, doc).rows:
                seen, cells = set(), []
                for cell in row.cells:
                    if id(cell._tc) in seen:
                        continue
                    seen.add(id(cell._tc))
                    value = " ".join(cell.text.split())
                    if value:
                        cells.append(value)
                if cells:
                    parts.append(" ".join(cells))
    return "\n".join(parts)


def extract_text(filepath: str, filename: str) -> str:
    """
    Extract plain text from PDF, DOCX, or TXT.
    """
    ext = Path(filename).suffix.lower()

    if ext == ".pdf":
        try:
            with pdfplumber.open(filepath) as pdf:
                pages = [p.extract_text() or "" for p in pdf.pages]
            text = normalize_text("\n".join(_strip_repeated_page_lines(pages)))
            if text.strip():
                logger.info(f"📄  pdfplumber: {len(text):,} chars from {len(pages)} pages")
                return text
        except Exception as e:
            logger.warning(f"⚠️   pdfplumber failed ({e}), trying PyPDF2 …")

        with open(filepath, "rb") as fh:
            reader = PyPDF2.PdfReader(fh)
            pages = [p.extract_text() or "" for p in reader.pages]
        text = normalize_text("\n".join(_strip_repeated_page_lines(pages)))
        logger.info(f"📄  PyPDF2: {len(text):,} chars")
        return text

    elif ext == ".docx":
        text = normalize_text(_docx_text(filepath))
        logger.info(f"📄  DOCX: {len(text):,} chars")
        return text

    elif ext == ".txt":
        with open(filepath, "r", encoding="utf-8", errors="replace") as fh:
            text = normalize_text(fh.read())
        logger.info(f"📄  TXT: {len(text):,} chars")
        return text

    raise ValueError(f"Unsupported file type: {ext}")