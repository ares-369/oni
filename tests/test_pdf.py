"""Tests for the zero-dependency Markdown-to-PDF exporter."""
from oniops.pdf import markdown_to_pdf


def test_markdown_to_pdf_structure():
    md = (
        "# Executive Summary\n\n"
        "Target **10.0.0.150** was assessed.\n\n"
        "## Findings\n"
        "- Open port `80/tcp` running HTTP\n"
        "- Auth challenge verified\n\n"
        "```\n"
        "HTTP/1.1 200 OK\n"
        "Server: nginx\n"
        "```\n"
    )
    pdf = markdown_to_pdf(md, title="ONIOPS Test Report")
    assert pdf.startswith(b"%PDF-1.4")
    assert pdf.endswith(b"%%EOF\n")
    assert b"ONIOPS Test Report" in pdf
    assert b"Executive Summary" in pdf
    assert b"/Count 1" in pdf


def test_markdown_to_pdf_multipage_and_escaping():
    long_md = "\n".join(f"- Finding #{i}: parentheses (test) & backslash \\ check — dash" for i in range(120))
    pdf = markdown_to_pdf(long_md, title="Multi-page Report")
    assert pdf.startswith(b"%PDF-1.4")
    assert b"/Count 2" in pdf or b"/Count 3" in pdf
    assert b"\\(test\\)" in pdf
