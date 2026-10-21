"""Save the printable summary as a PDF using Qt's own renderer (no extra software)."""
from PySide6.QtCore import QMarginsF
from PySide6.QtGui import QFont, QPageLayout, QPageSize, QPdfWriter, QTextDocument


def export_pdf(html: str, path: str, letter: bool = True) -> None:
    writer = QPdfWriter(path)
    writer.setTitle("XML-ray summary")
    writer.setCreator("XML-ray")
    writer.setPageSize(QPageSize(QPageSize.Letter if letter else QPageSize.A4))
    writer.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout.Millimeter)
    doc = QTextDocument()
    doc.setDefaultFont(QFont("Segoe UI", 9))
    doc.setHtml(html)
    doc.print_(writer)
