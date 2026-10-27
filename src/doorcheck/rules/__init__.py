"""Home Assistant rules; findings and coverage gaps are separate results."""

from doorcheck.rules.file_view import analyze
from doorcheck.rules.scan import Scanned, scan

__all__ = ["Scanned", "analyze", "scan"]
