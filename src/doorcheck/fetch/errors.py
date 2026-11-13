from doorcheck.errors import DoorcheckError
from doorcheck.findings import param


class FetchError(DoorcheckError):
    """Something to scan couldn't be fetched or isn't what an install would use."""

    key = "problem.fetch_failed"


class UnsafeArchive(FetchError):
    """An archive that is malformed, too large, or tries to write outside its folder."""

    key = "problem.unsafe_archive"


class ArchiveLink(UnsafeArchive):
    """A symbolic link where Doorcheck must read or unpack files."""

    key = "problem.archive_link"

    def __init__(self, message: str, path: str) -> None:
        super().__init__(message, params={"path": param(path)})
