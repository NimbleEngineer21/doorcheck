from doorcheck.errors import DoorcheckError


class FetchError(DoorcheckError):
    """Something to scan couldn't be fetched or isn't what an install would use."""

    key = "problem.fetch_failed"


class UnsafeArchive(FetchError):
    """An archive that is malformed, too large, or tries to write outside its folder."""

    key = "problem.unsafe_archive"
