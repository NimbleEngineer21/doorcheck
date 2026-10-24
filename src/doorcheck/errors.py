"""Doorcheck's own errors.

Each error carries a catalog key, so every surface can explain it in the
reader's language; the English message is for logs. They don't subclass
ValueError, so catching one never swallows a bug elsewhere.
"""


class DoorcheckError(Exception):
    key = "problem.unexpected"

    def __init__(self, message: str, key: str | None = None) -> None:
        super().__init__(message)
        if key is not None:
            self.key = key
