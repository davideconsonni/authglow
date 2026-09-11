"""Domain-specific exceptions raised by repository implementations.

These are translated by the service layer into ``fastapi.HTTPException``
or absorbed into domain-specific error handling. Generic I/O errors
(``FileNotFoundError``, ``PermissionError``, ``OSError``) propagate as-is
since they are typically operational concerns, not domain logic.

One deliberate exception lives in the read / delete primitives of
``BaseFileRepository``: a *path-shape* ``OSError`` (an illegal filename
character on Windows, an over-long name, a non-directory path component)
is absorbed as "not found", so a caller-supplied id can never turn a
lookup or delete into an unhandled 500. Operational errors
(``PermissionError``, ``EIO``, ...) are **not** path-shape and still
propagate.
"""


class EntityNotFoundError(LookupError):
    """Raised when a repository lookup fails to find the requested entity.

    The service layer should translate this into an appropriate
    ``HTTPException(status_code=404)`` or domain-level "not found"
    handling. The ``entity`` attribute identifies which entity type
    was being looked up.
    """

    def __init__(self, entity: str, identifier: str | object) -> None:
        self.entity = entity
        self.identifier = identifier
        super().__init__(f"{entity} not found: {identifier!r}")


class EntityAlreadyExistsError(ValueError):
    """Raised when a unique constraint is violated on ``create``.

    Common causes: duplicate email index, duplicate API key prefix,
    duplicate federation identity mapping, duplicate role name, etc.
    The service layer should translate this into ``HTTPException(409)``
    or a domain-specific error.
    """

    def __init__(self, entity: str, identifier: str | object) -> None:
        self.entity = entity
        self.identifier = identifier
        super().__init__(f"{entity} already exists: {identifier!r}")
