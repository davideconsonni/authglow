"""File-system implementations of the repository Protocols.

This subpackage provides ``File<Entity>Repository`` classes that
satisfy the contracts declared in ``authglow.repositories.protocols``
using ``fsspec`` + ``AsyncFileSystem`` as the I/O layer. The
individual entity repositories are added incrementally as each
service is migrated.
"""
