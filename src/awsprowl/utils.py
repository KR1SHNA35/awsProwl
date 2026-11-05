"""Utility functions for awsProwl."""

from __future__ import annotations

from datetime import datetime
from typing import Any


def remove_empty_from_dict(d: dict[str, Any] | list[Any] | Any) -> dict[str, Any] | list[Any] | Any:
    """Remove empty values from dict/list recursively.

    Reference: https://stackoverflow.com/a/24893252
    """
    if isinstance(d, dict):
        return {
            k: remove_empty_from_dict(v)
            for k, v in d.items()
            if v and remove_empty_from_dict(v)
        }

    if isinstance(d, list):
        return [
            remove_empty_from_dict(v)
            for v in d
            if v and remove_empty_from_dict(v)
        ]

    return d


def stringify(obj: dict[str, Any] | list[Any] | datetime | bytes | Any) -> dict[str, Any] | list[Any] | str | Any:
    """Convert datetime and bytes objects to strings for JSON serialization.

    SQLAlchemy's JSONType doesn't accept Python datetime/bytes objects.
    This method converts them to strings, allowing the ORM to save them.
    """
    if isinstance(obj, dict):
        new_dict: dict[str, Any] = {}
        for k, v in obj.items():
            new_dict[k] = stringify(v)
        return new_dict

    if isinstance(obj, list):
        new_list: list[Any] = []
        for v in obj:
            new_list.append(stringify(v))
        return new_list

    if isinstance(obj, datetime):
        return str(obj.strftime("%a, %d %b %Y %H:%M:%S"))

    if isinstance(obj, bytes):
        return obj.decode()

    return obj
