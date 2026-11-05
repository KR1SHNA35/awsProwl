"""Model mixins for awsProwl."""

from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from awsprowl.utils import stringify


class ModelUpdateMixin:
    """Mixin to simplify model updates in a database session."""

    def update(self, database: Session, commit: bool = True, **kwargs: Any) -> None:
        """Update model fields in a single line.

        Example usage:
            session.update(database, field_name={'json': ...})
        """
        for key, value in kwargs.items():
            value = stringify(value)
            setattr(self, key, value)

        database.add(self)

        if commit:
            database.commit()
