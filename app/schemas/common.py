from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    """Base for every request body.

    `extra="forbid"` is an injection defense as much as a typo catcher: a client
    cannot smuggle an unexpected field into a model that some later code path
    might read. `str_strip_whitespace` normalizes input once, at the edge.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


#: Page sizes are capped. An uncapped `limit` is a denial-of-service parameter.
PageSize = Annotated[int, Field(default=20, ge=1, le=100)]
PageNumber = Annotated[int, Field(default=1, ge=1, le=1000)]


class Page[T](ResponseModel):
    items: list[T]
    page: int
    page_size: int
    total: int
    has_more: bool


class CursorPage[T](ResponseModel):
    """Cursor pagination for append-only feeds (audit, security events).

    Offsets drift when rows are being appended underneath you; a cursor on a
    monotonic id does not.
    """

    items: list[T]
    next_cursor: int | None = None
    has_more: bool
