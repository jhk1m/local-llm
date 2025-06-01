from __future__ import annotations

from enum import Enum
from typing import Any
from typing import Type
from typing import TypeVar

from humps.main import camelize
from pydantic import BaseModel
from pydantic import Field

T = TypeVar('T', bound=BaseModel)


class SQSMessage(BaseModel):
    message_id: str
    receipt_handle: str
    body: str
    attributes: dict[str, str]
    message_attributes: dict[str, Any]

    def parse_body(self, cls: type[T]) -> T:
        """Return the body of the message as a Pydantic model"""

        return cls.parse_raw(self.body)

    class Config:
        alias_generator = camelize
        populate_by_name = True


class SQSEvent(BaseModel):
    records: list[SQSMessage] = Field(..., alias='Records')


class DynamoDBAtomicOp(Enum):
    increment = '+'
    decrement = '-'
    overwrite = '='