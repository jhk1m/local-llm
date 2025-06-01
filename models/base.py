from __future__ import annotations

import inspect
import logging
from typing import Type

from fastapi import Depends
from fastapi import Form
from pydantic import BaseModel

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def as_form(cls: type[BaseModel]):
    new_parameters = [
        inspect.Parameter(
            field.alias,
            inspect.Parameter.KEYWORD_ONLY,
            default=(Form(...) if field.required else Form(field.default)),
            annotation=field.outer_type_,
        )
        for field in cls.__fields__.values()
    ]

    async def _as_form(**data):
        return cls(**data)

    # Update signature
    _as_form.__signature__ = inspect.Signature(new_parameters)
    return _as_form