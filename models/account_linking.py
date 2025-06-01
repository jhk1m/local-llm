from __future__ import annotations

import logging
from abc import ABC
from abc import abstractproperty
from typing import Callable
from typing import ClassVar

from pydantic import BaseModel

from .base import as_form

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


class NotLinkedError(Exception):
    def __init__(self, username: str, system: str):
        super().__init__(f'{username} is not linked to {system}')

### Base ###


class UserConfigurationBase(ABC, BaseModel):
    @abstractproperty
    def is_valid(self) -> bool:
        pass

### Alexa ###


class UserAlexaConfigurationCreate(BaseModel):
    user_id: str


class UserAlexaConfiguration(UserAlexaConfigurationCreate, UserConfigurationBase):
    @property
    def is_valid(self):
        return True