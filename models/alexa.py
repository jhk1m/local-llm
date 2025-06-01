from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from dateutil.parser import parse as parse_date
from pydantic import BaseModel
from pydantic import validator

from .core import BaseSyncEvent
from .core import Source

### Auth ###


class AlexaAuthRequest(BaseModel):
    client_id: str
    redirect_uri: str
    response_type: str
    state: str