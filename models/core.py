from __future__ import annotations

import logging
import time
from datetime import datetime
from enum import Enum
from typing import Optional
from typing import TypeVar
from uuid import uuid4

import humps
from app_config import AppSecrets
from app_config import AppSettings
from pydantic import BaseModel
from pydantic import Field
from pydantic import validator

from .account_linking import UserAlexaConfiguration

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

T = TypeVar('T', bound=BaseModel)

app_secrets = AppSecrets()
app_settings = AppSettings()

class Token(BaseModel):
    access_token: str
    token_type: str


class WhitelistError(Exception):
    def __init__(self):
        super().__init__('You are not whitelisted on this application')


class RateLimitCategory(Enum):
    read = 'read'
    modify = 'modify'
    sync = 'sync'


class RateLimitInterval(Enum):
    minutely = 'minutely'


class UserConfiguration(BaseModel):
    alexa: UserAlexaConfiguration | None

    class Config:
        arbitrary_types_allowed = True


class UserRateLimit(BaseModel):
    value: int
    expires: int


class AlexaLinkingInfo(BaseModel):
    alexa_user_id: str | None = None
    auth_code: str | None = None
    auth_code_expires: int | None = None
    client_id: str | None = None # New: Store client_id
    redirect_uri: str | None = None # New: Store redirect_uri


class User(BaseModel):
    username: str
    email: str
    disabled: bool

    user_expires: int | None = None
    last_registration_token: str | None = None
    last_password_reset_token: str | None = None
    incorrect_login_attempts: int | None = 0
    api_token: str | None = None
    access_token: str | None = None

    # TODO: migrate and make this required
    is_rate_limit_exempt: bool | None = False
    # TODO: migrate and make this required
    rate_limit_map: dict[str, UserRateLimit] | None = {}
    """Map of `RateLimitCategory` to `UserRateLimit`"""

    configuration: UserConfiguration = Field(default_factory=UserConfiguration)
    alexa_linking: AlexaLinkingInfo = Field(default_factory=AlexaLinkingInfo)
    alexa_auth_code: str | None = None

    use_developer_routes: bool = False

    class Config:
        populate_by_name = True

    @property
    def is_linked_to_alexa(self):
        return bool(self.configuration.alexa and self.configuration.alexa.is_valid)


    def link_alexa_account(self, alexa_user_id: str):
        self.alexa_linking.alexa_user_id = alexa_user_id

    def unlink_alexa_account(self):
        self.alexa_linking = AlexaLinkingInfo()

    def set_alexa_auth_code(self, auth_code: str, expires_in: int):
        self.alexa_linking.auth_code = auth_code
        self.alexa_linking.auth_code_expires = int(time.time()) + expires_in

    def clear_alexa_auth_code(self):
        self.alexa_linking.auth_code = None
        self.alexa_linking.auth_code_expires = None

    def is_alexa_auth_code_valid(self, auth_code: str) -> bool:
        return (
            self.alexa_linking.auth_code == auth_code
            and self.alexa_linking.auth_code_expires
            and self.alexa_linking.auth_code_expires > int(time.time())
        )

    def set_expiration(self, expiration_in_seconds: int) -> int:
        """Sets expiration time in seconds and returns the TTL value"""

        self.user_expires = round(time.time()) + expiration_in_seconds
        return self.user_expires


class UserInDB(User):
    hashed_password: str

    def cast(self, cls: type[T], **kwargs) -> T:
        create_data = self.dict()
        create_data.update(kwargs or {})
        return cls(**create_data)


class Source(Enum):
    alexa = 'Alexa'


class BaseSyncEvent(BaseModel):
    username: str
    source: Source

    client_id: str = app_secrets.ALEXA_CLIENT_ID
    client_secret: str = app_secrets.ALEXA_CLIENT_SECRET

    event_id: str = Field(default_factory=lambda: str(uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True

    @property
    def group_id(self):
        return self.username  # preserves order of events per-user
    
class OAuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in: int
    refresh_token: str | None = None