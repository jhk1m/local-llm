# In services/auth_token.py - FINAL version

from __future__ import annotations
import logging
from datetime import datetime, timedelta
import jwt
from models.core import Token
import config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class InvalidTokenError(Exception):
    pass

class AuthTokenService:
    def _create_api_token(self, username: str, expires_delta: timedelta) -> Token:
        """Helper to create a JWT for the Alexa API, including aud and iss."""
        expire = datetime.utcnow() + expires_delta
        to_encode = {
            "sub": username, 
            "exp": expire,
            "aud": config.secrets.ALEXA_SKILL_ID,
            "iss": config.secrets.ALEXA_SKILL_ID
        }
        encoded_jwt = jwt.encode(
            to_encode, config.secrets.JWT_SECRET_KEY, algorithm=config.settings.JWT_ALGORITHM
        )
        return Token(access_token=encoded_jwt, token_type='Bearer')

    def _create_website_session_token(self, username: str, expires_delta: timedelta) -> Token:
        """Helper to create a simple JWT for the website session, WITHOUT aud or iss."""
        expire = datetime.utcnow() + expires_delta
        to_encode = {"sub": username, "exp": expire}
        encoded_jwt = jwt.encode(
            to_encode, config.secrets.JWT_SECRET_KEY, algorithm=config.settings.JWT_ALGORITHM
        )
        return Token(access_token=encoded_jwt, token_type='Bearer')

    def create_token(self, username: str) -> Token:
        """Creates a short-lived access token for the Alexa API."""
        expires = timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        return self._create_api_token(username, expires)

    def create_refresh_token(self, username: str) -> Token:
        """Creates a long-lived refresh token for the Alexa API."""
        expires = timedelta(days=config.settings.REFRESH_TOKEN_EXPIRE_DAYS)
        return self._create_api_token(username, expires)

    def create_session(self, username: str) -> str:
        """Creates a short-lived session token for the WEBSITE."""
        expires = timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        return self._create_website_session_token(username, expires).access_token

    def get_username_from_token(self, token: str) -> str:
        """Decodes any token (API or session) and returns the username."""
        try:
            # This decode function does not check for audience, so it will work for both token types.
            payload = jwt.decode(
                token,
                config.secrets.JWT_SECRET_KEY,
                algorithms=[config.settings.JWT_ALGORITHM],
            )
            username: str | None = payload.get("sub")
            if username is None:
                raise InvalidTokenError("Token missing username (sub) claim")
            return username
        except jwt.PyJWTError as e:
            logger.error(f"JWT Decode Error: {e}")
            raise InvalidTokenError(str(e))

    def validate_session(self, token: str) -> bool:
        """Validates a session token."""
        try:
            self.get_username_from_token(token)
            return True
        except InvalidTokenError:
            return False