from __future__ import annotations

import logging
import string
import secrets
from datetime import datetime, timedelta

from fastapi.security import OAuth2PasswordBearer
from jose import jwt, JWTError
from models.core import Token

import config

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/oauth/authorization/token')


class InvalidTokenError(Exception):
    def __init__(self):
        super().__init__('Invalid token')


class AuthTokenService:
    def __init__(self):
        self.sessions = {}

    def create_session(self, username: str) -> str:
        session_token = secrets.token_urlsafe(32)
        self.sessions[session_token] = {
            "username": username,
            "expires": datetime.utcnow() + timedelta(minutes=15)
        }
        return session_token

    def validate_session(self, session_token: str) -> bool:
        session = self.sessions.get(session_token)
        if not session or datetime.utcnow() > session["expires"]:
            return False
        return True
    
    def get_username_from_session(self, session_token: str) -> str | None:
        session = self.sessions.get(session_token)
        return session["username"] if session else None

    def create_token(self, username: str, expires: timedelta | None = None) -> Token:
        logger.debug('...............CREATE_TOKEN for: %s', username)
        if not expires:
            expires = timedelta(minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES)

        expiration = datetime.utcnow() + expires
        data = {'sub': username, 'exp': expiration}
        access_token = jwt.encode(data, config.secrets.DB_SECRET_KEY, algorithm=config.secrets.DB_ALGORITHM)

        logger.debug('...............ACCESS_TOKEN CREATED: %s', access_token)
        return Token(access_token=access_token, token_type='Bearer')

    def get_username_from_token(self, access_token: str) -> str:
        try:
            payload = jwt.decode(
                access_token,
                config.secrets.DB_SECRET_KEY,
                algorithms=[config.secrets.DB_ALGORITHM],
                options={"verify_exp": True}
            )
            logger.debug('Decoded JWT payload: %s', payload)
            username: str | None = payload.get('sub')
            
            if not username:
                logger.error('Missing "sub" claim in token')
                raise InvalidTokenError()
                
            return username

        except JWTError as e:
            logger.error('JWT decoding failed: %s', str(e))
            raise InvalidTokenError()

    def refresh_token(self, access_token: str, expires: timedelta | None = None) -> Token:
        username = self.get_username_from_token(access_token)
        return self.create_token(username, expires)
