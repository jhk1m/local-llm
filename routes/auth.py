# routes/auth.py - FINAL VERSION

from __future__ import annotations
import logging
from app import services
from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from models.core import User
from services.auth_token import InvalidTokenError

oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/oauth/authorization/token')
router = APIRouter(prefix='/oauth/authorization', tags=['Authorization'])

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    """Dependency to get the current user from a bearer token."""
    try:
        username = services.token.get_username_from_token(token)
        _user_in_db = services.user.get_user(username, active_only=False)
        
        if not _user_in_db:
            raise InvalidTokenError('User not found for token')

        user = _user_in_db.cast(User)

        if user.disabled:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail='Account disabled')

        return user

    except InvalidTokenError as e:
        logger.error(f'Invalid token encountered: {e}')
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Invalid credentials',
            headers={'WWW-Authenticate': 'Bearer'},
        )

@router.get('/me', response_model=User)
async def get_logged_in_user(current_user: User = Depends(get_current_user)) -> User:
    """Returns the authenticated user's details."""
    return current_user