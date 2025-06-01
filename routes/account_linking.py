# routes/account_linking.py - FINAL, CLEAN VERSION (NO CIRCULAR IMPORTS)

from __future__ import annotations

import json
import logging
import random
import string
from typing import cast

# --- CRITICAL: Ensure `from app import app` and `from app import templates` ARE NOT HERE ---
# If they are, DELETE THEM. This is often the source of the circular import.

from app import services # Fine if services.serve does not import `app` at module level
from app import app_settings # Fine, just config

from fastapi import APIRouter
from fastapi import Depends
from fastapi import Form
from fastapi import HTTPException
from fastapi import Request
from fastapi import Response
from fastapi import status
from fastapi.responses import HTMLResponse
from fastapi.responses import RedirectResponse
from models.account_linking import UserAlexaConfiguration
from models.account_linking import UserAlexaConfigurationCreate
from models.core import RateLimitCategory
from models.core import Source
from models.core import User

from .auth import get_current_user # Relative import is fine
from .core import redirect_if_not_logged_in # Relative import is fine

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

api_router = APIRouter(prefix='/api/account-linking', tags=['Account Linking'])

### API ###

@api_router.get('/alexa', response_model=UserAlexaConfiguration, tags=['Alexa'], include_in_schema=False)
async def link_alexa_account(
    user: User = Depends(get_current_user),
    alexa_config_input: 'UserAlexaConfigurationCreate' = Depends(),
) -> 'UserAlexaConfiguration':
    logger.debug('...............ALEXA USER CONFIG: %s', alexa_config_input)
    user.alexa_user_id = alexa_config_input.user_id
    user.configuration.alexa = alexa_config_input.cast(UserAlexaConfiguration)
    services.user.update_user(user)
    return user.configuration.alexa


@api_router.delete('/alexa', tags=['Alexa'])
@services.rate_limit.limit(RateLimitCategory.modify)
async def unlink_alexa_account(user: User = Depends(get_current_user)) -> User:
    # TODO: send unlink request to Alexa; currently this just removes the id from the database
    user.alexa_user_id = None
    user.configuration.alexa = None
    services.user.update_user(user)
    return user