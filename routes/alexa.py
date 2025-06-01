from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import boto3
from datetime import timedelta
from json import JSONDecodeError
from typing import cast
from typing import Optional
from uuid import uuid4

import requests
import config

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, Response, status
from fastapi.routing import APIRoute
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from models.account_linking import UserAlexaConfiguration, UserAlexaConfigurationCreate
from models.alexa import AlexaAuthRequest
from models.core import RateLimitCategory, Token, User
from pydantic import ValidationError
from requests import PreparedRequest

from .account_linking import unlink_alexa_account
from .auth import get_current_user
from .core import redirect_if_not_logged_in
from app import services, templates

# Initialize configuration and services

kms_client = boto3.client('kms', region_name=config.secrets.AWS_REGION)

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create routers
router = APIRouter(prefix='/app', tags=['Application'])
auth_router = APIRouter(prefix="/oauth/authorization", tags=["Alexa Account Linking"])
frontend_router = APIRouter(prefix='/app/alexa', tags=['Alexa'])

### Frontend ###

def create_alexa_config_template(request: Request, user: User, **kwargs):
    context = {
        'request': request,
        'user': user,
    }

    return templates.TemplateResponse(
        'alexa_config.html',
        {**context, **{k: v for k, v in kwargs.items() if k not in context}},
    )

@frontend_router.get('', response_class=HTMLResponse)
async def configure_alexa(request: Request):
    """Render the Alexa authorization page"""
    logged_in_response = await redirect_if_not_logged_in(
        request,
        redirect_path=frontend_router.url_path_for('configure_alexa'),
    )

    if isinstance(logged_in_response, Response):
        return logged_in_response

    user = logged_in_response
    return create_alexa_config_template(request, user)

@frontend_router.post('/unlink', response_class=HTMLResponse)
async def delete_alexa_config(request: Request):
    """Delete the user's Alexa authorization"""
    logged_in_response = await redirect_if_not_logged_in(
        request,
        redirect_path=frontend_router.url_path_for('configure_alexa'),
    )

    if isinstance(logged_in_response, Response):
        return logged_in_response

    user = logged_in_response

    try:
        user = await unlink_alexa_account(user)
        return create_alexa_config_template(
            request,
            user,
            success_message='Successfully unlinked your Alexa account',
        )
    except Exception:
        return create_alexa_config_template(
            request,
            user,
            auth_error='Unknown error when trying to unlink your account',
        )


### Auth Handshake  **Web Authorization URI ###
# /authorization/alexa

@router.get("/authorize")
async def authorize(
    request: Request,
    client_id: str,
    response_type: str,
    redirect_uri: str,
    state: str,
    alexa_service: AlexaService = Depends()
):
    # Log all incoming params for debugging.
    logger.debug(
        '.....................Received Alexa authorization request: %s', auth.dict(),
    )

    """The authorization URI for Alexa account linking"""
    logger.debug('...............RECEIVED CLIENT_ID: %s', auth.client_id)
    if auth.client_id != config.secrets.APP_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail='Invalid client_id',
        )

    logged_in_response = await redirect_if_not_logged_in(
        request,
        redirect_path=auth_router.url_path_for('authorize_alexa_app'),
        params=auth.dict(),
    )

    if isinstance(logged_in_response, Response):
        return logged_in_response

    user = logged_in_response

    access_token_expires = timedelta(
        minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES_TEMPORARY,
    )
    user_access_token = services.token.create_token(
        user.username, access_token_expires,
    )
    user.access_token = user_access_token.access_token
    logger.debug('...............UPDATING USER: %s', user)
    # Update user with specified fields
    try:
        services.user.update_user(user)
        logger.debug(
            '...............User ACCESS & API token and updated successfully',
        )
    except Exception as e:
        logger.error(f'...............Error updating user: {e}')
        # Handle the error appropriately

    req = PreparedRequest()
    req.prepare_url(
        auth.redirect_uri, {
            'code': user_access_token.access_token, 'state': auth.state,
        },
    )
    redirect_uri = cast(str, req.url)

    # add params to redirect uri
    # redirect_uri = f"{auth.redirect_uri}?state={auth.state}&code={user_access_token.access_token}"
    # logger.debug("...............ACCESS TOKEN SENT TO ALEXA: %s", redirect_uri)

    return RedirectResponse(redirect_uri, status_code=302)


### Access token and token refresh request  **Access token URI ###
# /authorization/alexa/token
@auth_router.post('/token', response_model=Token)
async def get_access_token(
    grant_type: str = Form(...),
    code: str | None = Form(None),
    refresh_token: str | None = Form(None),
    client_id: str = Form(...),
    redirect_uri: str | None = Form(None),
) -> Token:
    """Process Alexa auth-request form and returns an access token"""
    logger.debug(
        '...............ACCESS TOKEN REQUESTED /authorization/alexa/token',
    )
    logger.debug('...............GRANT TYPE: %s', grant_type)
    logger.debug('...............CODE: %s', code)
    if client_id != config.secrets.APP_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
        )

    access_token_expires = timedelta(
        minutes=config.settings.ACCESS_TOKEN_EXPIRE_MINUTES_INTEGRATION,
    )
    return services.token.refresh_token(code, access_token_expires)


@frontend_router.delete('/link')
async def unlink_user_from_alexa_app(request: Request, user_id: str = Query(..., alias='userId')):
    secret_hash = request.headers.get(config.settings.ALEXA_SECRET_HEADER_KEY)
    if not secret_hash:
        logging.error('Alexa unlink request received without security hash')
        raise HTTPException(status.HTTP_400_BAD_REQUEST)

    hmac_signature = hmac.new(
        key=config.secrets.APP_CLIENT_SECRET.encode('utf-8'),
        msg=config.secrets.APP_CLIENT_ID.encode('utf-8'),
        digestmod=hashlib.sha256,
    )

    calculated_hash = base64.b64encode(hmac_signature.digest()).decode()
    if calculated_hash != secret_hash:
        logging.error('Alexa unlink request received with invalid hash')
        raise HTTPException(status.HTTP_400_BAD_REQUEST)

    usernames = services.user.get_usernames_by_secondary_index(
        'alexa_user_id', user_id,
    )
    if not usernames:
        return

    for username in usernames:
        _user_in_db = services.user.get_user(username, active_only=False)
        if not _user_in_db:
            continue

        user = _user_in_db.cast(User)
        await unlink_alexa_account(user)
